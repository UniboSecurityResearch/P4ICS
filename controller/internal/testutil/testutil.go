// Package testutil has test helpers: a PKI like the one of pki.sh, and an
// in-memory P4Runtime server with mutual TLS that behaves like
// simple_switch_grpc for the requests the controller sends. Adapted from the
// Pk-IOTA controller (same authors).
package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// PKI writes dir/ca.pem and, for each name, dir/<name>.pem and
// dir/<name>-key.pem: EC P-256, common name and DNS name <name>, IP
// address 127.0.0.1 (the files of pki.sh).
func PKI(t testing.TB, dir string, names ...string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "P4ICS test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER)
	for i, name := range names {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     []string{name},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := x509.MarshalECPrivateKey(key)
		write(t, filepath.Join(dir, name+".pem"), "CERTIFICATE", der)
		write(t, filepath.Join(dir, name+"-key.pem"), "EC PRIVATE KEY", k)
	}
}

func write(t testing.TB, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// FakeSwitch is an in-memory P4Runtime target.
type FakeSwitch struct {
	p4v1.UnimplementedP4RuntimeServer

	mu       sync.Mutex
	pipeline *p4v1.ForwardingPipelineConfig
	entries  map[string]*p4v1.TableEntry // non-default entries
	defaults map[uint32]*p4v1.TableEntry

	srv  *grpc.Server
	Addr string
}

// StartFakeSwitch listens on 127.0.0.1 with the certificate of name in the
// PKI of dir, and requires client certificates of its CA.
func StartFakeSwitch(t testing.TB, dir, name string) *FakeSwitch {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeSwitch{entries: map[string]*p4v1.TableEntry{}, defaults: map[uint32]*p4v1.TableEntry{},
		srv: grpc.NewServer(grpc.Creds(creds)), Addr: l.Addr().String()}
	p4v1.RegisterP4RuntimeServer(f.srv, f)
	go f.srv.Serve(l)
	t.Cleanup(f.srv.Stop)
	return f
}

// key identifies an entry by table, match fields and priority.
func key(te *p4v1.TableEntry) string {
	ms := append([]*p4v1.FieldMatch(nil), te.GetMatch()...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].GetFieldId() < ms[j].GetFieldId() })
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&p4v1.TableEntry{
		TableId: te.GetTableId(), Match: ms, Priority: te.GetPriority()})
	return string(b)
}

func (f *FakeSwitch) Capabilities(context.Context, *p4v1.CapabilitiesRequest) (*p4v1.CapabilitiesResponse, error) {
	return &p4v1.CapabilitiesResponse{P4RuntimeApiVersion: "1.4.0"}, nil
}

func (f *FakeSwitch) SetForwardingPipelineConfig(_ context.Context, r *p4v1.SetForwardingPipelineConfigRequest) (*p4v1.SetForwardingPipelineConfigResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pipeline = r.GetConfig()
	f.entries = map[string]*p4v1.TableEntry{}
	f.defaults = map[uint32]*p4v1.TableEntry{}
	return &p4v1.SetForwardingPipelineConfigResponse{}, nil
}

func (f *FakeSwitch) StreamChannel(s p4v1.P4Runtime_StreamChannelServer) error {
	for {
		m, err := s.Recv()
		if err != nil {
			return err
		}
		if a := m.GetArbitration(); a != nil {
			a.Status = &rpcstatus.Status{Code: int32(code.Code_OK)}
			if err := s.Send(&p4v1.StreamMessageResponse{Update: &p4v1.StreamMessageResponse_Arbitration{Arbitration: a}}); err != nil {
				return err
			}
		}
	}
}

func (f *FakeSwitch) Write(_ context.Context, r *p4v1.WriteRequest) (*p4v1.WriteResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pipeline == nil {
		return nil, status.Error(codes.FailedPrecondition, "no pipeline")
	}
	// all or nothing, like a request with one failing update
	for _, u := range r.GetUpdates() {
		te := u.GetEntity().GetTableEntry()
		if te == nil {
			continue // digest configuration
		}
		_, exists := f.entries[key(te)]
		switch {
		case te.GetIsDefaultAction():
		case u.GetType() == p4v1.Update_INSERT && exists:
			return nil, status.Error(codes.AlreadyExists, "entry exists")
		case u.GetType() == p4v1.Update_DELETE && !exists,
			u.GetType() == p4v1.Update_MODIFY && !exists:
			return nil, status.Error(codes.NotFound, "no entry")
		}
	}
	for _, u := range r.GetUpdates() {
		te := u.GetEntity().GetTableEntry()
		switch {
		case te == nil:
		case te.GetIsDefaultAction():
			f.defaults[te.GetTableId()] = te
		case u.GetType() == p4v1.Update_DELETE:
			delete(f.entries, key(te))
		default:
			f.entries[key(te)] = te
		}
	}
	return &p4v1.WriteResponse{}, nil
}

// Read answers table reads (by table id) and counter reads (5 indices, no
// packets).
func (f *FakeSwitch) Read(r *p4v1.ReadRequest, s p4v1.P4Runtime_ReadServer) error {
	f.mu.Lock()
	var out []*p4v1.Entity
	for _, e := range r.GetEntities() {
		if te := e.GetTableEntry(); te != nil {
			for _, x := range f.entries {
				if x.GetTableId() == te.GetTableId() {
					out = append(out, &p4v1.Entity{Entity: &p4v1.Entity_TableEntry{TableEntry: x}})
				}
			}
		}
		if ce := e.GetCounterEntry(); ce != nil {
			for i := int64(0); i < 5; i++ {
				out = append(out, &p4v1.Entity{Entity: &p4v1.Entity_CounterEntry{CounterEntry: &p4v1.CounterEntry{
					CounterId: ce.GetCounterId(), Index: &p4v1.Index{Index: i}, Data: &p4v1.CounterData{}}}})
			}
		}
	}
	f.mu.Unlock()
	return s.Send(&p4v1.ReadResponse{Entities: out})
}

// Entries returns the entries of a table id.
func (f *FakeSwitch) Entries(tableID uint32) []*p4v1.TableEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*p4v1.TableEntry
	for _, x := range f.entries {
		if x.GetTableId() == tableID {
			out = append(out, x)
		}
	}
	return out
}

// Eventually fails the test if cond is not true within timeout.
func Eventually(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
