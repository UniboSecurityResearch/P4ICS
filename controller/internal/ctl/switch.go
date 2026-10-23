package ctl

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/p4rt"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/sa"
)

// Names in testbed/s1/industrial_aes.p4.
const (
	tableLocal   = "p4ics_local"
	tableKeys    = "p4ics_keys"
	tableSec     = "ics_sec"
	tableForward = "ipv4_lpm"
	digestTunnel = "p4ics_tunnel_request_t"
	counterEvent = "p4ics_events"
)

// Event names of p4ics_events, by index.
var eventNames = []string{"protected", "unprotected", "rejected", "replay", "waiting"}

// Priority (simple_switch_CLI scale, lower wins) of the per-pair ics_sec
// entries: above the per-port wildcard entries of commands.txt.
const tunnelPriority = 10

var electionID = &p4v1.Uint128{High: 0, Low: 1}

// Switch is one simple_switch_grpc and what the controller installed on it.
type Switch struct {
	cfg config.Switch
	ctl *Controller
	log *slog.Logger
	tls *tls.Config

	mu           sync.Mutex
	rt           *client.Client // nil until the controller is primary
	pipe         *pipeline      // files of the current session
	ready        bool           // pipeline and tables installed, connection up
	configuredAt time.Time
	hasKey       [2]bool // p4ics_keys entries installed since the pipeline was set
}

// pipeline: what the controller installs, read from the configured files
// at every connection (a restarted switch may run a recompiled program).
type pipeline struct {
	json, p4info []byte
	info         *p4rt.Info
	entries      []*p4rt.Entry
	spi          uint32
	routes       []route
	roles        map[uint32]string // egress port -> cipher | decipher (ics_sec of commands.txt)
}

type route struct {
	prefix netip.Prefix
	port   uint32
}

func (sw *Switch) Name() string { return sw.cfg.Name }

func (sw *Switch) isReady() bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.ready
}

func (sw *Switch) setReady(ready bool) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.ready && !ready {
		sw.log.Warn("switch not reachable")
	}
	sw.ready = ready
}

func (sw *Switch) loadPipeline() (*pipeline, error) {
	p := &pipeline{roles: map[uint32]string{}}
	var err error
	if p.json, err = os.ReadFile(sw.cfg.JSON); err != nil {
		return nil, err
	}
	if p.p4info, err = os.ReadFile(sw.cfg.P4Info); err != nil {
		return nil, err
	}
	if p.info, err = p4rt.ParseInfo(p.p4info); err != nil {
		return nil, err
	}
	commands, err := os.ReadFile(sw.cfg.Commands)
	if err != nil {
		return nil, err
	}
	if p.entries, err = p.info.ParseCommands(commands); err != nil {
		return nil, fmt.Errorf("%s: %w", sw.cfg.Commands, err)
	}
	p.spi = sw.cfg.SPI
	for _, e := range p.entries {
		switch {
		case e.TableName() == tableLocal && e.Default && p.spi == 0:
			v, _ := e.Param("spi")
			spi, err := strconv.ParseUint(v, 0, 8)
			if err != nil {
				return nil, fmt.Errorf("%s: spi %q: %v", sw.cfg.Commands, v, err)
			}
			p.spi = uint32(spi)
		case e.TableName() == tableForward && !e.Default:
			pfx, err1 := netip.ParsePrefix(e.MatchTokens[0])
			port, ok := e.Param("port")
			n, err2 := strconv.ParseUint(port, 0, 9)
			if err1 == nil && err2 == nil && ok {
				p.routes = append(p.routes, route{pfx.Masked(), uint32(n)})
			}
		case e.TableName() == tableSec && !e.Default && wildcardAddrs(e.MatchTokens):
			port, _, _ := strings.Cut(e.MatchTokens[0], "&&&")
			if n, err := strconv.ParseUint(port, 0, 9); err == nil &&
				(e.ActionName() == "cipher" || e.ActionName() == "decipher") {
				p.roles[uint32(n)] = e.ActionName()
			}
		}
	}
	if p.spi < 1 || p.spi > 255 {
		return nil, fmt.Errorf("no sender id (spi 1..255): set it in the configuration or in %s", sw.cfg.Commands)
	}
	return p, nil
}

func wildcardAddrs(match []string) bool {
	return len(match) == 3 && strings.HasSuffix(match[1], "&&&0.0.0.0") && strings.HasSuffix(match[2], "&&&0.0.0.0")
}

// port returns the egress port ipv4_lpm picks for dst.
func (p *pipeline) port(dst netip.Addr) (uint32, bool) {
	best := -1
	var port uint32
	for _, r := range p.routes {
		if r.prefix.Contains(dst) && r.prefix.Bits() > best {
			best, port = r.prefix.Bits(), r.port
		}
	}
	return port, best >= 0
}

// run keeps a P4Runtime session with the switch, reconnecting forever.
func (sw *Switch) run(ctx context.Context) {
	for {
		err := sw.session(ctx)
		sw.setReady(false)
		if ctx.Err() != nil {
			return
		}
		sw.log.Warn("session ended, retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (sw *Switch) session(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn, err := grpc.NewClient(sw.cfg.Address, grpc.WithTransportCredentials(credentials.NewTLS(sw.tls)))
	if err != nil {
		return err
	}
	defer conn.Close()
	p4c := p4v1.NewP4RuntimeClient(conn)
	for waiting := false; ; waiting = true {
		cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
		_, err = p4c.Capabilities(cctx, &p4v1.CapabilitiesRequest{})
		ccancel()
		if err == nil {
			break
		}
		if !waiting {
			sw.log.Info("waiting for the switch", "address", sw.cfg.Address, "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	rt := client.NewClient(p4c, sw.cfg.DeviceID, electionID)
	arbitration := make(chan bool)
	messages := make(chan *p4v1.StreamMessageResponse, 1000)
	// Run also reconnects after the switch restarts, and arbitrates again:
	// every arbitration won (re)configures the switch.
	go rt.Run(ctx, conn, arbitration, messages)
	go sw.watch(ctx, conn)

	stopConfigure := func() {}
	defer func() { stopConfigure() }()
	// The switch closes the stream without an answer when another client
	// holds the same election id.
	noAnswer := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-noAnswer:
			sw.log.Error("no arbitration answer: is another controller primary for this switch?")
		case primary := <-arbitration:
			noAnswer = nil
			stopConfigure()
			stopConfigure = func() {}
			if !primary {
				sw.setReady(false)
				sw.log.Error("another controller is primary for this switch")
				continue
			}
			stopConfigure = sw.startConfigure(ctx, rt)
		case m := <-messages:
			switch u := m.Update.(type) {
			case *p4v1.StreamMessageResponse_Digest:
				sw.ctl.onDigest(ctx, sw, u.Digest)
				if err := rt.AckDigestList(ctx, u.Digest); err != nil {
					sw.log.Warn("digest ack", "err", err)
				}
			case *p4v1.StreamMessageResponse_Error:
				sw.log.Warn("stream error", "err", prototext.Format(u.Error))
			}
		}
	}
}

// watch marks the switch not ready as soon as the connection breaks, and
// keeps the channel connecting, so that the client's reconnection (which
// checks every 5s) finds it ready at its first check.
func (sw *Switch) watch(ctx context.Context, conn *grpc.ClientConn) {
	for {
		s := conn.GetState()
		if s == connectivity.TransientFailure || s == connectivity.Idle || s == connectivity.Shutdown {
			sw.setReady(false)
		}
		if s == connectivity.Idle {
			conn.Connect()
		}
		if !conn.WaitForStateChange(ctx, s) {
			return
		}
	}
}

func (sw *Switch) startConfigure(ctx context.Context, rt *client.Client) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go sw.configure(ctx, rt)
	return cancel
}

// configure installs the pipeline and the tables, then asks for a key
// rotation: a switch that was (re)started has no key and no anti-replay
// state, so it must not get the keys used before.
func (sw *Switch) configure(ctx context.Context, rt *client.Client) {
	for attempt := 0; ; attempt++ {
		err := sw.ctl.configure(ctx, sw, rt)
		if err == nil {
			sw.ctl.RequestRekey(sw.Name() + " configured")
			return
		}
		if ctx.Err() != nil {
			return
		}
		if attempt == 0 {
			sw.log.Warn("configuration failed, retrying", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// setPipeline replaces the program, and with it every table and register.
func (sw *Switch) setPipeline(ctx context.Context, rt *client.Client, p *pipeline) error {
	h := sha256.New()
	h.Write(p.json)
	h.Write(p.p4info)
	_, err := rt.SetForwardingPipelineConfig(ctx, &p4v1.SetForwardingPipelineConfigRequest{
		DeviceId:   sw.cfg.DeviceID,
		ElectionId: electionID,
		Action:     p4v1.SetForwardingPipelineConfigRequest_VERIFY_AND_COMMIT,
		Config: &p4v1.ForwardingPipelineConfig{
			P4Info:         p.info.P,
			P4DeviceConfig: p.json,
			Cookie:         &p4v1.ForwardingPipelineConfig_Cookie{Cookie: binary.BigEndian.Uint64(h.Sum(nil))},
		},
	})
	if err != nil {
		return fmt.Errorf("set pipeline: %w", writeError(err))
	}
	sw.mu.Lock()
	sw.rt, sw.pipe, sw.hasKey = rt, p, [2]bool{}
	sw.mu.Unlock()
	return nil
}

func (sw *Switch) current() (*client.Client, *pipeline) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.rt, sw.pipe
}

func update(kind p4v1.Update_Type, e *p4rt.Entry) *p4v1.Update {
	return &p4v1.Update{Type: kind, Entity: &p4v1.Entity{
		Entity: &p4v1.Entity_TableEntry{TableEntry: e.TableEntry()}}}
}

// write sends updates in one request.
func (sw *Switch) write(ctx context.Context, updates ...*p4v1.Update) error {
	rt, _ := sw.current()
	if rt == nil {
		return errors.New("not connected")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := rt.Write(ctx, &p4v1.WriteRequest{DeviceId: sw.cfg.DeviceID, ElectionId: electionID, Updates: updates})
	if status.Code(err) == codes.Unavailable {
		sw.setReady(false)
	}
	return writeError(err)
}

// writeError adds the per-update errors P4Runtime puts in the status details.
func writeError(err error) error {
	st, ok := status.FromError(err)
	if err == nil || !ok {
		return err
	}
	var msgs []string
	for _, d := range st.Details() {
		if e, ok := d.(*p4v1.Error); ok && codes.Code(e.CanonicalCode) != codes.OK {
			msgs = append(msgs, fmt.Sprintf("%s: %s", codes.Code(e.CanonicalCode), e.Message))
		}
	}
	if len(msgs) == 0 {
		return err
	}
	return &updateError{code: st.Code(), msg: strings.Join(msgs, "; ")}
}

type updateError struct {
	code codes.Code
	msg  string
}

func (e *updateError) Error() string { return e.msg }

// GRPCStatus lets status.Code see the code of the request.
func (e *updateError) GRPCStatus() *status.Status { return status.New(e.code, e.msg) }

// installKey writes the key of a phase (insert, or modify if present).
func (sw *Switch) installKey(ctx context.Context, phase uint8, key sa.Key) error {
	_, p := sw.current()
	e, err := p.info.Build(tableKeys, "set_key", []string{strconv.Itoa(int(phase))}, []string{key.Hex()}, 0)
	if err != nil {
		return err
	}
	sw.mu.Lock()
	kind := p4v1.Update_INSERT
	if sw.hasKey[phase] {
		kind = p4v1.Update_MODIFY
	}
	sw.mu.Unlock()
	if err := sw.write(ctx, update(kind, e)); err != nil {
		return fmt.Errorf("key phase %d: %w", phase, err)
	}
	sw.mu.Lock()
	sw.hasKey[phase] = true
	sw.mu.Unlock()
	return nil
}

// activate makes the switch protect with phase from now on.
func (sw *Switch) activate(ctx context.Context, phase uint8, epoch uint64) error {
	_, p := sw.current()
	e, err := p.info.BuildDefault(tableLocal, "set_local_sa", []string{
		strconv.Itoa(int(p.spi)), strconv.Itoa(int(phase)), strconv.FormatUint(epoch, 10)})
	if err != nil {
		return err
	}
	if err := sw.write(ctx, update(p4v1.Update_MODIFY, e)); err != nil {
		return fmt.Errorf("activate phase %d: %w", phase, err)
	}
	return nil
}

// tunnelEntries: the ics_sec entries of one endpoint pair, both directions,
// with the action of the port each direction leaves from.
func (sw *Switch) tunnelEntries(pair Pair) ([]*p4rt.Entry, error) {
	_, p := sw.current()
	var entries []*p4rt.Entry
	for _, dir := range [][2]netip.Addr{{pair.A, pair.B}, {pair.B, pair.A}} {
		port, ok := p.port(dir[1])
		if !ok {
			continue
		}
		role, ok := p.roles[port]
		if !ok {
			continue
		}
		e, err := p.info.Build(tableSec, role, []string{
			fmt.Sprintf("%d&&&0x1ff", port),
			dir[0].String() + "&&&255.255.255.255",
			dir[1].String() + "&&&255.255.255.255",
		}, nil, tunnelPriority)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (sw *Switch) addTunnel(ctx context.Context, pair Pair) error {
	entries, err := sw.tunnelEntries(pair)
	if err != nil {
		return err
	}
	for _, e := range entries {
		// one request per entry: a pair already installed is not an error
		if err := sw.write(ctx, update(p4v1.Update_INSERT, e)); err != nil && status.Code(err) != codes.AlreadyExists {
			return fmt.Errorf("tunnel %s: %w", pair, err)
		}
	}
	return nil
}

func (sw *Switch) deleteTunnel(ctx context.Context, pair Pair) error {
	entries, err := sw.tunnelEntries(pair)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := sw.write(ctx, update(p4v1.Update_DELETE, e)); err != nil && status.Code(err) != codes.NotFound {
			return fmt.Errorf("tunnel %s: %w", pair, err)
		}
	}
	return nil
}

// enableDigest asks for p4ics_tunnel_request_t digests, one per message.
func (sw *Switch) enableDigest(ctx context.Context) error {
	rt, p := sw.current()
	d, err := p.info.Digest(digestTunnel)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return writeError(rt.WriteUpdate(ctx, &p4v1.Update{
		Type: p4v1.Update_INSERT,
		Entity: &p4v1.Entity{Entity: &p4v1.Entity_DigestEntry{DigestEntry: &p4v1.DigestEntry{
			DigestId: d.GetPreamble().GetId(),
			Config:   &p4v1.DigestEntry_Config{MaxTimeoutNs: 0, MaxListSize: 1, AckTimeoutNs: int64(time.Second)},
		}}},
	}))
}

// events reads p4ics_events.
func (sw *Switch) events(ctx context.Context) (map[string]int64, error) {
	rt, p := sw.current()
	if rt == nil {
		return nil, errors.New("not connected")
	}
	c, err := p.info.Counter(counterEvent)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ch := make(chan *p4v1.Entity, 16)
	out := map[string]int64{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range ch {
			ce := e.GetCounterEntry()
			if i := ce.GetIndex().GetIndex(); ce != nil && i >= 0 && int(i) < len(eventNames) {
				out[eventNames[i]] = ce.GetData().GetPacketCount()
			}
		}
	}()
	err = rt.ReadEntityWildcard(ctx, &p4v1.Entity{Entity: &p4v1.Entity_CounterEntry{
		CounterEntry: &p4v1.CounterEntry{CounterId: c.GetPreamble().GetId()}}}, ch)
	<-done
	return out, err
}
