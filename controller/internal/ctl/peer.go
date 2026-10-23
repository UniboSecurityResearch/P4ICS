package ctl

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/sa"
)

// Two controllers, each managing its own switches, agree on every key with
// an ephemeral X25519 exchange over their mutually authenticated HTTPS API:
//
//	leader                                   follower
//	POST /peer/prepare {rotation, phase, bits, pub A}
//	                                         key = HKDF(X25519(b, A), ...), installed in the idle phase
//	                     <- {pub B}
//	key = HKDF(X25519(a, B), ...), installed in the idle phase
//	switches activate the phase
//	POST /peer/activate {rotation}           switches activate the phase
//
// The follower asks the leader for a rotation with POST /peer/rekey, and
// both forward on-demand tunnels with POST /peer/tunnel.

type prepareRequest struct {
	Rotation uint64 `json:"rotation"`
	Phase    uint8  `json:"phase"`
	Bits     int    `json:"bits"`
	Public   []byte `json:"public"`
}

type prepareResponse struct {
	Public []byte `json:"public"`
}

type activateRequest struct {
	Rotation uint64 `json:"rotation"`
}

type rekeyRequest struct {
	Reason string `json:"reason"`
}

type tunnelRequest struct {
	A   netip.Addr `json:"a"`
	B   netip.Addr `json:"b"`
	Add bool       `json:"add"`
}

type peerClient struct {
	cfg  *config.Peer
	http *http.Client
}

func newPeerClient(cfg *config.Peer, creds *tls.Config) *peerClient {
	return &peerClient{cfg: cfg, http: &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: creds},
	}}
}

func (p *peerClient) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.URL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(data))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// prepare runs the exchange and returns the key; the peer has installed it.
func (p *peerClient) prepare(ctx context.Context, rotation uint64, phase uint8, bits int) (sa.Key, error) {
	x, err := sa.NewExchange()
	if err != nil {
		return sa.Key{}, err
	}
	var resp prepareResponse
	req := prepareRequest{Rotation: rotation, Phase: phase, Bits: bits, Public: x.Public()}
	if err := p.call(ctx, http.MethodPost, "/peer/prepare", req, &resp); err != nil {
		return sa.Key{}, err
	}
	return x.Key(resp.Public, rotation, phase, x.Public(), resp.Public, bits)
}

func (p *peerClient) activate(ctx context.Context, rotation uint64) error {
	return p.call(ctx, http.MethodPost, "/peer/activate", activateRequest{Rotation: rotation}, nil)
}

func (p *peerClient) rekey(ctx context.Context, reason string) error {
	return p.call(ctx, http.MethodPost, "/peer/rekey", rekeyRequest{Reason: reason}, nil)
}

func (p *peerClient) tunnel(ctx context.Context, pair Pair, add bool) error {
	return p.call(ctx, http.MethodPost, "/peer/tunnel", tunnelRequest{A: pair.A, B: pair.B, Add: add}, nil)
}

func (p *peerClient) status(ctx context.Context) (Status, error) {
	var s Status
	err := p.call(ctx, http.MethodGet, "/status", nil, &s)
	return s, err
}
