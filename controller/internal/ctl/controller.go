// Package ctl is the P4ICS controller: it configures P4ICS switches over
// P4Runtime (mutual TLS), installs and rotates their keys without dropping
// traffic, activates tunnels statically or on demand, and agrees on keys
// with a peer controller.
package ctl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/sa"
)

type Controller struct {
	cfg      *config.Config
	log      *slog.Logger
	switches []*Switch
	peer     *peerClient // nil without a peer controller
	server   *tls.Config // API

	rekeyCh chan string // queued rotation request and its reason

	// mu serialises everything that writes security associations, so that
	// a rotation never interleaves with a switch being configured. It is
	// never held while waiting for the peer to take its own lock.
	mu        sync.Mutex
	phase     uint8 // phase the switches protect with
	keys      [2]*sa.Key
	rotation  uint64
	rotatedAt time.Time
	tunnels   map[Pair]bool
	pending   *pendingKey // prepared by the leader, not yet activated
	denied    map[Pair]time.Time
}

type pendingKey struct {
	rotation uint64
	phase    uint8
	key      sa.Key
}

// Pair is an endpoint pair of on-demand tunnels, A < B.
type Pair struct{ A, B netip.Addr }

func NewPair(x, y netip.Addr) Pair {
	if y.Less(x) {
		x, y = y, x
	}
	return Pair{x, y}
}

func (p Pair) String() string { return p.A.String() + "<->" + p.B.String() }

func New(cfg *config.Config, log *slog.Logger) (*Controller, error) {
	ca, cert, err := loadTLS(cfg.TLS)
	if err != nil {
		return nil, err
	}
	c := &Controller{
		cfg:     cfg,
		log:     log,
		rekeyCh: make(chan string, 1),
		phase:   1, // the first key goes to phase 0
		tunnels: map[Pair]bool{},
		denied:  map[Pair]time.Time{},
		server: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    ca,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		},
	}
	for _, s := range cfg.Switches {
		c.switches = append(c.switches, &Switch{
			cfg: s,
			ctl: c,
			log: log.With("switch", s.Name),
			tls: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      ca,
				ServerName:   s.ServerName,
				MinVersion:   tls.VersionTLS12,
			},
		})
	}
	if cfg.Peer != nil {
		c.peer = newPeerClient(cfg.Peer, &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      ca,
			ServerName:   cfg.Peer.Name,
			MinVersion:   tls.VersionTLS12,
		})
	}
	return c, nil
}

func loadTLS(t config.TLS) (*x509.CertPool, tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
	if err != nil {
		return nil, cert, fmt.Errorf("tls: %w", err)
	}
	pem, err := os.ReadFile(t.CA)
	if err != nil {
		return nil, cert, fmt.Errorf("tls: %w", err)
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(pem) {
		return nil, cert, fmt.Errorf("tls: no certificate in %s", t.CA)
	}
	return ca, cert, nil
}

// Run serves until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	role := "single"
	if c.peer != nil {
		role = map[bool]string{true: "leader", false: "follower"}[c.cfg.Leader()]
	}
	c.log.Info("P4ICS controller", "name", c.cfg.Name, "role", role, "switches", len(c.switches),
		"tunnels", c.cfg.Tunnels.Mode, "key_bits", c.cfg.Keys.Bits, "rotate", c.cfg.Keys.Rotate)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 1)
	if c.cfg.API.Listen != "" {
		go func() { errs <- c.serveAPI(ctx) }()
	}
	go c.rekeyLoop(ctx)
	var wg sync.WaitGroup
	for _, sw := range c.switches {
		wg.Add(1)
		go func() { defer wg.Done(); sw.run(ctx) }()
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
		cancel()
	}
	wg.Wait()
	return err
}

// configure (re)installs everything on a switch the controller just became
// primary for. The switch keeps the current tx phase but gets no key: it
// fails closed until the rotation that follows gives it a new one.
func (c *Controller) configure(ctx context.Context, sw *Switch, rt *client.Client) error {
	p, err := sw.loadPipeline()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := sw.setPipeline(ctx, rt, p); err != nil {
		return err
	}
	var updates []*p4v1.Update
	for _, e := range p.entries {
		switch {
		case e.TableName() == tableLocal || e.TableName() == tableKeys:
			continue // the controller's
		case e.TableName() == tableSec && c.cfg.Tunnels.Mode == config.OnDemand:
			continue // the per-port entries only say which ports face the tunnel
		case e.Default:
			updates = append(updates, update(p4v1.Update_MODIFY, e))
		default:
			updates = append(updates, update(p4v1.Update_INSERT, e))
		}
	}
	if c.cfg.Tunnels.Mode == config.OnDemand {
		e, err := p.info.BuildDefault(tableSec, "request_tunnel", nil)
		if err != nil {
			return err
		}
		updates = append(updates, update(p4v1.Update_MODIFY, e))
	}
	if err := sw.write(ctx, updates...); err != nil {
		return fmt.Errorf("tables: %w", err)
	}
	if c.cfg.Tunnels.Mode == config.OnDemand {
		if err := sw.enableDigest(ctx); err != nil {
			return fmt.Errorf("digest: %w", err)
		}
		for pair := range c.tunnels {
			if err := sw.addTunnel(ctx, pair); err != nil {
				return err
			}
		}
	}
	if err := sw.activate(ctx, c.phase, sa.Epoch(time.Now())); err != nil {
		return err
	}
	sw.mu.Lock()
	sw.ready, sw.configuredAt = true, time.Now()
	sw.mu.Unlock()
	sw.log.Info("configured", "spi", p.spi, "entries", len(updates), "tunnel_ports", p.roles)
	return nil
}

func (c *Controller) readySwitches() []*Switch {
	var out []*Switch
	for _, sw := range c.switches {
		if sw.isReady() {
			out = append(out, sw)
		}
	}
	return out
}

// RequestRekey queues a key rotation (requests arriving together coalesce).
func (c *Controller) RequestRekey(reason string) {
	select {
	case c.rekeyCh <- reason:
	default:
	}
}

func (c *Controller) rekeyLoop(ctx context.Context) {
	var tick <-chan time.Time
	if c.cfg.Keys.Rotate > 0 && c.cfg.Leader() {
		t := time.NewTicker(c.cfg.Keys.Rotate)
		defer t.Stop()
		tick = t.C
	}
	for {
		var reason string
		select {
		case <-ctx.Done():
			return
		case reason = <-c.rekeyCh:
		case <-tick:
			reason = "periodic"
		}
		// let switches that come up together share one rotation
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
		select {
		case r := <-c.rekeyCh:
			reason += ", " + r
		default:
		}
		var err error
		if c.cfg.Leader() {
			err = c.rotate(ctx, reason)
		} else {
			err = c.peer.rekey(ctx, reason)
		}
		if err != nil && ctx.Err() == nil {
			c.log.Error("key rotation failed, retrying in 2s", "reason", reason, "err", err)
			time.AfterFunc(2*time.Second, func() { c.RequestRekey(reason) })
		}
	}
}

// rotate replaces the key without dropping traffic: the new key goes to the
// idle phase of every endpoint first, and only then do the senders switch
// to that phase. Frames already in flight carry the old phase, whose key
// stays installed until the next rotation.
func (c *Controller) rotate(ctx context.Context, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer != nil && c.rotation == 0 {
		// A restarted leader continues from the follower's phase, so the
		// new key goes to the phase the follower is not using.
		if st, err := c.peer.status(ctx); err == nil && st.Rotation > 0 {
			c.phase, c.rotation = st.Phase, st.Rotation
		}
	}
	next, id := 1-c.phase, c.rotation+1
	targets := c.readySwitches()
	if len(targets) == 0 && c.peer == nil {
		return nil // the next switch that comes up asks again
	}
	var key sa.Key
	var err error
	if c.peer != nil {
		key, err = c.peer.prepare(ctx, id, next, c.cfg.Keys.Bits)
		if err != nil {
			return fmt.Errorf("peer %s: %w", c.cfg.Peer.Name, err)
		}
	} else if key, err = sa.NewKey(c.cfg.Keys.Bits); err != nil {
		return err
	}
	for _, sw := range targets {
		if err := sw.installKey(ctx, next, key); err != nil {
			return fmt.Errorf("%s: %w", sw.Name(), err)
		}
	}
	c.activateAll(ctx, targets, next)
	if c.peer != nil {
		if err := c.peer.activate(ctx, id); err != nil {
			// it keeps protecting with the old phase, whose key is still
			// everywhere; it asks for a rotation when it reconnects
			c.log.Error("peer did not activate the new key", "peer", c.cfg.Peer.Name, "err", err)
		}
	}
	c.phase, c.keys[next], c.rotation, c.rotatedAt = next, &key, id, time.Now()
	c.log.Info("key rotated", "rotation", id, "phase", next, "key", key.ID(), "bits", key.Bits(),
		"switches", names(targets), "reason", reason)
	return nil
}

func (c *Controller) activateAll(ctx context.Context, targets []*Switch, phase uint8) {
	epoch := sa.Epoch(time.Now())
	for _, sw := range targets {
		if err := sw.activate(ctx, phase, epoch); err != nil {
			sw.log.Error("still on the previous key", "err", err)
			sw.setReady(false)
		}
	}
}

func names(sws []*Switch) []string {
	var out []string
	for _, sw := range sws {
		out = append(out, sw.Name())
	}
	return out
}

// prepareFromLeader installs the key of a rotation the leader started.
func (c *Controller) prepareFromLeader(ctx context.Context, rotation uint64, phase uint8, bits int, leaderPub []byte) ([]byte, error) {
	if phase > 1 || !sa.ValidBits(bits) {
		return nil, fmt.Errorf("bad phase %d or key size %d", phase, bits)
	}
	x, err := sa.NewExchange()
	if err != nil {
		return nil, err
	}
	key, err := x.Key(leaderPub, rotation, phase, leaderPub, x.Public(), bits)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, sw := range c.readySwitches() {
		if err := sw.installKey(ctx, phase, key); err != nil {
			return nil, fmt.Errorf("%s: %w", sw.Name(), err)
		}
	}
	c.pending = &pendingKey{rotation: rotation, phase: phase, key: key}
	return x.Public(), nil
}

var errNoPending = errors.New("no prepared key for this rotation")

func (c *Controller) activateFromLeader(ctx context.Context, rotation uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil || p.rotation != rotation {
		return errNoPending
	}
	targets := c.readySwitches()
	c.activateAll(ctx, targets, p.phase)
	c.phase, c.keys[p.phase], c.rotation, c.rotatedAt, c.pending = p.phase, &p.key, rotation, time.Now(), nil
	c.log.Info("key rotated", "rotation", rotation, "phase", p.phase, "key", p.key.ID(), "bits", p.key.Bits(),
		"switches", names(targets), "by", c.cfg.Peer.Name)
	return nil
}

// onDigest handles a p4ics_tunnel_request_t: a flow without a tunnel.
func (c *Controller) onDigest(ctx context.Context, sw *Switch, list *p4v1.DigestList) {
	for _, d := range list.GetData() {
		m := d.GetStruct().GetMembers()
		if len(m) < 2 {
			continue
		}
		src, ok1 := netip.AddrFromSlice(pad(m[0].GetBitstring(), 4))
		dst, ok2 := netip.AddrFromSlice(pad(m[1].GetBitstring(), 4))
		if !ok1 || !ok2 {
			continue
		}
		pair := NewPair(src, dst)
		if !c.allowed(pair) {
			c.mu.Lock()
			last := c.denied[pair]
			c.denied[pair] = time.Now()
			c.mu.Unlock()
			if time.Since(last) > time.Minute {
				sw.log.Warn("tunnel not allowed by tunnels.allow", "pair", pair)
			}
			continue
		}
		if err := c.addTunnel(ctx, pair, true); err != nil {
			sw.log.Error("on-demand tunnel", "pair", pair, "err", err)
		}
	}
}

// pad restores the leading zero bytes of a canonical bytestring.
func pad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	return append(make([]byte, n-len(b)), b...)
}

func (c *Controller) allowed(p Pair) bool {
	for _, r := range c.cfg.Tunnels.Allow {
		if (r.A.Contains(p.A) && r.B.Contains(p.B)) || (r.A.Contains(p.B) && r.B.Contains(p.A)) {
			return true
		}
	}
	return false
}

var errStatic = errors.New("tunnels are static (tunnels.mode)")

// addTunnel installs a pair on every switch, then on the peer's.
func (c *Controller) addTunnel(ctx context.Context, pair Pair, toPeer bool) error {
	if c.cfg.Tunnels.Mode != config.OnDemand {
		return errStatic
	}
	c.mu.Lock()
	known := c.tunnels[pair]
	c.tunnels[pair] = true
	var errs []error
	for _, sw := range c.readySwitches() {
		errs = append(errs, sw.addTunnel(ctx, pair))
	}
	c.mu.Unlock()
	if !known {
		c.log.Info("tunnel added", "pair", pair)
	}
	if toPeer && c.peer != nil {
		errs = append(errs, c.peer.tunnel(ctx, pair, true))
	}
	return errors.Join(errs...)
}

func (c *Controller) deleteTunnel(ctx context.Context, pair Pair, toPeer bool) error {
	if c.cfg.Tunnels.Mode != config.OnDemand {
		return errStatic
	}
	c.mu.Lock()
	delete(c.tunnels, pair)
	var errs []error
	for _, sw := range c.readySwitches() {
		errs = append(errs, sw.deleteTunnel(ctx, pair))
	}
	c.mu.Unlock()
	c.log.Info("tunnel deleted", "pair", pair)
	if toPeer && c.peer != nil {
		errs = append(errs, c.peer.tunnel(ctx, pair, false))
	}
	return errors.Join(errs...)
}

// Status is what GET /status returns.
type Status struct {
	Name      string         `json:"name"`
	Role      string         `json:"role"`
	Phase     uint8          `json:"phase"`
	Rotation  uint64         `json:"rotation"`
	RotatedAt *time.Time     `json:"rotated_at,omitempty"`
	Keys      [2]string      `json:"keys"` // key ids per phase, "" if none
	KeyBits   int            `json:"key_bits"`
	Tunnels   []string       `json:"tunnels"`
	Switches  []SwitchStatus `json:"switches"`
	Peer      string         `json:"peer,omitempty"`
}

type SwitchStatus struct {
	Name         string           `json:"name"`
	Address      string           `json:"address"`
	Ready        bool             `json:"ready"`
	SPI          uint32           `json:"spi,omitempty"`
	ConfiguredAt *time.Time       `json:"configured_at,omitempty"`
	Events       map[string]int64 `json:"events,omitempty"`
	Error        string           `json:"error,omitempty"`
}

func (c *Controller) Status(ctx context.Context) Status {
	c.mu.Lock()
	s := Status{Name: c.cfg.Name, Phase: c.phase, Rotation: c.rotation, KeyBits: c.cfg.Keys.Bits, Tunnels: []string{}}
	s.Role = "single"
	if c.peer != nil {
		s.Role = map[bool]string{true: "leader", false: "follower"}[c.cfg.Leader()]
		s.Peer = c.cfg.Peer.Name
	}
	if !c.rotatedAt.IsZero() {
		t := c.rotatedAt
		s.RotatedAt = &t
	}
	for i, k := range c.keys {
		if k != nil {
			s.Keys[i] = k.ID()
		}
	}
	for p := range c.tunnels {
		s.Tunnels = append(s.Tunnels, p.String())
	}
	c.mu.Unlock()
	sort.Strings(s.Tunnels)
	for _, sw := range c.switches {
		st := SwitchStatus{Name: sw.Name(), Address: sw.cfg.Address}
		sw.mu.Lock()
		st.Ready = sw.ready
		if sw.pipe != nil {
			st.SPI = sw.pipe.spi
		}
		if !sw.configuredAt.IsZero() {
			t := sw.configuredAt
			st.ConfiguredAt = &t
		}
		sw.mu.Unlock()
		if st.Ready {
			ev, err := sw.events(ctx)
			st.Events = ev
			if err != nil {
				st.Error = err.Error()
			}
		}
		s.Switches = append(s.Switches, st)
	}
	return s
}

func (c *Controller) rotations() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rotation
}
