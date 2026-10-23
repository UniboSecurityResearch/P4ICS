package ctl

import (
	"bytes"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
)

// A switch of the testbed, with the P4Info of internal/p4rt/testdata.
func testbedSwitch(t *testing.T, name string) *Switch {
	t.Helper()
	sw := &Switch{cfg: config.Switch{
		Name:     name,
		JSON:     filepath.Join("..", "p4rt", "testdata", "industrial_aes.p4info.txtpb"), // any file
		P4Info:   filepath.Join("..", "p4rt", "testdata", "industrial_aes.p4info.txtpb"),
		Commands: filepath.Join("..", "..", "..", "testbed", name, "commands.txt"),
	}, log: slog.Default()}
	p, err := sw.loadPipeline()
	if err != nil {
		t.Fatal(err)
	}
	sw.pipe = p
	return sw
}

func TestPipelineFromCommands(t *testing.T) {
	for name, spi := range map[string]uint32{"s1": 1, "s2": 2} {
		p := testbedSwitch(t, name).pipe
		if p.spi != spi {
			t.Errorf("%s: spi %d", name, p.spi)
		}
		if p.roles[1] != "decipher" || p.roles[2] != "cipher" || len(p.roles) != 2 {
			t.Errorf("%s: roles %v", name, p.roles)
		}
	}
	p := testbedSwitch(t, "s1").pipe
	for addr, port := range map[string]uint32{"200.1.1.7": 2, "195.11.14.5": 1, "195.11.14.10": 1} {
		if got, ok := p.port(netip.MustParseAddr(addr)); !ok || got != port {
			t.Errorf("s1 route to %s: port %d, %v", addr, got, ok)
		}
	}
	if _, ok := p.port(netip.MustParseAddr("10.0.0.1")); ok {
		t.Error("route to an unknown address")
	}
}

func TestLongestPrefix(t *testing.T) {
	p := &pipeline{routes: []route{
		{netip.MustParsePrefix("10.0.0.0/8"), 1},
		{netip.MustParsePrefix("10.1.0.0/16"), 2},
		{netip.MustParsePrefix("0.0.0.0/0"), 3},
	}}
	for addr, port := range map[string]uint32{"10.1.2.3": 2, "10.2.0.1": 1, "8.8.8.8": 3} {
		if got, _ := p.port(netip.MustParseAddr(addr)); got != port {
			t.Errorf("%s: port %d, want %d", addr, got, port)
		}
	}
}

func TestTunnelEntries(t *testing.T) {
	client, server := netip.MustParseAddr("195.11.14.5"), netip.MustParseAddr("200.1.1.7")
	pair := NewPair(server, client)
	if pair.A != client || pair != NewPair(client, server) {
		t.Fatalf("pair %v", pair)
	}
	want := map[string][2]string{
		// switch: action towards the server, action towards the client
		"s1": {"cipher", "decipher"},
		"s2": {"decipher", "cipher"},
	}
	for name, actions := range want {
		entries, err := testbedSwitch(t, name).tunnelEntries(pair)
		if err != nil || len(entries) != 2 {
			t.Fatalf("%s: %v %v", name, entries, err)
		}
		for i, e := range entries {
			te := e.TableEntry()
			src, dst := te.Match[1].GetTernary().Value, te.Match[2].GetTernary().Value
			if e.ActionName() != actions[i] || len(te.Match) != 3 || te.Priority <= 0 {
				t.Errorf("%s entry %d: %s %v", name, i, e.ActionName(), te)
			}
			if i == 0 && (!bytes.Equal(src, client.AsSlice()) || !bytes.Equal(dst, server.AsSlice())) {
				t.Errorf("%s: client->server entry matches %v -> %v", name, src, dst)
			}
		}
	}
}

func TestAllowed(t *testing.T) {
	cfg := &config.Config{Tunnels: config.Tunnels{Mode: config.OnDemand, Allow: []config.Allow{
		{A: netip.MustParsePrefix("195.11.14.0/24"), B: netip.MustParsePrefix("200.1.1.7/32")},
	}}}
	c := &Controller{cfg: cfg}
	a := func(x, y string) bool { return c.allowed(NewPair(netip.MustParseAddr(x), netip.MustParseAddr(y))) }
	if !a("195.11.14.5", "200.1.1.7") || !a("200.1.1.7", "195.11.14.99") {
		t.Error("allowed pair refused")
	}
	if a("195.11.14.5", "200.1.1.8") || a("195.11.14.5", "195.11.14.6") {
		t.Error("pair outside the rules allowed")
	}
}

func TestPad(t *testing.T) {
	if !bytes.Equal(pad([]byte{1, 2}, 4), []byte{0, 0, 1, 2}) || !bytes.Equal(pad([]byte{9, 1, 2, 3, 4}, 4), []byte{1, 2, 3, 4}) {
		t.Error("pad")
	}
}
