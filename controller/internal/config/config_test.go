package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const base = `
name: c1
tls: {ca: ca.pem, cert: c1.pem, key: c1-key.pem}
switches:
  - name: s1
    address: 100.0.1.1:50051
    device_id: 1
    json: s1.json
    p4info: s1.p4info.txtpb
    commands: s1.commands.txt
`

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Keys.Bits != 256 || c.Keys.Rotate != 0 || c.Tunnels.Mode != Static {
		t.Fatalf("defaults %+v %+v", c.Keys, c.Tunnels)
	}
	if c.Switches[0].ServerName != "s1" || c.API.Admins[0] != "admin" || !c.Leader() {
		t.Fatalf("defaults %+v %+v", c.Switches[0], c.API)
	}
}

func TestFull(t *testing.T) {
	c, err := Parse([]byte(base + `
api: {listen: ":3333", admins: [ops]}
gui: {listen: ":8080", user: admin, password_file: gui-password, read_only: true}
keys: {bits: 128, rotate: 90s}
tunnels:
  mode: on-demand
  allow:
    - {a: 195.11.14.0/24, b: 200.1.1.7/32}
peer: {name: c0, url: "https://100.0.1.10:3333"}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Keys.Rotate != 90*time.Second || c.Tunnels.Allow[0].B.Bits() != 32 || c.Leader() {
		t.Fatalf("%+v %+v leader=%v", c.Keys, c.Tunnels, c.Leader())
	}
	if c.GUI.Listen != ":8080" || c.GUI.PasswordFile != "gui-password" || !c.GUI.ReadOnly {
		t.Fatalf("gui %+v", c.GUI)
	}
}

func TestErrors(t *testing.T) {
	for extra, want := range map[string]string{
		"keys: {bits: 100}":                                     "keys.bits",
		"keys: {rotate: 10ms}":                                  "keys.rotate",
		"tunnels: {mode: sometimes}":                            "tunnels.mode",
		"tunnels: {mode: on-demand}":                            "tunnels.allow",
		"peer: {name: c2, url: https://x}":                      "api.listen",
		"peer: {name: c1, url: https://x}\napi: {listen: ':1'}": "same name",
		"gui: {listen: ':8080', user: admin}":                   "gui: user admin without password",
		"gui: {listen: ':1'}\napi: {listen: ':1'}":              "gui.listen",
	} {
		_, err := Parse([]byte(base + extra))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %s", extra, err, want)
		}
	}
	if _, err := Parse([]byte("name: c1\n")); err == nil || !strings.Contains(err.Error(), "tls") ||
		!strings.Contains(err.Error(), "switches") {
		t.Errorf("empty config: %v", err)
	}
}

func TestLabConfigs(t *testing.T) {
	files, _ := filepath.Glob("../../lab/*/*.yml")
	if len(files) != 3 {
		t.Fatalf("lab configurations: %v", files)
	}
	for _, f := range files {
		c, err := Load(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if c.Peer != nil && c.Leader() != (c.Name == "c1") {
			t.Errorf("%s: c1 must lead", f)
		}
	}
}
