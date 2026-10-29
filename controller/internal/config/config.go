// Package config reads the controller configuration (YAML). See
// controller/README.md and the examples in controller/lab/.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/sa"
)

type Config struct {
	// Name of this controller: the common name of its certificate, and how
	// the peer controller recognises it.
	Name     string   `yaml:"name"`
	TLS      TLS      `yaml:"tls"`
	API      API      `yaml:"api"`
	GUI      GUI      `yaml:"gui"`
	Keys     Keys     `yaml:"keys"`
	Tunnels  Tunnels  `yaml:"tunnels"`
	Switches []Switch `yaml:"switches"`
	// Optional second controller managing the other switches. The two agree
	// on every key with a Diffie-Hellman exchange.
	Peer *Peer `yaml:"peer"`
}

// TLS: PEM files. The same certificate authenticates the controller to the
// switches (gRPC), to the peer and to API clients (HTTPS); the CA verifies
// all of them. controller/pki.sh creates them.
type TLS struct {
	CA   string `yaml:"ca"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type API struct {
	// host:port of the HTTPS API (client certificates required); empty: no
	// API. A peer controller needs it.
	Listen string `yaml:"listen"`
	// Common names of the client certificates allowed to use it.
	Admins []string `yaml:"admins"`
}

// GUI: the web GUI of the p4runtime-go-client controller (KatharaP4AAS),
// over plain HTTP.
type GUI struct {
	// host:port of the GUI; empty: no GUI.
	Listen string `yaml:"listen"`
	// HTTP basic authentication; no user: no authentication.
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"password_file"` // read at startup when password is empty
	// Topology shown by /topology, in the format of the P4AAS GUI (hosts,
	// switches, links). Optional.
	Topology string `yaml:"topology"`
	// No changes from the GUI: no entries, rotations or tunnels.
	ReadOnly bool `yaml:"read_only"`
}

type Keys struct {
	Bits int `yaml:"bits"`
	// Periodic rotation; 0: rotate only on request and when a switch
	// (re)connects. With a peer, the leader's value applies.
	Rotate time.Duration `yaml:"rotate"`
}

type Tunnels struct {
	// static: the ics_sec entries of the switches' commands.txt.
	// on-demand: a tunnel per endpoint pair, when traffic shows up.
	Mode  string  `yaml:"mode"`
	Allow []Allow `yaml:"allow"`
}

// Allow lets on-demand tunnels between an address in A and one in B.
type Allow struct {
	A netip.Prefix `yaml:"a"`
	B netip.Prefix `yaml:"b"`
}

type Switch struct {
	Name string `yaml:"name"`
	// host:port of simple_switch_grpc.
	Address    string `yaml:"address"`
	DeviceID   uint64 `yaml:"device_id"`
	ServerName string `yaml:"server_name"` // name in its certificate; default: Name
	// Pipeline: p4c-bm2-ss --emit-externs --p4runtime-files <p4info> -o <json>.
	JSON   string `yaml:"json"`
	P4Info string `yaml:"p4info"`
	// simple_switch_CLI file with the switch's tables (testbed/sN/commands.txt).
	Commands string `yaml:"commands"`
	// Sender id 1..255; default: the set_local_sa default entry of Commands.
	SPI uint32 `yaml:"spi"`
}

type Peer struct {
	Name string `yaml:"name"` // common name of its certificate
	URL  string `yaml:"url"`  // https://host:port of its API
}

const (
	Static   = "static"
	OnDemand = "on-demand"
)

// Load reads and checks a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, err
	}
	if c.Keys.Bits == 0 {
		c.Keys.Bits = 256
	}
	if c.Tunnels.Mode == "" {
		c.Tunnels.Mode = Static
	}
	if c.API.Admins == nil {
		c.API.Admins = []string{"admin"}
	}
	for i := range c.Switches {
		if c.Switches[i].ServerName == "" {
			c.Switches[i].ServerName = c.Switches[i].Name
		}
	}
	return c, c.check()
}

func (c *Config) check() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if c.Name == "" {
		fail("name: missing")
	}
	if c.TLS.CA == "" || c.TLS.Cert == "" || c.TLS.Key == "" {
		fail("tls: ca, cert and key are required (mutual TLS with the switches)")
	}
	if c.GUI.Listen != "" && c.GUI.User != "" && c.GUI.Password == "" && c.GUI.PasswordFile == "" {
		fail("gui: user %s without password or password_file", c.GUI.User)
	}
	if c.GUI.Listen != "" && c.GUI.Listen == c.API.Listen {
		fail("gui.listen: same address as api.listen")
	}
	if !sa.ValidBits(c.Keys.Bits) {
		fail("keys.bits: %d: must be 128, 160, 192, 224 or 256", c.Keys.Bits)
	}
	if c.Keys.Rotate < 0 || (c.Keys.Rotate > 0 && c.Keys.Rotate < time.Second) {
		fail("keys.rotate: %s: must be 0 or at least 1s", c.Keys.Rotate)
	}
	switch c.Tunnels.Mode {
	case Static:
	case OnDemand:
		if len(c.Tunnels.Allow) == 0 {
			fail("tunnels.allow: on-demand tunnels need at least one rule (0.0.0.0/0 allows all)")
		}
		for i, a := range c.Tunnels.Allow {
			if !a.A.IsValid() || !a.B.IsValid() || !a.A.Addr().Is4() || !a.B.Addr().Is4() {
				fail("tunnels.allow[%d]: a and b must be IPv4 prefixes", i)
			}
		}
	default:
		fail("tunnels.mode: %q: must be %s or %s", c.Tunnels.Mode, Static, OnDemand)
	}
	if len(c.Switches) == 0 {
		fail("switches: none")
	}
	names := map[string]bool{}
	for i, s := range c.Switches {
		if s.Name == "" || names[s.Name] {
			fail("switches[%d]: missing or repeated name", i)
		}
		names[s.Name] = true
		if s.Address == "" || s.JSON == "" || s.P4Info == "" || s.Commands == "" {
			fail("switch %s: address, json, p4info and commands are required", s.Name)
		}
		if s.SPI > 255 {
			fail("switch %s: spi %d: must be 1..255", s.Name, s.SPI)
		}
	}
	if c.Peer != nil {
		if c.Peer.Name == "" || c.Peer.URL == "" {
			fail("peer: name and url are required")
		}
		if c.Peer.Name == c.Name {
			fail("peer: same name as this controller")
		}
		if c.API.Listen == "" {
			fail("api.listen: required with a peer")
		}
	}
	return errors.Join(errs...)
}

// Leader: the controller that runs key rotations (a single controller, or
// the one of the pair whose name sorts first).
func (c *Config) Leader() bool {
	return c.Peer == nil || c.Name < c.Peer.Name
}
