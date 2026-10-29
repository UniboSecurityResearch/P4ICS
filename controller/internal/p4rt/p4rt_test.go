package p4rt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

// testdata/industrial_aes.p4info.txtpb is generated from testbed/s1 (CI
// checks it is up to date).
func loadInfo(t *testing.T) *Info {
	t.Helper()
	text, err := os.ReadFile("testdata/industrial_aes.p4info.txtpb")
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseInfo(text)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestTestbedCommands(t *testing.T) {
	info := loadInfo(t)
	for _, sw := range []string{"s1", "s2"} {
		text, err := os.ReadFile(filepath.Join("..", "..", "..", "testbed", sw, "commands.txt"))
		if err != nil {
			t.Fatal(err)
		}
		entries, err := info.ParseCommands(text)
		if err != nil {
			t.Fatalf("%s: %v", sw, err)
		}
		if n := strings.Count(string(text), "\ntable_") + 1; len(entries) != n {
			t.Fatalf("%s: %d entries for %d commands", sw, len(entries), n)
		}
	}
}

func TestForwardEntry(t *testing.T) {
	info := loadInfo(t)
	entries, err := info.ParseCommands([]byte(
		"# comment\n\ntable_add ipv4_lpm ipv4_forward 200.1.1.7/24 =>  00:00:0a:00:01:02 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := entries[0]
	if e.TableName() != "ipv4_lpm" || e.ActionName() != "ipv4_forward" {
		t.Fatalf("names %s %s", e.TableName(), e.ActionName())
	}
	if p, _ := e.Param("port"); p != "1" {
		t.Fatalf("port param %q", p)
	}
	te := e.TableEntry()
	lpm := te.Match[0].GetLpm()
	// host bits cleared, as P4Runtime requires
	if !bytes.Equal(lpm.Value, []byte{200, 1, 1, 0}) || lpm.PrefixLen != 24 {
		t.Fatalf("lpm %v/%d", lpm.Value, lpm.PrefixLen)
	}
	params := te.Action.GetAction().Params
	if !bytes.Equal(params[0].Value, []byte{0x0a, 0, 1, 2}) || !bytes.Equal(params[1].Value, []byte{1}) {
		t.Fatalf("params %v", params)
	}
	if te.Priority != 0 || te.IsDefaultAction {
		t.Fatalf("priority %d default %v", te.Priority, te.IsDefaultAction)
	}
}

func TestTernaryEntry(t *testing.T) {
	info := loadInfo(t)
	wild, err := info.Build("ics_sec", "cipher", []string{"2&&&0x1ff", "0.0.0.0&&&0.0.0.0", "0.0.0.0&&&0.0.0.0"}, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	te := wild.TableEntry()
	// zero masks are don't-care fields: omitted
	if len(te.Match) != 1 || !bytes.Equal(te.Match[0].GetTernary().Value, []byte{2}) ||
		!bytes.Equal(te.Match[0].GetTernary().Mask, []byte{1, 0xff}) {
		t.Fatalf("match %v", te.Match)
	}
	pair, err := info.Build("ics_sec", "decipher", []string{"1&&&0x1ff", "200.1.1.7&&&255.255.255.255", "195.11.14.5"}, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	// lower CLI priority wins in bmv2, higher P4Runtime priority wins
	if pair.TableEntry().Priority <= te.Priority {
		t.Fatalf("priorities %d %d", pair.TableEntry().Priority, te.Priority)
	}
	if len(pair.TableEntry().Match) != 3 {
		t.Fatalf("pair match %v", pair.TableEntry().Match)
	}
	// value bits outside the mask are cleared
	e, err := info.Build("ics_sec", "cipher", []string{"0x1ff&&&0x0f0", "1.2.3.4&&&255.0.0.0", "0.0.0.0&&&0"}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	m := e.TableEntry().Match
	if !bytes.Equal(m[0].GetTernary().Value, []byte{0xf0}) || !bytes.Equal(m[1].GetTernary().Value, []byte{1, 0, 0, 0}) {
		t.Fatalf("masked values %v", m)
	}
}

func TestDefaultAndKeyEntries(t *testing.T) {
	info := loadInfo(t)
	d, err := info.BuildDefault("p4ics_local", "set_local_sa", []string{"7", "1", "0x0102030405060708"})
	if err != nil {
		t.Fatal(err)
	}
	te := d.TableEntry()
	if !te.IsDefaultAction || len(te.Match) != 0 {
		t.Fatalf("default entry %v", te)
	}
	p := te.Action.GetAction().Params
	if !bytes.Equal(p[0].Value, []byte{7}) || !bytes.Equal(p[1].Value, []byte{1}) ||
		!bytes.Equal(p[2].Value, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("params %v", p)
	}
	key := "0x" + strings.Repeat("00", 2) + strings.Repeat("ab", 30)
	k, err := info.Build("p4ics_keys", "set_key", []string{"0"}, []string{key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	kv := k.TableEntry()
	if !bytes.Equal(kv.Match[0].GetExact().Value, []byte{0}) || len(kv.Action.GetAction().Params[0].Value) != 30 {
		t.Fatalf("key entry %v", kv)
	}
	if kv.Priority != 0 {
		t.Fatalf("exact table with priority %d", kv.Priority)
	}
}

func TestErrors(t *testing.T) {
	info := loadInfo(t)
	for _, line := range []string{
		"register_write keys 0 1",                                             // not a table command
		"table_add nosuch drop 1 =>",                                          // table
		"table_add ipv4_lpm cipher 1.2.3.4/32 =>",                             // action of another table
		"table_add ipv4_lpm ipv4_forward 1.2.3.4/33 => 00:00:00:00:00:01 1",   // prefix
		"table_add ipv4_lpm ipv4_forward 1.2.3.4/32 => 00:00:00:00:00:01 512", // 9-bit port
		"table_add ipv4_lpm ipv4_forward 1.2.3.4/32 => 00:00:00:00:00:01",     // missing param
		"table_add p4ics_keys set_key 2 => 0x1",                               // 1-bit phase
		"table_add ics_sec cipher 1&&&0x1ff 0.0.0.0&&&0.0.0.0 => 1",           // missing field
		"table_add ics_sec cipher 1 2 3 => 70000",                             // priority range
		"table_set_default p4ics_local set_local_sa 1 0",                      // missing epoch
		"table_add ipv4_lpm ipv4_forward 1.2.3/32 => 00:00:00:00:00:01 1",     // address
	} {
		if _, err := info.ParseCommands([]byte(line)); err == nil {
			t.Errorf("accepted %q", line)
		}
	}
}

func TestNames(t *testing.T) {
	info := loadInfo(t)
	for _, n := range []string{"MyIngress.p4ics_events", "p4ics_events"} {
		if c, err := info.Counter(n); err != nil || c.GetSize() != 5 {
			t.Fatalf("counter %s: %v", n, err)
		}
	}
	d, err := info.Digest("p4ics_tunnel_request_t")
	if err != nil || len(d.GetTypeSpec().GetStruct().GetName()) == 0 {
		t.Fatalf("digest: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	info := loadInfo(t)
	entries, err := info.ParseCommands([]byte(
		"table_add ipv4_lpm ipv4_forward 200.1.1.0/24 => 00:00:0a:00:01:02 1\n" +
			"table_add ics_sec cipher 2&&&0x1ff 0.0.0.0&&&0.0.0.0 200.1.1.7&&&255.255.255.255 => 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := info.Describe(entries[0].TableEntry())
	if d.Table != "ipv4_lpm" || d.Action != "ipv4_forward" || strings.Join(d.Match, " ") != "200.1.1.0/24" ||
		strings.Join(d.Params, " ") != "00:00:0a:00:01:02 0x1" {
		t.Fatalf("ipv4_lpm entry %+v", d)
	}
	// don't-care fields are omitted on the wire and shown as *
	d = info.Describe(entries[1].TableEntry())
	if strings.Join(d.Match, " ") != "0x2&&&0x1ff * 200.1.1.7&&&255.255.255.255" || len(d.Params) != 0 {
		t.Fatalf("ics_sec entry %+v", d)
	}
	// what Describe writes, Build reads back
	d = info.Describe(entries[0].TableEntry())
	e, err := info.Build(d.Table, d.Action, d.Match, d.Params, 0)
	if err != nil || !proto.Equal(e.TableEntry(), entries[0].TableEntry()) {
		t.Fatalf("round trip: %v", err)
	}
	// a 32-bit parameter that is not an address stays a number
	sa, _ := info.BuildDefault("p4ics_local", "set_local_sa", []string{"7", "1", "0x10"})
	if d := info.Describe(sa.TableEntry()); strings.Join(d.Params, " ") != "0x7 0x1 0x10" || !d.Default {
		t.Fatalf("p4ics_local default %+v", d)
	}
}
