package gui

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/ctl"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/p4rt"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/testutil"
)

var p4infoPath, _ = filepath.Abs("../p4rt/testdata/industrial_aes.p4info.txtpb")

// setup runs the controller with s1 (testbed/s1/commands.txt) on a fake
// switch and serves the GUI; gui is YAML added to the gui section, extra
// YAML appended to the configuration.
func setup(t *testing.T, gui, extra string) (*httptest.Server, *ctl.Controller, *testutil.FakeSwitch) {
	t.Helper()
	dir := t.TempDir()
	testutil.PKI(t, dir, "s1", "c1")
	f := testutil.StartFakeSwitch(t, dir, "s1")
	commands, _ := filepath.Abs("../../../testbed/s1/commands.txt")
	topo := filepath.Join(dir, "topology.json")
	os.WriteFile(topo, []byte(`{"hosts": {"modbusclient": {}, "modbusserver": {}}, "switches": ["s1", "s2"],
		"links": [["modbusclient", "s1-p1"], ["s1-p2", "s2-p2"], ["modbusserver", "s2-p1"]]}`), 0o644)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
name: c1
tls: {ca: %[1]s/ca.pem, cert: %[1]s/c1.pem, key: %[1]s/c1-key.pem}
gui: {listen: "127.0.0.1:0", topology: %[2]q %[7]s}
switches:
  - {name: s1, address: %[3]q, device_id: 1, json: %[4]q, p4info: %[4]q, commands: %[5]q}
%[6]s`, dir, topo, f.Addr, p4infoPath, commands, extra, gui)))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := ctl.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	s, err := New(cfg, c, log)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	testutil.Eventually(t, 10*time.Second, "s1 configured with a key", func() bool {
		st := c.Status(context.Background())
		return st.Switches[0].Ready && st.Rotation >= 1
	})
	return srv, c, f
}

func get(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// post submits a form and returns where the GUI redirects to.
func post(t *testing.T, u string, form url.Values) string {
	t.Helper()
	resp, err := noRedirect.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.QueryUnescape(resp.Header.Get("Location"))
	return loc
}

func csrf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, page := get(t, srv.URL+"/p4ics")
	m := regexp.MustCompile(`name='csrf' value='([0-9a-f]+)'`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no form token in the page")
	}
	return m[1]
}

func tableID(t *testing.T, name string) uint32 {
	t.Helper()
	text, _ := os.ReadFile(p4infoPath)
	info, err := p4rt.ParseInfo(text)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := info.Table(name)
	if err != nil {
		t.Fatal(err)
	}
	return tb.GetPreamble().GetId()
}

func tables(t *testing.T, srv *httptest.Server) map[string]ctl.TableView {
	t.Helper()
	_, body := get(t, srv.URL+"/getRules?switch=s1")
	var tv []ctl.TableView
	if err := json.Unmarshal([]byte(body), &tv); err != nil {
		t.Fatal(err)
	}
	out := map[string]ctl.TableView{}
	for _, v := range tv {
		out[v.Name] = v
	}
	return out
}

func TestPages(t *testing.T) {
	srv, c, f := setup(t, "", "")
	st := c.Status(context.Background())
	for path, want := range map[string]string{
		"/":                          "Switch s1",
		"/p4ics":                     st.Keys[st.Phase],
		"/topology":                  "vis-network",
		"/web/css/bootstrap.min.css": "bootstrap",
		"/web/img/router.png":        "PNG",
		"/getTopologyData":           `"Switch s1"`,
		"/getRules?switch=s1":        "200.1.1.7/32",
		"/getCounters?switch=s1":     `"protected"`,
		"/api/status":                `"rotation"`,
		"/healthz":                   "ok",
	} {
		code, body := get(t, srv.URL+path)
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("%s: %d, missing %q", path, code, want)
		}
	}
	if code, _ := get(t, srv.URL+"/getRules?switch=nope"); code != 404 {
		t.Errorf("unknown switch: %d", code)
	}
	// s2 is in the topology but not managed by c1
	if _, body := get(t, srv.URL+"/getTopologyData"); !strings.Contains(body, `"switchesOther"`) ||
		!strings.Contains(body, `"Host modbusclient"`) || !strings.Contains(body, `"to"`) {
		t.Errorf("topology %s", body)
	}

	tv := tables(t, srv)
	if tv["ipv4_lpm"].Managed != "" || len(tv["ipv4_lpm"].Entries) != 8 || tv["p4ics_keys"].Managed == "" ||
		tv["p4ics_local"].Managed == "" || tv["ics_sec"].Managed != "" || tv["ics_sec"].Entries[0].Priority != 1000 {
		t.Fatalf("tables %+v", tv)
	}
	// keys are shown by id, never by value
	keys := f.Entries(tableID(t, "p4ics_keys"))
	if len(keys) == 0 {
		t.Fatal("no key on the switch")
	}
	for _, k := range tv["p4ics_keys"].Entries {
		if len(k.Params) != 1 || !strings.HasPrefix(k.Params[0], "key id ") {
			t.Fatalf("key entry %+v", k)
		}
	}
	if !strings.Contains(tv["p4ics_keys"].Entries[0].Params[0]+tv["p4ics_keys"].Entries[len(keys)-1].Params[0],
		st.Keys[st.Phase]) {
		t.Fatalf("key ids %+v, status %v", tv["p4ics_keys"].Entries, st.Keys)
	}
	for _, path := range []string{"/", "/p4ics", "/getRules?switch=s1", "/api/status"} {
		_, body := get(t, srv.URL+path)
		for _, k := range keys {
			v := hex.EncodeToString(k.GetAction().GetAction().GetParams()[0].GetValue())
			if strings.Contains(body, v[:16]) {
				t.Fatalf("%s shows a key", path)
			}
		}
	}
}

func TestChanges(t *testing.T) {
	srv, c, f := setup(t, "", "")
	lpm := tableID(t, "ipv4_lpm")
	form := url.Values{"switch": {"s1"}, "table": {"ipv4_lpm"}, "action": {"ipv4_forward"},
		"match": {"10.9.0.0/16"}, "params": {"00:00:0a:00:09:01 1"}}
	if loc := post(t, srv.URL+"/rules/add", form); !strings.Contains(loc, "err=invalid form token") {
		t.Fatalf("add without the form token: %s", loc)
	}
	tok := csrf(t, srv)
	form.Set("csrf", tok)
	if loc := post(t, srv.URL+"/rules/add", form); !strings.HasPrefix(loc, "/?ok=") {
		t.Fatalf("add: %s", loc)
	}
	if n := len(f.Entries(lpm)); n != 9 {
		t.Fatalf("%d ipv4_lpm entries", n)
	}
	var ref string
	for _, e := range tables(t, srv)["ipv4_lpm"].Entries {
		if e.Match[0] == "10.9.0.0/16" && e.Params[0] == "00:00:0a:00:09:01" {
			ref = e.Ref
		}
	}
	if ref == "" {
		t.Fatal("added entry not read back")
	}
	// a reference is only valid for its table
	if loc := post(t, srv.URL+"/rules/delete", url.Values{"csrf": {tok}, "switch": {"s1"}, "table": {"ics_sec"},
		"ref": {ref}}); !strings.Contains(loc, "another table") {
		t.Fatalf("delete with the reference of another table: %s", loc)
	}
	if loc := post(t, srv.URL+"/rules/delete", url.Values{"csrf": {tok}, "switch": {"s1"}, "table": {"ipv4_lpm"},
		"ref": {ref}}); !strings.HasPrefix(loc, "/?ok=") {
		t.Fatalf("delete: %s", loc)
	}
	if n := len(f.Entries(lpm)); n != 8 {
		t.Fatalf("%d ipv4_lpm entries after the delete", n)
	}
	// the controller's tables cannot be changed by hand
	for _, table := range []string{"p4ics_keys", "p4ics_local"} {
		loc := post(t, srv.URL+"/rules/add", url.Values{"csrf": {tok}, "switch": {"s1"}, "table": {table},
			"action": {"set_key"}, "match": {"0"}, "params": {"0x1"}})
		if !strings.Contains(loc, "managed by the controller") {
			t.Fatalf("manual %s entry: %s", table, loc)
		}
	}
	// rotation
	rot := c.Status(context.Background()).Rotation
	if loc := post(t, srv.URL+"/rekey", url.Values{"csrf": {tok}}); !strings.HasPrefix(loc, "/p4ics?ok=key rotated") ||
		c.Status(context.Background()).Rotation != rot+1 {
		t.Fatalf("rekey: %s", loc)
	}
	// static mode: no tunnels to add
	if loc := post(t, srv.URL+"/tunnels/add", url.Values{"csrf": {tok}, "a": {"195.11.14.5"}, "b": {"200.1.1.7"}}); !strings.Contains(loc, "static") {
		t.Fatalf("tunnel in static mode: %s", loc)
	}
	// messages are escaped
	if _, body := get(t, srv.URL+"/?err=%3Cscript%3Ealert(1)%3C/script%3E"); strings.Contains(body, "<script>alert(1)") {
		t.Fatal("unescaped message")
	}
}

func TestOnDemandTunnels(t *testing.T) {
	srv, c, f := setup(t, "", "tunnels: {mode: on-demand, allow: [{a: 195.11.14.0/24, b: 200.1.1.7/32}]}")
	sec := tableID(t, "ics_sec")
	tok := csrf(t, srv)
	if n := len(f.Entries(sec)); n != 0 {
		t.Fatalf("%d ics_sec entries before any tunnel", n)
	}
	if tables(t, srv)["ics_sec"].Managed == "" {
		t.Fatal("ics_sec editable in on-demand mode")
	}
	if loc := post(t, srv.URL+"/rules/add", url.Values{"csrf": {tok}, "switch": {"s1"}, "table": {"ics_sec"},
		"action": {"cipher"}, "match": {"2&&&0x1ff 0.0.0.0&&&0 0.0.0.0&&&0"}, "priority": {"1"}}); !strings.Contains(loc, "managed") {
		t.Fatalf("manual ics_sec entry: %s", loc)
	}
	for _, bad := range []url.Values{{"a": {"195.11.14.5"}, "b": {"x"}}, {"a": {"::1"}, "b": {"200.1.1.7"}}} {
		bad.Set("csrf", tok)
		if loc := post(t, srv.URL+"/tunnels/add", bad); !strings.Contains(loc, "IPv4") {
			t.Fatalf("bad tunnel %v: %s", bad, loc)
		}
	}
	// a tunnel outside tunnels.allow: the GUI, like the API, may add it
	form := url.Values{"csrf": {tok}, "a": {"200.1.1.7"}, "b": {"195.11.14.6"}}
	if loc := post(t, srv.URL+"/tunnels/add", form); !strings.HasPrefix(loc, "/p4ics?ok=tunnel 195.11.14.6<->200.1.1.7 added") {
		t.Fatalf("add tunnel: %s", loc)
	}
	if st := c.Status(context.Background()); len(st.Tunnels) != 1 || len(f.Entries(sec)) != 2 {
		t.Fatalf("tunnels %v, %d ics_sec entries", st.Tunnels, len(f.Entries(sec)))
	}
	if _, page := get(t, srv.URL+"/p4ics"); !strings.Contains(page, "195.11.14.6&lt;-&gt;200.1.1.7") ||
		!strings.Contains(page, "value='195.11.14.6'") || !strings.Contains(page, "195.11.14.0/24") {
		t.Fatal("tunnel not on the page")
	}
	if loc := post(t, srv.URL+"/tunnels/delete", form); !strings.HasPrefix(loc, "/p4ics?ok=") {
		t.Fatalf("delete tunnel: %s", loc)
	}
	if st := c.Status(context.Background()); len(st.Tunnels) != 0 || len(f.Entries(sec)) != 0 {
		t.Fatalf("after the delete: tunnels %v, %d ics_sec entries", st.Tunnels, len(f.Entries(sec)))
	}
}

func TestAuthAndReadOnly(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "gui-password")
	os.WriteFile(pw, []byte("s3cret\n"), 0o600)
	srv, c, _ := setup(t, fmt.Sprintf(", user: admin, password_file: %q, read_only: true", pw), "")
	req := func(method, path, user, pass string, body url.Values) *http.Response {
		t.Helper()
		r, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			r.SetBasicAuth(user, pass)
		}
		resp, err := noRedirect.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	for _, path := range []string{"/", "/api/status", "/web/css/bootstrap.min.css"} {
		if code := req("GET", path, "", "", nil).StatusCode; code != 401 {
			t.Errorf("%s without credentials: %d", path, code)
		}
	}
	if code := req("GET", "/", "admin", "wrong", nil).StatusCode; code != 401 {
		t.Errorf("wrong password: %d", code)
	}
	resp := req("GET", "/", "admin", "s3cret", nil)
	if resp.StatusCode != 200 || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("right password: %d %v", resp.StatusCode, resp.Header)
	}
	rot := c.Status(context.Background()).Rotation
	for _, path := range []string{"/rules/add", "/rekey", "/tunnels/add"} {
		loc, _ := url.QueryUnescape(req("POST", path, "admin", "s3cret", url.Values{"switch": {"s1"}}).Header.Get("Location"))
		if !strings.Contains(loc, "read-only") {
			t.Errorf("read-only GUI accepted %s: %s", path, loc)
		}
	}
	if c.Status(context.Background()).Rotation != rot {
		t.Error("read-only GUI rotated the key")
	}
}

func TestPasswordFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	for file, want := range map[string]string{filepath.Join(dir, "missing"): "no such file", empty: "empty"} {
		cfg := &config.Config{GUI: config.GUI{Listen: ":0", User: "admin", PasswordFile: file}}
		if _, err := New(cfg, nil, slog.Default()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", file, err)
		}
	}
}
