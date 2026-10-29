// Package gui serves the web GUI of the controller. Pages, style and assets
// come from the GUI of the UniboSecurityResearch p4runtime-go-client
// controller (pkg/server, KatharaP4AAS version), extended to several
// switches and to the P4ICS keys and tunnels; the Pk-IOTA controller (same
// authors) serves the same GUI.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/ctl"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed web
var webFS embed.FS

type Server struct {
	cfg  *config.Config
	gui  config.GUI // with the password of password_file
	ctl  *ctl.Controller
	log  *slog.Logger
	tmpl *template.Template
	csrf string
}

func New(cfg *config.Config, c *ctl.Controller, log *slog.Logger) (*Server, error) {
	g := cfg.GUI
	if g.User != "" && g.Password == "" {
		b, err := os.ReadFile(g.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("gui.password_file: %w", err)
		}
		if g.Password = strings.TrimSpace(string(b)); g.Password == "" {
			return nil, fmt.Errorf("gui.password_file: %s is empty", g.PasswordFile)
		}
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	t, err := template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, gui: g, ctl: c, log: log, tmpl: t, csrf: hex.EncodeToString(tok)}, nil
}

var funcs = template.FuncMap{
	"tm": func(t any) string {
		var v time.Time
		switch t := t.(type) {
		case time.Time:
			v = t
		case *time.Time:
			if t != nil {
				v = *t
			}
		}
		if v.IsZero() {
			return "-"
		}
		return v.Local().Format("2006-01-02 15:04:05.000")
	},
	"join": strings.Join,
	"int":  func(v uint8) int { return int(v) },
	// the two addresses of a ctl.Pair
	"split": func(pair string) []string { return strings.SplitN(pair, "<->", 2) },
	"sortedEvents": func(m map[string]int64) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	},
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	web, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /web/", http.StripPrefix("/web/", http.FileServer(http.FS(web))))
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /p4ics", s.p4ics)
	mux.HandleFunc("GET /topology", s.topology)
	mux.HandleFunc("GET /getTopologyData", s.topologyData)
	mux.HandleFunc("POST /rules/add", s.addRule)
	mux.HandleFunc("POST /rules/delete", s.deleteRule)
	mux.HandleFunc("POST /rekey", s.rekey)
	mux.HandleFunc("POST /tunnels/add", s.addTunnel)
	mux.HandleFunc("POST /tunnels/delete", s.deleteTunnel)
	// JSON
	mux.HandleFunc("GET /api/status", s.apiStatus)
	mux.HandleFunc("GET /api/tables", s.apiTables)
	// endpoints of the p4runtime-go-client GUI
	mux.HandleFunc("GET /getRules", s.apiTables)
	mux.HandleFunc("GET /getCounters", s.apiCounters)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	return s.auth(mux)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		if s.gui.User != "" {
			u, p, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(s.gui.User)) != 1 ||
				subtle.ConstantTimeCompare([]byte(p), []byte(s.gui.Password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="P4ICS controller"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Serve listens until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{Addr: s.gui.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	// A previous instance may still hold the port while it shuts down.
	var l net.Listener
	var err error
	for i := 0; i < 30; i++ {
		if l, err = net.Listen("tcp", s.gui.Listen); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return err
	}
	if s.gui.User == "" {
		s.log.Warn("GUI without authentication (gui.user)", "address", s.gui.Listen)
	}
	s.log.Info("GUI listening", "address", s.gui.Listen, "auth", s.gui.User != "", "read_only", s.gui.ReadOnly)
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------
// Pages

type switchPage struct {
	ctl.SwitchStatus
	Tables []ctl.TableView
	Error  string
}

type page struct {
	Title    string
	Active   string
	OK, Err  string
	CSRF     string
	ReadOnly bool
	Status   ctl.Status
	Config   *config.Config
	Switches []switchPage
}

func (s *Server) page(r *http.Request, title, active string) page {
	return page{Title: title, Active: active, OK: r.URL.Query().Get("ok"), Err: r.URL.Query().Get("err"),
		CSRF: s.csrf, ReadOnly: s.gui.ReadOnly, Status: s.ctl.Status(r.Context()), Config: s.cfg}
}

func (s *Server) render(w http.ResponseWriter, name string, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, p); err != nil {
		s.log.Error("template", "name", name, "err", err)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	p := s.page(r, "Switches", "home")
	for _, st := range p.Status.Switches {
		sp := switchPage{SwitchStatus: st}
		if sw, err := s.ctl.Switch(st.Name); err == nil && st.Ready {
			if sp.Tables, err = sw.Tables(r.Context()); err != nil {
				sp.Error = err.Error()
			}
		}
		p.Switches = append(p.Switches, sp)
	}
	s.render(w, "index.html", p)
}

func (s *Server) p4ics(w http.ResponseWriter, r *http.Request) {
	s.render(w, "p4ics.html", s.page(r, "Keys & tunnels", "p4ics"))
}

func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	s.render(w, "topology.html", s.page(r, "Topology", "topology"))
}

// back redirects to the page at path with the outcome of a change.
func (s *Server) back(w http.ResponseWriter, r *http.Request, path string, err error, ok string) {
	q := url.Values{}
	if err != nil {
		q.Set("err", err.Error())
	} else {
		q.Set("ok", ok)
	}
	http.Redirect(w, r, path+"?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) checkPost(r *http.Request) error {
	if s.gui.ReadOnly {
		return errors.New("the GUI is read-only")
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrf)) != 1 {
		return errors.New("invalid form token: reload the page")
	}
	return nil
}

func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	if err := s.checkPost(r); err != nil {
		s.back(w, r, "/", err, "")
		return
	}
	sw, err := s.ctl.Switch(r.PostFormValue("switch"))
	if err != nil {
		s.back(w, r, "/", err, "")
		return
	}
	prio := 0
	if p := strings.TrimSpace(r.PostFormValue("priority")); p != "" {
		if prio, err = strconv.Atoi(p); err != nil {
			s.back(w, r, "/", fmt.Errorf("priority: %w", err), "")
			return
		}
	}
	table, action := r.PostFormValue("table"), r.PostFormValue("action")
	match := strings.Fields(r.PostFormValue("match"))
	params := strings.Fields(r.PostFormValue("params"))
	err = sw.AddEntry(r.Context(), table, action, match, params, prio)
	s.back(w, r, "/", err, fmt.Sprintf("%s: entry added to %s", sw.Name(), table))
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.checkPost(r); err != nil {
		s.back(w, r, "/", err, "")
		return
	}
	sw, err := s.ctl.Switch(r.PostFormValue("switch"))
	if err != nil {
		s.back(w, r, "/", err, "")
		return
	}
	table := r.PostFormValue("table")
	err = sw.DeleteEntry(r.Context(), table, r.PostFormValue("ref"))
	s.back(w, r, "/", err, fmt.Sprintf("%s: entry deleted from %s", sw.Name(), table))
}

func (s *Server) rekey(w http.ResponseWriter, r *http.Request) {
	if err := s.checkPost(r); err != nil {
		s.back(w, r, "/p4ics", err, "")
		return
	}
	err := s.ctl.Rekey(r.Context(), "GUI")
	s.back(w, r, "/p4ics", err, fmt.Sprintf("key rotated (rotation %d)", s.ctl.Status(r.Context()).Rotation))
}

// pair reads the endpoint pair of a tunnel form.
func pair(r *http.Request) (ctl.Pair, error) {
	a, err1 := netip.ParseAddr(strings.TrimSpace(r.PostFormValue("a")))
	b, err2 := netip.ParseAddr(strings.TrimSpace(r.PostFormValue("b")))
	if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() {
		return ctl.Pair{}, errors.New("a and b: IPv4 addresses")
	}
	return ctl.NewPair(a, b), nil
}

func (s *Server) addTunnel(w http.ResponseWriter, r *http.Request) {
	if err := s.checkPost(r); err != nil {
		s.back(w, r, "/p4ics", err, "")
		return
	}
	p, err := pair(r)
	if err == nil {
		err = s.ctl.AddTunnel(r.Context(), p)
	}
	s.back(w, r, "/p4ics", err, "tunnel "+p.String()+" added")
}

func (s *Server) deleteTunnel(w http.ResponseWriter, r *http.Request) {
	if err := s.checkPost(r); err != nil {
		s.back(w, r, "/p4ics", err, "")
		return
	}
	p, err := pair(r)
	if err == nil {
		err = s.ctl.DeleteTunnel(r.Context(), p)
	}
	s.back(w, r, "/p4ics", err, "tunnel "+p.String()+" deleted")
}

// ---------------------------------------------------------------------
// Topology (format of the p4runtime-go-client GUI)

type node struct {
	ID    int    `json:"id"`
	Label string `json:"label"`
	Group string `json:"group"`
}

type edge struct {
	From int `json:"from"`
	To   int `json:"to"`
}

func (s *Server) topologyData(w http.ResponseWriter, r *http.Request) {
	var topo struct {
		Hosts    map[string]json.RawMessage `json:"hosts"`
		Switches []string                   `json:"switches"`
		Links    [][]string                 `json:"links"`
	}
	if s.gui.Topology != "" {
		b, err := os.ReadFile(s.gui.Topology)
		if err == nil {
			err = json.Unmarshal(b, &topo)
		}
		if err != nil {
			http.Error(w, "topology: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	ready := map[string]bool{}
	for _, sw := range s.ctl.Status(r.Context()).Switches {
		ready[sw.Name] = sw.Ready
		if !slices.Contains(topo.Switches, sw.Name) {
			topo.Switches = append(topo.Switches, sw.Name)
		}
	}
	var nodes []node
	ids := map[string]int{}
	hosts := make([]string, 0, len(topo.Hosts))
	for h := range topo.Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		ids[h] = len(nodes) + 1
		nodes = append(nodes, node{ids[h], "Host " + h, "hosts"})
	}
	for _, sw := range topo.Switches {
		ids[sw] = len(nodes) + 1
		group, label := "switches", "Switch "+sw
		up, managed := ready[sw]
		switch {
		case !managed && s.cfg.Peer != nil:
			group, label = "switchesOther", label+"\n(managed by "+s.cfg.Peer.Name+")"
		case !managed:
			group, label = "switchesOther", label+"\n(not managed)"
		case !up:
			group, label = "switchesUnavailable", label+"\nUNAVAILABLE"
		}
		nodes = append(nodes, node{ids[sw], label, group})
	}
	var edges []edge
	for _, l := range topo.Links {
		if len(l) != 2 {
			continue
		}
		a, b := strings.Split(l[0], "-")[0], strings.Split(l[1], "-")[0]
		if ids[a] != 0 && ids[b] != 0 {
			edges = append(edges, edge{ids[a], ids[b]})
		}
	}
	writeJSON(w, map[string]any{"nodes": nodes, "edges": edges})
}

// ---------------------------------------------------------------------
// JSON

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.ctl.Status(r.Context()))
}

func (s *Server) apiTables(w http.ResponseWriter, r *http.Request) {
	sw, err := s.ctl.Switch(r.URL.Query().Get("switch"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	tables, err := sw.Tables(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, tables)
}

func (s *Server) apiCounters(w http.ResponseWriter, r *http.Request) {
	sw, err := s.ctl.Switch(r.URL.Query().Get("switch"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	c, err := sw.Events(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, c)
}
