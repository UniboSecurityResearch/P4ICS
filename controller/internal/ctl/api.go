package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"time"
)

// HTTPS API. Every client presents a certificate of the CA; its common name
// decides what it may call:
//
//	GET    /status                     admins, peer
//	POST   /rekey                      admins  (?wait=1: return after the rotation)
//	GET    /tunnels                    admins
//	POST   /tunnels   {"a":..,"b":..}  admins  (on-demand mode)
//	DELETE /tunnels?a=..&b=..          admins
//	POST   /peer/...                   peer    (see peer.go)
func (c *Controller) serveAPI(ctx context.Context) error {
	mux := http.NewServeMux()
	admin, peer := c.cfg.API.Admins, []string{}
	if c.cfg.Peer != nil {
		peer = []string{c.cfg.Peer.Name}
	}
	handle := func(pattern string, allowed []string, h func(*http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			cn := ""
			if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
				cn = r.TLS.VerifiedChains[0][0].Subject.CommonName
			}
			if !slices.Contains(allowed, cn) {
				http.Error(w, "forbidden for "+cn, http.StatusForbidden)
				return
			}
			out, err := h(r)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				code := http.StatusInternalServerError
				var he httpError
				switch {
				case errors.As(err, &he):
					code = he.code
				case errors.Is(err, errStatic) || errors.Is(err, errNoPending):
					code = http.StatusConflict
				}
				w.WriteHeader(code)
				out = map[string]string{"error": err.Error()}
			}
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	both := append(slices.Clone(admin), peer...)

	handle("GET /status", both, func(r *http.Request) (any, error) {
		return c.Status(r.Context()), nil
	})
	handle("POST /rekey", admin, func(r *http.Request) (any, error) {
		if r.URL.Query().Get("wait") == "" {
			c.RequestRekey("API")
			return map[string]string{"queued": "rotation"}, nil
		}
		if err := c.Rekey(r.Context(), "API"); errors.Is(err, errRekeyTimeout) {
			return nil, httpError{http.StatusGatewayTimeout, err.Error()}
		} else if err != nil {
			return nil, err
		}
		return c.Status(r.Context()), nil
	})
	handle("GET /tunnels", admin, func(r *http.Request) (any, error) {
		return c.Status(r.Context()).Tunnels, nil
	})
	handle("POST /tunnels", admin, func(r *http.Request) (any, error) {
		var t tunnelRequest
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			return nil, httpError{http.StatusBadRequest, err.Error()}
		}
		if !t.A.Is4() || !t.B.Is4() {
			return nil, httpError{http.StatusBadRequest, "a and b: IPv4 addresses"}
		}
		return map[string]string{"added": NewPair(t.A, t.B).String()}, c.addTunnel(r.Context(), NewPair(t.A, t.B), true)
	})
	handle("DELETE /tunnels", admin, func(r *http.Request) (any, error) {
		a, err1 := netip.ParseAddr(r.URL.Query().Get("a"))
		b, err2 := netip.ParseAddr(r.URL.Query().Get("b"))
		if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() {
			return nil, httpError{http.StatusBadRequest, "a and b: IPv4 addresses"}
		}
		return map[string]string{"deleted": NewPair(a, b).String()}, c.deleteTunnel(r.Context(), NewPair(a, b), true)
	})

	handle("POST /peer/prepare", peer, func(r *http.Request) (any, error) {
		var req prepareRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, httpError{http.StatusBadRequest, err.Error()}
		}
		if c.cfg.Leader() {
			return nil, httpError{http.StatusConflict, "this controller is the leader"}
		}
		pub, err := c.prepareFromLeader(r.Context(), req.Rotation, req.Phase, req.Bits, req.Public)
		return prepareResponse{Public: pub}, err
	})
	handle("POST /peer/activate", peer, func(r *http.Request) (any, error) {
		var req activateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, httpError{http.StatusBadRequest, err.Error()}
		}
		return map[string]uint64{"activated": req.Rotation}, c.activateFromLeader(r.Context(), req.Rotation)
	})
	handle("POST /peer/rekey", peer, func(r *http.Request) (any, error) {
		var req rekeyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !c.cfg.Leader() {
			return nil, httpError{http.StatusConflict, "this controller is not the leader"}
		}
		c.RequestRekey(c.cfg.Peer.Name + ": " + req.Reason)
		return map[string]string{"queued": "rotation"}, nil
	})
	handle("POST /peer/tunnel", peer, func(r *http.Request) (any, error) {
		var t tunnelRequest
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil || !t.A.Is4() || !t.B.Is4() {
			return nil, httpError{http.StatusBadRequest, "a and b: IPv4 addresses"}
		}
		pair := NewPair(t.A, t.B)
		if !t.Add {
			return map[string]string{"deleted": pair.String()}, c.deleteTunnel(r.Context(), pair, false)
		}
		if !c.allowed(pair) {
			return nil, httpError{http.StatusForbidden, "not allowed by tunnels.allow"}
		}
		return map[string]string{"added": pair.String()}, c.addTunnel(r.Context(), pair, false)
	})

	srv := &http.Server{
		Addr:              c.cfg.API.Listen,
		Handler:           mux,
		TLSConfig:         c.server,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	c.log.Info("API listening", "address", c.cfg.API.Listen)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }
