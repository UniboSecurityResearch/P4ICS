package ctl

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	p4cfg "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/protobuf/proto"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/p4rt"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/sa"
)

// Operations of the web GUI (internal/gui): the tables read back from the
// switches, entries added and deleted by hand, rotations and tunnels.

// Switch returns the switch called name.
func (c *Controller) Switch(name string) (*Switch, error) {
	for _, sw := range c.switches {
		if sw.Name() == name {
			return sw, nil
		}
	}
	return nil, fmt.Errorf("no switch %q", name)
}

var errRekeyTimeout = errors.New("rotation not done yet")

// Rekey queues a rotation and returns once a rotation has completed, or
// after 20 s.
func (c *Controller) Rekey(ctx context.Context, reason string) error {
	before := c.rotations()
	c.RequestRekey(reason)
	deadline := time.Now().Add(20 * time.Second)
	for c.rotations() == before {
		if time.Now().After(deadline) {
			return errRekeyTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return nil
}

// AddTunnel installs an on-demand tunnel here and on the peer's switches,
// whatever tunnels.allow says (like POST /tunnels).
func (c *Controller) AddTunnel(ctx context.Context, pair Pair) error {
	return c.addTunnel(ctx, pair, true)
}

func (c *Controller) DeleteTunnel(ctx context.Context, pair Pair) error {
	return c.deleteTunnel(ctx, pair, true)
}

// TableView is a table and its entries, for the GUI.
type TableView struct {
	Name string `json:"name"`
	// Why the controller owns the table; empty: entries may be added and
	// deleted by hand.
	Managed string      `json:"managed,omitempty"`
	Size    int64       `json:"size"`
	Keys    []string    `json:"keys"`
	Actions []string    `json:"actions"`
	Entries []EntryView `json:"entries"`
	Error   string      `json:"error,omitempty"`
	params  map[string][]string
}

type EntryView struct {
	p4rt.Description
	// simple_switch_CLI priority (lower wins), for ternary tables.
	Priority int32  `json:"priority,omitempty"`
	Ref      string `json:"ref"` // opaque reference for DeleteEntry
}

// ActionParams: action -> parameter names, for the add-entry form.
func (t TableView) ActionParams() map[string][]string { return t.params }

// managed says why the controller owns a table ("" if it does not).
func (sw *Switch) managed(table string) string {
	switch {
	case table == tableLocal:
		return "sender id, key phase and counter base, set by the controller"
	case table == tableKeys:
		return "keys of the two phases, installed at every rotation (shown by key id)"
	case table == tableSec && sw.ctl.cfg.Tunnels.Mode == config.OnDemand:
		return "on-demand tunnels: add and delete them on the Keys & tunnels page"
	}
	return ""
}

// Tables reads every table of the program. The keys of p4ics_keys are
// replaced by their ids.
func (sw *Switch) Tables(ctx context.Context) ([]TableView, error) {
	rt, p := sw.current()
	if rt == nil || p == nil {
		return nil, errors.New("not connected")
	}
	var out []TableView
	for _, t := range p.info.P.GetTables() {
		name := t.GetPreamble().GetName()
		short := name[strings.LastIndex(name, ".")+1:]
		v := TableView{Name: short, Managed: sw.managed(short), Size: t.GetSize(), params: map[string][]string{}}
		for _, f := range t.GetMatchFields() {
			v.Keys = append(v.Keys, fmt.Sprintf("%s (%s, %d bit)", f.GetName(),
				strings.ToLower(f.GetMatchType().String()), f.GetBitwidth()))
		}
		for _, ref := range t.GetActionRefs() {
			for _, a := range p.info.P.GetActions() {
				if a.GetPreamble().GetId() == ref.GetId() && ref.GetScope() != p4cfg.ActionRef_DEFAULT_ONLY {
					an := a.GetPreamble().GetName()
					an = an[strings.LastIndex(an, ".")+1:]
					v.Actions = append(v.Actions, an)
					v.params[an] = []string{}
					for _, ap := range a.GetParams() {
						v.params[an] = append(v.params[an], fmt.Sprintf("%s (%d bit)", ap.GetName(), ap.GetBitwidth()))
					}
				}
			}
		}
		entries, err := sw.readTable(ctx, t)
		if err != nil {
			v.Error = err.Error()
		}
		for _, te := range entries {
			e := EntryView{Description: p.info.Describe(te), Ref: entryRef(te)}
			if te.GetPriority() > 0 {
				e.Priority = p4rt.PriorityBase - te.GetPriority()
			}
			if short == tableKeys {
				e.Params = nil
				for _, ap := range te.GetAction().GetAction().GetParams() {
					e.Params = append(e.Params, "key id "+keyID(ap.GetValue()))
				}
			}
			v.Entries = append(v.Entries, e)
		}
		// the order of the switch is arbitrary: first the entries that win
		sort.SliceStable(v.Entries, func(i, j int) bool {
			a, b := v.Entries[i], v.Entries[j]
			if a.Priority != b.Priority {
				return a.Priority < b.Priority
			}
			return strings.Join(a.Match, " ") < strings.Join(b.Match, " ")
		})
		out = append(out, v)
	}
	return out, nil
}

// keyID is the id (sa.Key.ID) of a set_key value read from a switch.
func keyID(b []byte) string {
	b = pad(b, 4*sa.Words)
	var k sa.Key
	for i := range k {
		k[i] = binary.BigEndian.Uint32(b[4*i:])
	}
	return k.ID()
}

// readTable returns every entry of a table (not the default one).
func (sw *Switch) readTable(ctx context.Context, table *p4cfg.Table) ([]*p4v1.TableEntry, error) {
	rt, _ := sw.current()
	if rt == nil {
		return nil, errors.New("not connected")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ch := make(chan *p4v1.Entity, 128)
	var out []*p4v1.TableEntry
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range ch {
			if te := e.GetTableEntry(); te != nil && !te.GetIsDefaultAction() {
				out = append(out, te)
			}
		}
	}()
	err := rt.ReadEntityWildcard(ctx, &p4v1.Entity{Entity: &p4v1.Entity_TableEntry{
		TableEntry: &p4v1.TableEntry{TableId: table.GetPreamble().GetId()}}}, ch)
	<-done
	return out, err
}

// AddEntry is a table_add from the GUI. Like the simple_switch_CLI changes
// of the testbed, it lasts until the switch is configured again (switch or
// controller restart): commands.txt stays the reference.
func (sw *Switch) AddEntry(ctx context.Context, table, action string, match, params []string, priority int) error {
	_, p := sw.current()
	if p == nil {
		return errors.New("not connected")
	}
	if why := sw.managed(table); why != "" {
		return fmt.Errorf("%s is managed by the controller: %s", table, why)
	}
	e, err := p.info.Build(table, action, match, params, priority)
	if err != nil {
		return err
	}
	if err := sw.write(ctx, update(p4v1.Update_INSERT, e)); err != nil {
		return err
	}
	sw.log.Info("entry added from the GUI", "table", table, "action", action, "match", match, "params", params)
	return nil
}

// DeleteEntry deletes the entry of ref (from Tables).
func (sw *Switch) DeleteEntry(ctx context.Context, table, ref string) error {
	_, p := sw.current()
	if p == nil {
		return errors.New("not connected")
	}
	if why := sw.managed(table); why != "" {
		return fmt.Errorf("%s is managed by the controller: %s", table, why)
	}
	t, err := p.info.Table(table)
	if err != nil {
		return err
	}
	b, err := base64.RawURLEncoding.DecodeString(ref)
	te := &p4v1.TableEntry{}
	if err != nil || proto.Unmarshal(b, te) != nil {
		return errors.New("bad entry reference")
	}
	if te.GetTableId() != t.GetPreamble().GetId() {
		return errors.New("entry reference of another table")
	}
	d := p.info.Describe(te)
	err = sw.write(ctx, &p4v1.Update{Type: p4v1.Update_DELETE, Entity: &p4v1.Entity{
		Entity: &p4v1.Entity_TableEntry{TableEntry: te}}})
	if err != nil {
		return err
	}
	sw.log.Info("entry deleted from the GUI", "table", table, "match", d.Match)
	return nil
}

// entryRef: the match fields and priority of an entry, which identify it.
func entryRef(te *p4v1.TableEntry) string {
	key := &p4v1.TableEntry{TableId: te.GetTableId(), Match: te.GetMatch(), Priority: te.GetPriority()}
	b, _ := proto.Marshal(key)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Events reads p4ics_events: packets per event name.
func (sw *Switch) Events(ctx context.Context) (map[string]int64, error) {
	return sw.events(ctx)
}
