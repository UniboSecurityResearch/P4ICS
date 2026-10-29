// Package p4rt turns the P4ICS switch configuration into P4Runtime entities:
// P4Info names resolved like simple_switch_CLI resolves them, and
// simple_switch_CLI table commands (the switches' commands.txt) translated
// into table entries. The controller therefore installs the same tables as
// the CLI mode of the testbed.
package p4rt

import (
	"bufio"
	"bytes"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	p4cfg "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/protobuf/encoding/prototext"
)

// PriorityBase converts simple_switch_CLI priorities (lower wins) into
// P4Runtime priorities (higher wins): P4Runtime = PriorityBase - CLI.
const PriorityBase = 1 << 16

// Info is a P4Info with name lookups.
type Info struct {
	P *p4cfg.P4Info
}

// ParseInfo reads a P4Info in protobuf text format (p4c --p4runtime-files x.txtpb).
// Fields newer than the P4Runtime protos of the client library (such as
// initial_default_action) are informational and skipped.
func ParseInfo(text []byte) (*Info, error) {
	p := &p4cfg.P4Info{}
	if err := (prototext.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(text, p); err != nil {
		return nil, fmt.Errorf("P4Info: %w", err)
	}
	return &Info{P: p}, nil
}

type named interface {
	GetPreamble() *p4cfg.Preamble
}

// find matches the full name ("MyIngress.ics_sec"), else the alias or a
// unique suffix ("ics_sec"), as simple_switch_CLI does.
func find[T named](items []T, kind, name string) (T, error) {
	var found []T
	for _, it := range items {
		p := it.GetPreamble()
		if p.GetName() == name {
			return it, nil
		}
		if p.GetAlias() == name || strings.HasSuffix(p.GetName(), "."+name) {
			found = append(found, it)
		}
	}
	var zero T
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return zero, fmt.Errorf("no %s %q in the P4Info", kind, name)
	default:
		return zero, fmt.Errorf("%s %q is ambiguous", kind, name)
	}
}

func (i *Info) Table(name string) (*p4cfg.Table, error) {
	return find(i.P.GetTables(), "table", name)
}

func (i *Info) Action(name string) (*p4cfg.Action, error) {
	return find(i.P.GetActions(), "action", name)
}

func (i *Info) Counter(name string) (*p4cfg.Counter, error) {
	return find(i.P.GetCounters(), "counter", name)
}

func (i *Info) Digest(name string) (*p4cfg.Digest, error) {
	return find(i.P.GetDigests(), "digest", name)
}

// Entry is a table entry, or a table's default entry.
type Entry struct {
	Table   *p4cfg.Table
	Action  *p4cfg.Action
	Default bool
	// The simple_switch_CLI tokens it was built from.
	MatchTokens, ParamTokens []string

	match    []*p4v1.FieldMatch
	params   [][]byte
	priority int32
}

// TableName is the short name of the entry's table ("ics_sec").
func (e *Entry) TableName() string { return short(e.Table.GetPreamble()) }

// ActionName is the short name of the entry's action ("cipher").
func (e *Entry) ActionName() string { return short(e.Action.GetPreamble()) }

func short(p *p4cfg.Preamble) string {
	n := p.GetName()
	return n[strings.LastIndex(n, ".")+1:]
}

// Param returns the CLI token of the action parameter called name.
func (e *Entry) Param(name string) (string, bool) {
	for i, p := range e.Action.GetParams() {
		if p.GetName() == name && i < len(e.ParamTokens) {
			return e.ParamTokens[i], true
		}
	}
	return "", false
}

// TableEntry is the P4Runtime form of the entry.
func (e *Entry) TableEntry() *p4v1.TableEntry {
	action := &p4v1.Action{ActionId: e.Action.GetPreamble().GetId()}
	for i, v := range e.params {
		action.Params = append(action.Params, &p4v1.Action_Param{
			ParamId: e.Action.GetParams()[i].GetId(),
			Value:   v,
		})
	}
	return &p4v1.TableEntry{
		TableId:         e.Table.GetPreamble().GetId(),
		Match:           e.match,
		Priority:        e.priority,
		IsDefaultAction: e.Default,
		Action:          &p4v1.TableAction{Type: &p4v1.TableAction_Action{Action: action}},
	}
}

// Build makes an entry from the tokens of
//
//	table_add <table> <action> <match...> => <params...> [<priority>]
//
// cliPriority is used only by tables with ternary, range or optional fields.
func (i *Info) Build(table, action string, match, params []string, cliPriority int) (*Entry, error) {
	e, err := i.newEntry(table, action, params)
	if err != nil {
		return nil, err
	}
	fields := e.Table.GetMatchFields()
	if len(match) != len(fields) {
		return nil, fmt.Errorf("table %s: %d match fields, got %d", table, len(fields), len(match))
	}
	needsPriority := false
	for n, f := range fields {
		fm, prio, err := fieldMatch(f, match[n])
		if err != nil {
			return nil, fmt.Errorf("table %s, field %s: %w", table, f.GetName(), err)
		}
		needsPriority = needsPriority || prio
		if fm != nil {
			e.match = append(e.match, fm)
		}
	}
	if needsPriority {
		if cliPriority < 0 || cliPriority >= PriorityBase {
			return nil, fmt.Errorf("table %s: priority must be in 0..%d", table, PriorityBase-1)
		}
		e.priority = int32(PriorityBase - cliPriority)
	}
	e.MatchTokens = match
	return e, nil
}

// BuildDefault makes the default entry of
//
//	table_set_default <table> <action> <params...>
func (i *Info) BuildDefault(table, action string, params []string) (*Entry, error) {
	e, err := i.newEntry(table, action, params)
	if err != nil {
		return nil, err
	}
	e.Default = true
	return e, nil
}

func (i *Info) newEntry(table, action string, params []string) (*Entry, error) {
	t, err := i.Table(table)
	if err != nil {
		return nil, err
	}
	a, err := i.Action(action)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, ref := range t.GetActionRefs() {
		allowed = allowed || ref.GetId() == a.GetPreamble().GetId()
	}
	if !allowed {
		return nil, fmt.Errorf("action %s is not an action of table %s", action, table)
	}
	if len(params) != len(a.GetParams()) {
		return nil, fmt.Errorf("action %s takes %d parameters, got %d", action, len(a.GetParams()), len(params))
	}
	e := &Entry{Table: t, Action: a, ParamTokens: params}
	for n, p := range a.GetParams() {
		v, err := Bytes(params[n], p.GetBitwidth())
		if err != nil {
			return nil, fmt.Errorf("action %s, parameter %s: %w", action, p.GetName(), err)
		}
		e.params = append(e.params, v)
	}
	return e, nil
}

// fieldMatch returns nil for a don't-care field (P4Runtime omits it) and
// whether the match kind needs a priority.
func fieldMatch(f *p4cfg.MatchField, tok string) (*p4v1.FieldMatch, bool, error) {
	bw := f.GetBitwidth()
	fm := &p4v1.FieldMatch{FieldId: f.GetId()}
	switch f.GetMatchType() {
	case p4cfg.MatchField_EXACT:
		v, err := Bytes(tok, bw)
		if err != nil {
			return nil, false, err
		}
		fm.FieldMatchType = &p4v1.FieldMatch_Exact_{Exact: &p4v1.FieldMatch_Exact{Value: v}}
		return fm, false, nil
	case p4cfg.MatchField_LPM:
		addr, plen, ok := strings.Cut(tok, "/")
		if !ok {
			return nil, false, fmt.Errorf("%q: expected <value>/<prefix length>", tok)
		}
		n, err := strconv.Atoi(plen)
		if err != nil || n < 0 || n > int(bw) {
			return nil, false, fmt.Errorf("%q: bad prefix length", tok)
		}
		if n == 0 {
			return nil, false, nil
		}
		v, err := value(addr, bw)
		if err != nil {
			return nil, false, err
		}
		v.And(v, prefixMask(n, bw))
		fm.FieldMatchType = &p4v1.FieldMatch_Lpm{Lpm: &p4v1.FieldMatch_LPM{
			Value: canonical(v), PrefixLen: int32(n)}}
		return fm, false, nil
	case p4cfg.MatchField_TERNARY:
		vs, ms, ok := strings.Cut(tok, "&&&")
		v, err := value(vs, bw)
		if err != nil {
			return nil, true, err
		}
		m := prefixMask(int(bw), bw)
		if ok {
			if m, err = value(ms, bw); err != nil {
				return nil, true, err
			}
		}
		if m.Sign() == 0 {
			return nil, true, nil
		}
		v.And(v, m)
		fm.FieldMatchType = &p4v1.FieldMatch_Ternary_{Ternary: &p4v1.FieldMatch_Ternary{
			Value: canonical(v), Mask: canonical(m)}}
		return fm, true, nil
	case p4cfg.MatchField_OPTIONAL:
		v, err := Bytes(tok, bw)
		if err != nil {
			return nil, true, err
		}
		fm.FieldMatchType = &p4v1.FieldMatch_Optional_{Optional: &p4v1.FieldMatch_Optional{Value: v}}
		return fm, true, nil
	default:
		return nil, false, fmt.Errorf("match kind %s is not supported", f.GetMatchType())
	}
}

// Bytes encodes a simple_switch_CLI value (decimal, 0x hexadecimal, IPv4 or
// MAC address) of bitwidth bits as a canonical P4Runtime bytestring.
func Bytes(tok string, bitwidth int32) ([]byte, error) {
	v, err := value(tok, bitwidth)
	if err != nil {
		return nil, err
	}
	return canonical(v), nil
}

func value(tok string, bitwidth int32) (*big.Int, error) {
	v := new(big.Int)
	switch {
	case strings.Count(tok, ".") == 3:
		ip := net.ParseIP(tok).To4()
		if ip == nil {
			return nil, fmt.Errorf("%q: bad IPv4 address", tok)
		}
		v.SetBytes(ip)
	case strings.Count(tok, ":") == 5:
		mac, err := net.ParseMAC(tok)
		if err != nil {
			return nil, fmt.Errorf("%q: bad MAC address", tok)
		}
		v.SetBytes(mac)
	case strings.HasPrefix(tok, "0x") || strings.HasPrefix(tok, "0X"):
		if _, ok := v.SetString(tok[2:], 16); !ok {
			return nil, fmt.Errorf("%q: bad hexadecimal number", tok)
		}
	default:
		if _, ok := v.SetString(tok, 10); !ok {
			return nil, fmt.Errorf("%q: bad number", tok)
		}
	}
	if v.Sign() < 0 || v.BitLen() > int(bitwidth) {
		return nil, fmt.Errorf("%q does not fit in %d bits", tok, bitwidth)
	}
	return v, nil
}

// prefixMask has the n most significant of bitwidth bits set.
func prefixMask(n int, bitwidth int32) *big.Int {
	m := new(big.Int).Lsh(big.NewInt(1), uint(n))
	m.Sub(m, big.NewInt(1))
	return m.Lsh(m, uint(int(bitwidth)-n))
}

// canonical: no leading zero bytes, at least one byte.
func canonical(v *big.Int) []byte {
	if v.Sign() == 0 {
		return []byte{0}
	}
	return v.Bytes()
}

// ParseCommands translates the table commands of a simple_switch_CLI file:
// table_add and table_set_default. Empty lines and # comments are skipped,
// EOF (the CLI's exit command) ends the file; any other command is an error.
func (i *Info) ParseCommands(text []byte) ([]*Entry, error) {
	var entries []*Entry
	sc := bufio.NewScanner(bytes.NewReader(text))
	for line := 1; sc.Scan(); line++ {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if f[0] == "EOF" {
			break
		}
		e, err := i.command(f)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

func (i *Info) command(f []string) (*Entry, error) {
	switch f[0] {
	case "table_set_default":
		if len(f) < 3 {
			return nil, fmt.Errorf("usage: table_set_default <table> <action> <params...>")
		}
		return i.BuildDefault(f[1], f[2], f[3:])
	case "table_add":
		sep := -1
		for n, tok := range f {
			if tok == "=>" {
				sep = n
				break
			}
		}
		if len(f) < 3 || sep < 3 {
			return nil, fmt.Errorf("usage: table_add <table> <action> <match...> => <params...> [<priority>]")
		}
		a, err := i.Action(f[2])
		if err != nil {
			return nil, err
		}
		params, prio := f[sep+1:], 0
		if len(params) == len(a.GetParams())+1 {
			if prio, err = strconv.Atoi(params[len(params)-1]); err != nil {
				return nil, fmt.Errorf("bad priority %q", params[len(params)-1])
			}
			params = params[:len(params)-1]
		}
		return i.Build(f[1], f[2], f[3:sep], params, prio)
	default:
		return nil, fmt.Errorf("unsupported command %q", f[0])
	}
}

// Description is a table entry read back from a switch, in CLI notation:
// ternary fields are value&&&mask and LPM fields value/prefix length.
// Addresses (32- and 48-bit fields and parameters whose name ends in Addr)
// are IPv4 or MAC addresses, other values hexadecimal (0x...).
type Description struct {
	Table   string   `json:"table"`
	Action  string   `json:"action"`
	Match   []string `json:"match"`
	Params  []string `json:"params"`
	Default bool     `json:"default,omitempty"`
}

// Describe translates an entry read from the switch.
func (i *Info) Describe(te *p4v1.TableEntry) Description {
	d := Description{Default: te.GetIsDefaultAction()}
	var table *p4cfg.Table
	for _, t := range i.P.GetTables() {
		if t.GetPreamble().GetId() == te.GetTableId() {
			table = t
			d.Table = short(t.GetPreamble())
		}
	}
	if table != nil {
		for _, f := range table.GetMatchFields() {
			tok := "*"
			for _, m := range te.GetMatch() {
				if m.GetFieldId() != f.GetId() {
					continue
				}
				str := func(v []byte) string { return format(v, f.GetBitwidth(), f.GetName()) }
				switch {
				case m.GetExact() != nil:
					tok = str(m.GetExact().GetValue())
				case m.GetLpm() != nil:
					tok = fmt.Sprintf("%s/%d", str(m.GetLpm().GetValue()), m.GetLpm().GetPrefixLen())
				case m.GetTernary() != nil:
					tok = str(m.GetTernary().GetValue()) + "&&&" + str(m.GetTernary().GetMask())
				case m.GetOptional() != nil:
					tok = str(m.GetOptional().GetValue())
				}
			}
			d.Match = append(d.Match, tok)
		}
	}
	if a := te.GetAction().GetAction(); a != nil {
		var action *p4cfg.Action
		for _, act := range i.P.GetActions() {
			if act.GetPreamble().GetId() == a.GetActionId() {
				action = act
				d.Action = short(act.GetPreamble())
			}
		}
		for _, p := range a.GetParams() {
			var bw int32
			var name string
			for _, ap := range action.GetParams() {
				if ap.GetId() == p.GetParamId() {
					bw, name = ap.GetBitwidth(), ap.GetName()
				}
			}
			d.Params = append(d.Params, format(p.GetValue(), bw, name))
		}
	}
	return d
}

// format writes a value read from the switch as a simple_switch_CLI token.
func format(b []byte, bitwidth int32, name string) string {
	v := new(big.Int).SetBytes(b)
	if strings.HasSuffix(strings.ToLower(name), "addr") && v.BitLen() <= int(bitwidth) {
		switch bitwidth {
		case 32:
			return net.IP(v.FillBytes(make([]byte, 4))).String()
		case 48:
			return net.HardwareAddr(v.FillBytes(make([]byte, 6))).String()
		}
	}
	return "0x" + v.Text(16)
}
