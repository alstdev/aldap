package ldapfilter

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNotUnder reports a DN that is not within the requested base.
var ErrNotUnder = errors.New("dn is not under base")

// DefaultMaxDNLen is the maximum DN string length accepted by ParseDN.
const DefaultMaxDNLen = 8192

// DN is a parsed distinguished name. RDNs[0] is the leftmost (leaf) RDN;
// the last one is closest to the root. A zero-length DN is the root DSE.
type DN struct {
	RDNs []RDN
}

// RDN is one relative distinguished name: one or more attribute value
// assertions joined with '+'.
type RDN struct {
	AVAs []AVA
}

// AVA is an attribute type and its unescaped value (raw bytes in a
// string; a "#hex" value is decoded).
type AVA struct {
	Type  string
	Value string
}

// ParseDN parses an RFC 4514 string with DefaultMaxDNLen.
//
// Beyond the RFC, unescaped spaces around ',', '+' and '=' are ignored,
// as in "CN=x, OU=y" written by Active Directory tools. The ';' separator
// of RFC 1779 and the old "\<char>" escapes other than those RFC 4514
// lists are rejected.
func ParseDN(s string) (*DN, error) {
	return ParseDNWithLimit(s, DefaultMaxDNLen)
}

// ParseDNWithLimit is ParseDN with an explicit maximum length.
func ParseDNWithLimit(s string, maxLen int) (*DN, error) {
	if maxLen <= 0 {
		maxLen = DefaultMaxDNLen
	}
	if len(s) > maxLen {
		return nil, fmt.Errorf("dn: %d bytes > %d: %w", len(s), maxLen, ErrTooLong)
	}
	dn := &DN{}
	if strings.TrimSpace(s) == "" {
		return dn, nil
	}
	p := &dnParser{s: s}
	for {
		rdn, err := p.rdn()
		if err != nil {
			return nil, err
		}
		dn.RDNs = append(dn.RDNs, rdn)
		p.skipSpaces()
		if p.pos >= len(s) {
			return dn, nil
		}
		if s[p.pos] != ',' {
			return nil, p.errf("expected ',' but found %q", s[p.pos])
		}
		p.pos++
	}
}

type dnParser struct {
	s   string
	pos int
}

func (p *dnParser) errf(format string, args ...any) error {
	return fmt.Errorf("dn: at %d: %s: %w", p.pos, fmt.Sprintf(format, args...), ErrSyntax)
}

func (p *dnParser) skipSpaces() {
	for p.pos < len(p.s) && p.s[p.pos] == ' ' {
		p.pos++
	}
}

// rdn = ava *("+" ava)
func (p *dnParser) rdn() (RDN, error) {
	var rdn RDN
	for {
		ava, err := p.ava()
		if err != nil {
			return RDN{}, err
		}
		rdn.AVAs = append(rdn.AVAs, ava)
		p.skipSpaces()
		if p.pos < len(p.s) && p.s[p.pos] == '+' {
			p.pos++
			continue
		}
		return rdn, nil
	}
}

// ava = attributeType "=" attributeValue
func (p *dnParser) ava() (AVA, error) {
	p.skipSpaces()
	start := p.pos
	for p.pos < len(p.s) && isAttrChar(p.s[p.pos]) && p.s[p.pos] != ';' {
		p.pos++
	}
	typ := p.s[start:p.pos]
	if !validOID(typ) {
		if typ == "" {
			return AVA{}, p.errf("expected attribute type")
		}
		return AVA{}, p.errf("invalid attribute type %q", typ)
	}
	p.skipSpaces()
	if p.pos >= len(p.s) || p.s[p.pos] != '=' {
		return AVA{}, p.errf("expected '=' after %q", typ)
	}
	p.pos++
	p.skipSpaces()
	if p.pos < len(p.s) && p.s[p.pos] == '#' {
		v, err := p.hexValue()
		return AVA{Type: typ, Value: v}, err
	}
	v, err := p.stringValue()
	return AVA{Type: typ, Value: v}, err
}

// hexValue = "#" 1*(HEX HEX)
func (p *dnParser) hexValue() (string, error) {
	p.pos++ // '#'
	var b strings.Builder
	for p.pos+1 < len(p.s) {
		v, ok := hexByte(p.s[p.pos], p.s[p.pos+1])
		if !ok {
			break
		}
		b.WriteByte(v)
		p.pos += 2
	}
	if b.Len() == 0 {
		return "", p.errf("empty #hex value")
	}
	if p.pos < len(p.s) && isHex(p.s[p.pos]) {
		return "", p.errf("odd number of hex digits in #hex value")
	}
	return b.String(), nil
}

// stringValue reads up to an unescaped ',' or '+', dropping trailing
// unescaped spaces.
func (p *dnParser) stringValue() (string, error) {
	var b strings.Builder
	trailing := 0 // unescaped spaces not yet committed
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch c {
		case ',', '+':
			return b.String(), nil
		case ';', '"', '<', '>', 0:
			return "", p.errf("unescaped %q in value", c)
		case ' ':
			trailing++
			p.pos++
			continue
		case '\\':
			if p.pos+1 >= len(p.s) {
				return "", p.errf("truncated escape")
			}
			n := p.s[p.pos+1]
			switch {
			case strings.IndexByte(` "#+,;<=>\`, n) >= 0:
				b.WriteString(strings.Repeat(" ", trailing))
				trailing = 0
				b.WriteByte(n)
				p.pos += 2
			case p.pos+2 < len(p.s) && isHex(n) && isHex(p.s[p.pos+2]):
				v, _ := hexByte(n, p.s[p.pos+2])
				b.WriteString(strings.Repeat(" ", trailing))
				trailing = 0
				b.WriteByte(v)
				p.pos += 3
			default:
				return "", p.errf("invalid escape %q", p.s[p.pos:min(p.pos+3, len(p.s))])
			}
		default:
			b.WriteString(strings.Repeat(" ", trailing))
			trailing = 0
			b.WriteByte(c)
			p.pos++
		}
	}
	return b.String(), nil
}

// ---- rendering --------------------------------------------------------------

// String renders the DN in RFC 4514 syntax: types lower-cased, values
// escaped canonically, AVAs of a multi-valued RDN sorted by type.
func (d *DN) String() string {
	if d == nil {
		return ""
	}
	parts := make([]string, len(d.RDNs))
	for i, r := range d.RDNs {
		parts[i] = r.String()
	}
	return strings.Join(parts, ",")
}

// String renders one RDN with lower-cased types and sorted AVAs.
func (r RDN) String() string {
	avas := append([]AVA(nil), r.AVAs...)
	sort.SliceStable(avas, func(i, j int) bool {
		ti, tj := strings.ToLower(avas[i].Type), strings.ToLower(avas[j].Type)
		return ti < tj || ti == tj && avas[i].Value < avas[j].Value
	})
	parts := make([]string, len(avas))
	for i, a := range avas {
		parts[i] = strings.ToLower(a.Type) + "=" + EscapeRDNValue(a.Value)
	}
	return strings.Join(parts, "+")
}

// EscapeRDNValue escapes an attribute value for use in a DN string
// (RFC 4514 §2.4): '"', '+', ',', ';', '<', '>', '\' and NUL anywhere, '#'
// or a space at the start and a space at the end are escaped with '\';
// other control bytes are written as \XX. An empty value stays empty.
func EscapeRDNValue(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 4)
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == 0 || c < 0x20 || c == 0x7f:
			b.WriteByte('\\')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		case strings.IndexByte(`"+,;<>\`, c) >= 0,
			c == '#' && i == 0,
			c == ' ' && (i == 0 || i == len(v)-1):
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ---- operations -------------------------------------------------------------

// Clone returns a deep copy.
func (d *DN) Clone() *DN {
	if d == nil {
		return nil
	}
	c := &DN{RDNs: make([]RDN, len(d.RDNs))}
	for i, r := range d.RDNs {
		c.RDNs[i] = RDN{AVAs: append([]AVA(nil), r.AVAs...)}
	}
	return c
}

// Depth is the number of RDNs.
func (d *DN) Depth() int {
	if d == nil {
		return 0
	}
	return len(d.RDNs)
}

// RDN returns the leftmost RDN, or an empty RDN for the root.
func (d *DN) RDN() RDN {
	if d == nil || len(d.RDNs) == 0 {
		return RDN{}
	}
	return d.RDNs[0]
}

// Parent returns the DN without its leftmost RDN; the root's parent is the
// root.
func (d *DN) Parent() *DN {
	if d == nil || len(d.RDNs) == 0 {
		return &DN{}
	}
	return &DN{RDNs: d.Clone().rdns()[1:]}
}

// Child returns rdn + "," + d.
func (d *DN) Child(rdn RDN) *DN {
	c := d.Clone()
	if c == nil {
		c = &DN{}
	}
	c.RDNs = append([]RDN{{AVAs: append([]AVA(nil), rdn.AVAs...)}}, c.RDNs...)
	return c
}

// Equal compares two DNs RDN by RDN. Types compare case-insensitively;
// values compare case-insensitively with surrounding white space ignored
// and internal runs of spaces folded (caseIgnoreMatch, RFC 4518), which is
// what the attribute types used in DNs (cn, ou, dc, o, uid, ...) use.
func (d *DN) Equal(o *DN) bool {
	if d == nil || o == nil {
		return d.Depth() == 0 && o.Depth() == 0
	}
	if len(d.RDNs) != len(o.RDNs) {
		return false
	}
	for i := range d.RDNs {
		if !d.RDNs[i].Equal(o.RDNs[i]) {
			return false
		}
	}
	return true
}

// Equal compares two RDNs regardless of AVA order.
func (r RDN) Equal(o RDN) bool {
	if len(r.AVAs) != len(o.AVAs) {
		return false
	}
	return r.String() == o.String() || r.canon() == o.canon()
}

func (r RDN) canon() string {
	keys := make([]string, len(r.AVAs))
	for i, a := range r.AVAs {
		keys[i] = strings.ToLower(a.Type) + "=" + canonValue(a.Value)
	}
	sort.Strings(keys)
	return strings.Join(keys, "+")
}

// canonValue folds a value for caseIgnoreMatch comparison.
func canonValue(v string) string {
	return strings.ToLower(strings.Join(strings.Fields(v), " "))
}

// Canonical returns a lower-cased, space-folded key suitable for map
// lookups and rate-limit keys; equal DNs have equal Canonical strings.
func (d *DN) Canonical() string {
	if d == nil {
		return ""
	}
	parts := make([]string, len(d.RDNs))
	for i, r := range d.RDNs {
		parts[i] = r.canon()
	}
	return strings.Join(parts, ",")
}

// IsUnder reports whether d equals base or lies below it. Every DN is
// under the root (an empty base).
func (d *DN) IsUnder(base *DN) bool {
	n := base.Depth()
	if d.Depth() < n {
		return false
	}
	if n == 0 {
		return true
	}
	suffix := &DN{RDNs: d.RDNs[len(d.RDNs)-n:]}
	return suffix.Equal(base)
}

// Rewrite replaces the oldBase suffix of d with newBase, keeping the RDNs
// above it; it fails with ErrNotUnder when d is not under oldBase. d is
// not modified.
func (d *DN) Rewrite(oldBase, newBase *DN) (*DN, error) {
	if !d.IsUnder(oldBase) {
		return nil, fmt.Errorf("rewrite %q under %q: %w", d, oldBase, ErrNotUnder)
	}
	keep := d.Clone().rdns()[:d.Depth()-oldBase.Depth()]
	return &DN{RDNs: append(keep, newBase.Clone().rdns()...)}, nil
}

// rdns is d.RDNs that tolerates a nil receiver.
func (d *DN) rdns() []RDN {
	if d == nil {
		return nil
	}
	return d.RDNs
}
