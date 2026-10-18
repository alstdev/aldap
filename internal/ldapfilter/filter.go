package ldapfilter

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Sentinel errors, matched with errors.Is.
var (
	// ErrSyntax reports malformed filter or DN text.
	ErrSyntax = errors.New("syntax error")
	// ErrTooDeep reports nesting beyond Limits.MaxDepth.
	ErrTooDeep = errors.New("filter too deep")
	// ErrTooLong reports input longer than the allowed length.
	ErrTooLong = errors.New("input too long")
)

// Kind is the type of a filter node (RFC 4511 §4.5.1.7).
type Kind uint8

// Filter node kinds.
const (
	And Kind = iota
	Or
	Not
	Equality
	Substring
	GreaterOrEqual
	LessOrEqual
	Present
	Approx
	Extensible
)

// String returns the kind name for diagnostics.
func (k Kind) String() string {
	names := [...]string{"and", "or", "not", "equality", "substring", "greaterOrEqual", "lessOrEqual", "present", "approx", "extensible"}
	if int(k) < len(names) {
		return names[k]
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Filter is one node of an LDAP search filter AST. Values are stored
// unescaped (raw bytes in a string); String re-escapes them.
type Filter struct {
	Kind Kind
	// Attr is the attribute description. Empty only for an Extensible
	// match of the form (:rule:=value).
	Attr string
	// Value is the assertion value of Equality, GreaterOrEqual,
	// LessOrEqual, Approx and Extensible nodes.
	Value string
	// Initial, Any and Final hold the pieces of a Substring node.
	Initial string
	Any     []string
	Final   string
	// MatchingRule and DNAttributes belong to Extensible nodes.
	MatchingRule string
	DNAttributes bool
	// Children of And and Or (any number, RFC 4526 allows zero) and Not
	// (exactly one).
	Children []*Filter
}

// Limits bounds the parser. The zero value means the defaults.
type Limits struct {
	// MaxDepth is the maximum nesting of and/or/not; default 20, hard
	// cap HardMaxDepth.
	MaxDepth int
	// MaxLen is the maximum input length in bytes; default 4096.
	MaxLen int
}

// Default and hard limits (SPEC §3.4 limits.*, §9).
const (
	DefaultMaxDepth = 20
	DefaultMaxLen   = 4096
	HardMaxDepth    = 64
)

func (l Limits) withDefaults() Limits {
	if l.MaxDepth <= 0 || l.MaxDepth > HardMaxDepth {
		l.MaxDepth = min(max(l.MaxDepth, DefaultMaxDepth), HardMaxDepth)
	}
	if l.MaxLen <= 0 {
		l.MaxLen = DefaultMaxLen
	}
	return l
}

// Parse parses an RFC 4515 filter string with the default Limits.
func Parse(s string) (*Filter, error) {
	return ParseWithLimits(s, Limits{})
}

// ParseWithLimits parses an RFC 4515 filter string. The outer parentheses
// are required. Returned errors wrap ErrSyntax, ErrTooDeep or ErrTooLong.
func ParseWithLimits(s string, lim Limits) (*Filter, error) {
	lim = lim.withDefaults()
	if len(s) > lim.MaxLen {
		return nil, fmt.Errorf("filter: %d bytes > %d: %w", len(s), lim.MaxLen, ErrTooLong)
	}
	p := &parser{s: s, lim: lim}
	f, err := p.filter(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(s) {
		return nil, p.errf("trailing data after filter")
	}
	return f, nil
}

type parser struct {
	s   string
	pos int
	lim Limits
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("filter: at %d: %s: %w", p.pos, fmt.Sprintf(format, args...), ErrSyntax)
}

func (p *parser) eof() bool { return p.pos >= len(p.s) }

func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.pos]
}

// filter = LPAREN filtercomp RPAREN
func (p *parser) filter(depth int) (*Filter, error) {
	if p.peek() != '(' {
		if p.eof() {
			return nil, p.errf("expected '('")
		}
		return nil, p.errf("expected '(' but found %q", p.peek())
	}
	p.pos++
	var f *Filter
	var err error
	switch p.peek() {
	case '&':
		p.pos++
		f, err = p.set(And, depth)
	case '|':
		p.pos++
		f, err = p.set(Or, depth)
	case '!':
		p.pos++
		if depth+1 > p.lim.MaxDepth {
			return nil, fmt.Errorf("filter: nesting > %d: %w", p.lim.MaxDepth, ErrTooDeep)
		}
		var child *Filter
		child, err = p.filter(depth + 1)
		if err == nil {
			f = &Filter{Kind: Not, Children: []*Filter{child}}
		}
	default:
		f, err = p.item()
	}
	if err != nil {
		return nil, err
	}
	if p.peek() != ')' {
		return nil, p.errf("expected ')'")
	}
	p.pos++
	return f, nil
}

// set parses the filterlist of an and/or; zero members are allowed (RFC 4526).
func (p *parser) set(kind Kind, depth int) (*Filter, error) {
	if depth+1 > p.lim.MaxDepth {
		return nil, fmt.Errorf("filter: nesting > %d: %w", p.lim.MaxDepth, ErrTooDeep)
	}
	f := &Filter{Kind: kind}
	for p.peek() == '(' {
		child, err := p.filter(depth + 1)
		if err != nil {
			return nil, err
		}
		f.Children = append(f.Children, child)
	}
	return f, nil
}

// item = simple / present / substring / extensible
func (p *parser) item() (*Filter, error) {
	attr := p.attr()
	switch p.peek() {
	case ':':
		return p.extensible(attr)
	case '=':
		if attr == "" {
			return nil, p.errf("missing attribute description")
		}
		p.pos++
		return p.equalityLike(attr)
	case '~', '>', '<':
		if attr == "" {
			return nil, p.errf("missing attribute description")
		}
		kinds := map[byte]Kind{'~': Approx, '>': GreaterOrEqual, '<': LessOrEqual}
		kind := kinds[p.peek()]
		p.pos++
		if p.peek() != '=' {
			return nil, p.errf("expected '='")
		}
		p.pos++
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		return &Filter{Kind: kind, Attr: attr, Value: v}, nil
	default:
		if attr == "" {
			return nil, p.errf("missing attribute description")
		}
		return nil, p.errf("expected filter operator")
	}
}

// attr = attributedescription (RFC 4512 §2.5): descr or numericoid, then
// ";option" parts. Returns "" when no attribute is present.
func (p *parser) attr() string {
	start := p.pos
	for !p.eof() && isAttrChar(p.s[p.pos]) {
		p.pos++
	}
	return p.s[start:p.pos]
}

func isAttrChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == ';'
}

// validAttr checks an attribute description: a keystring (ALPHA then
// ALPHA/DIGIT/HYPHEN) or a numeric OID, optionally followed by ";option"s.
func validAttr(a string) bool {
	parts := strings.Split(a, ";")
	if !validOID(parts[0]) {
		return false
	}
	for _, opt := range parts[1:] {
		if !validKeystring(opt) {
			return false
		}
	}
	return true
}

// validOID accepts a keystring (descr) or a numericoid such as 2.5.4.3.
func validOID(s string) bool {
	if s == "" {
		return false
	}
	if s[0] >= '0' && s[0] <= '9' {
		for _, arc := range strings.Split(s, ".") {
			if arc == "" || (len(arc) > 1 && arc[0] == '0') {
				return false
			}
			for i := 0; i < len(arc); i++ {
				if arc[i] < '0' || arc[i] > '9' {
					return false
				}
			}
		}
		return true
	}
	return validKeystring(s)
}

func validKeystring(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// equalityLike parses what follows "attr=": present, substring or equality.
func (p *parser) equalityLike(attr string) (*Filter, error) {
	if !validAttr(attr) {
		return nil, p.errf("invalid attribute description %q", attr)
	}
	var pieces []string
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		pieces = append(pieces, v)
		if p.peek() != '*' {
			break
		}
		p.pos++
	}
	if len(pieces) == 1 {
		return &Filter{Kind: Equality, Attr: attr, Value: pieces[0]}, nil
	}
	if len(pieces) == 2 && pieces[0] == "" && pieces[1] == "" {
		return &Filter{Kind: Present, Attr: attr}, nil
	}
	f := &Filter{Kind: Substring, Attr: attr, Initial: pieces[0], Final: pieces[len(pieces)-1]}
	for _, mid := range pieces[1 : len(pieces)-1] {
		if mid == "" {
			return nil, p.errf("empty substring between '*'")
		}
		f.Any = append(f.Any, mid)
	}
	return f, nil
}

// extensible = [attr] [":dn"] [":" matchingrule] ":=" value
func (p *parser) extensible(attr string) (*Filter, error) {
	if attr != "" && !validAttr(attr) {
		return nil, p.errf("invalid attribute description %q", attr)
	}
	f := &Filter{Kind: Extensible, Attr: attr}
	for p.peek() == ':' {
		p.pos++
		if p.peek() == '=' {
			p.pos++
			if attr == "" && f.MatchingRule == "" {
				return nil, p.errf("extensible match needs an attribute or a matching rule")
			}
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			f.Value = v
			return f, nil
		}
		tok := p.attr()
		switch {
		case tok == "":
			return nil, p.errf("expected 'dn', matching rule or '='")
		case strings.EqualFold(tok, "dn") && !f.DNAttributes && f.MatchingRule == "":
			f.DNAttributes = true
		case f.MatchingRule == "" && validOID(tok):
			f.MatchingRule = tok
		default:
			return nil, p.errf("unexpected %q in extensible match", tok)
		}
	}
	return nil, p.errf("expected ':=' in extensible match")
}

// value = *(normal / escaped); stops at '*', '(' or ')'.
func (p *parser) value() (string, error) {
	var b strings.Builder
	for !p.eof() {
		c := p.s[p.pos]
		switch c {
		case '*', '(', ')':
			return b.String(), nil
		case 0:
			return "", p.errf("NUL in value")
		case '\\':
			if p.pos+2 >= len(p.s) {
				return "", p.errf("truncated escape")
			}
			v, ok := hexByte(p.s[p.pos+1], p.s[p.pos+2])
			if !ok {
				return "", p.errf("invalid escape %q", p.s[p.pos:p.pos+3])
			}
			b.WriteByte(v)
			p.pos += 3
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return b.String(), nil
}

// unhex returns the value of one hex digit and whether c is one.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hexByte decodes two hex digits.
func hexByte(hi, lo byte) (byte, bool) {
	h, ok1 := unhex(hi)
	l, ok2 := unhex(lo)
	return h<<4 | l, ok1 && ok2
}

func isHex(c byte) bool {
	_, ok := unhex(c)
	return ok
}

// ---- serialization --------------------------------------------------------

// String renders the filter in RFC 4515 syntax with canonical escaping.
func (f *Filter) String() string {
	var b strings.Builder
	f.write(&b)
	return b.String()
}

func (f *Filter) write(b *strings.Builder) {
	if f == nil {
		return
	}
	b.WriteByte('(')
	switch f.Kind {
	case And, Or:
		if f.Kind == And {
			b.WriteByte('&')
		} else {
			b.WriteByte('|')
		}
		for _, c := range f.Children {
			c.write(b)
		}
	case Not:
		b.WriteByte('!')
		if len(f.Children) > 0 {
			f.Children[0].write(b)
		}
	case Equality:
		b.WriteString(f.Attr + "=" + EscapeValue(f.Value))
	case Approx:
		b.WriteString(f.Attr + "~=" + EscapeValue(f.Value))
	case GreaterOrEqual:
		b.WriteString(f.Attr + ">=" + EscapeValue(f.Value))
	case LessOrEqual:
		b.WriteString(f.Attr + "<=" + EscapeValue(f.Value))
	case Present:
		b.WriteString(f.Attr + "=*")
	case Substring:
		b.WriteString(f.Attr + "=" + EscapeValue(f.Initial))
		for _, a := range f.Any {
			b.WriteString("*" + EscapeValue(a))
		}
		b.WriteString("*" + EscapeValue(f.Final))
	case Extensible:
		b.WriteString(f.Attr)
		if f.DNAttributes {
			b.WriteString(":dn")
		}
		if f.MatchingRule != "" {
			b.WriteString(":" + f.MatchingRule)
		}
		b.WriteString(":=" + EscapeValue(f.Value))
	}
	b.WriteByte(')')
}

// Clone returns a deep copy.
func (f *Filter) Clone() *Filter {
	if f == nil {
		return nil
	}
	c := *f
	if f.Any != nil {
		c.Any = append([]string(nil), f.Any...)
	}
	if f.Children != nil {
		c.Children = make([]*Filter, len(f.Children))
		for i, ch := range f.Children {
			c.Children[i] = ch.Clone()
		}
	}
	return &c
}

// Equal reports structural equality (same kinds, attributes, values and
// child order). Normalize both sides first for a semantic comparison.
func (f *Filter) Equal(g *Filter) bool {
	if f == nil || g == nil {
		return f == g
	}
	if f.Kind != g.Kind || f.Attr != g.Attr || f.Value != g.Value || f.Initial != g.Initial ||
		f.Final != g.Final || f.MatchingRule != g.MatchingRule || f.DNAttributes != g.DNAttributes ||
		len(f.Any) != len(g.Any) || len(f.Children) != len(g.Children) {
		return false
	}
	for i := range f.Any {
		if f.Any[i] != g.Any[i] {
			return false
		}
	}
	for i := range f.Children {
		if !f.Children[i].Equal(g.Children[i]) {
			return false
		}
	}
	return true
}

// Normalize returns a canonical copy: attribute descriptions and matching
// rules lower-cased, and/or members sorted by their text with duplicates
// removed. Values are left as they are (their comparison rules depend on
// the attribute syntax). The result is what events report as filter_norm.
func (f *Filter) Normalize() *Filter {
	if f == nil {
		return nil
	}
	n := f.Clone()
	n.normalize()
	return n
}

func (f *Filter) normalize() {
	f.Attr = strings.ToLower(f.Attr)
	f.MatchingRule = strings.ToLower(f.MatchingRule)
	for _, c := range f.Children {
		c.normalize()
	}
	if f.Kind != And && f.Kind != Or {
		return
	}
	keys := make([]string, len(f.Children))
	for i, c := range f.Children {
		keys[i] = c.String()
	}
	idx := make([]int, len(f.Children))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	out := make([]*Filter, 0, len(idx))
	last := ""
	for n, i := range idx {
		if n > 0 && keys[i] == last {
			continue
		}
		out = append(out, f.Children[i])
		last = keys[i]
	}
	f.Children = out
}

// Depth returns the nesting depth of and/or/not nodes (a leaf is 0).
func (f *Filter) Depth() int {
	if f == nil {
		return 0
	}
	d := 0
	for _, c := range f.Children {
		d = max(d, c.Depth())
	}
	if f.Kind == And || f.Kind == Or || f.Kind == Not {
		return d + 1
	}
	return d
}
