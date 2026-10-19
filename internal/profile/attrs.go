package profile

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"text/template/parse"
	"unicode/utf8"
)

// Computed is one attrs.computed entry: a Go template evaluated over the
// upstream attributes of an entry (SPEC §3.4). Deps lists the upstream
// attribute names the template reads, so the directory can fetch them.
type Computed struct {
	Name string
	Deps []string
	tpl  *template.Template
}

// templateFuncs are the functions available to computed and honeytoken
// templates (SPEC §3.4 attrs.computed): or and printf are built in.
var templateFuncs = template.FuncMap{
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
	"trim":  strings.TrimSpace,
	// default returns def when v is empty: {{ .mail | default "none" }}.
	"default": func(def, v string) string {
		if v == "" {
			return def
		}
		return v
	},
	// first returns the first non-empty argument.
	"first": func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}
		return ""
	},
	// join concatenates the non-empty arguments with sep.
	"join": func(sep string, vals ...string) string {
		out := vals[:0:0]
		for _, v := range vals {
			if v != "" {
				out = append(out, v)
			}
		}
		return strings.Join(out, sep)
	},
	"regexReplace": regexReplace,
}

var (
	regexMu    sync.Mutex
	regexCache = map[string]*regexp.Regexp{}
)

// regexReplace replaces every match of pattern in s with repl ($1 groups).
func regexReplace(pattern, repl, s string) (string, error) {
	regexMu.Lock()
	re, ok := regexCache[pattern]
	if !ok {
		var err error
		if re, err = regexp.Compile(pattern); err != nil {
			regexMu.Unlock()
			return "", err
		}
		if len(regexCache) > 256 {
			regexCache = map[string]*regexp.Regexp{}
		}
		regexCache[pattern] = re
	}
	regexMu.Unlock()
	return re.ReplaceAllString(s, repl), nil
}

// ParseTemplate compiles an attribute template with the ALDAP function set.
func ParseTemplate(name, text string) (*template.Template, error) {
	return template.New(name).Funcs(templateFuncs).Option("missingkey=zero").Parse(text)
}

// CompileComputed parses one computed attribute.
func CompileComputed(name, text string) (*Computed, error) {
	tpl, err := ParseTemplate(name, text)
	if err != nil {
		return nil, err
	}
	c := &Computed{Name: name, tpl: tpl}
	seen := map[string]bool{}
	walkFields(tpl.Root, func(field string) {
		if l := strings.ToLower(field); !seen[l] {
			seen[l] = true
			c.Deps = append(c.Deps, field)
		}
	})
	return c, nil
}

// walkFields calls fn with the first identifier of every .Field reference.
func walkFields(n parse.Node, fn func(string)) {
	switch n := n.(type) {
	case nil:
	case *parse.ListNode:
		if n != nil {
			for _, c := range n.Nodes {
				walkFields(c, fn)
			}
		}
	case *parse.ActionNode:
		walkFields(n.Pipe, fn)
	case *parse.PipeNode:
		if n != nil {
			for _, c := range n.Cmds {
				walkFields(c, fn)
			}
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			walkFields(a, fn)
		}
	case *parse.FieldNode:
		if len(n.Ident) > 0 {
			fn(n.Ident[0])
		}
	case *parse.ChainNode:
		walkFields(n.Node, fn)
	case *parse.IfNode:
		walkFields(n.Pipe, fn)
		walkFields(n.List, fn)
		walkFields(n.ElseList, fn)
	case *parse.RangeNode:
		walkFields(n.Pipe, fn)
		walkFields(n.List, fn)
		walkFields(n.ElseList, fn)
	case *parse.WithNode:
		walkFields(n.Pipe, fn)
		walkFields(n.List, fn)
		walkFields(n.ElseList, fn)
	case *parse.TemplateNode:
		walkFields(n.Pipe, fn)
	}
}

// Eval renders the template over data (upstream attribute name → first
// value; every Deps key must be present, "" when the entry lacks it).
func (c *Computed) Eval(data map[string]string) (string, error) {
	var b strings.Builder
	if err := c.tpl.Execute(&b, data); err != nil {
		return "", err
	}
	return strings.TrimSpace(b.String()), nil
}

// Mask is one attrs.mask pattern (SPEC §4.6): literal text and the
// placeholders {first<N>}, {last<N>} and {domain}.
type Mask struct {
	Name  string
	parts []maskPart
}

type maskPart struct {
	kind    byte // 'l' literal, 'f' first N, 'e' last N, 'd' domain
	literal string
	n       int
}

var maskPlaceholder = regexp.MustCompile(`\{(first|last)([0-9]+)\}|\{domain\}`)

// ErrMaskPattern reports an invalid mask pattern.
var ErrMaskPattern = errors.New("invalid mask pattern")

// CompileMask parses a mask pattern.
func CompileMask(name, pattern string) (*Mask, error) {
	m := &Mask{Name: name}
	rest := pattern
	for rest != "" {
		loc := maskPlaceholder.FindStringSubmatchIndex(rest)
		if loc == nil {
			if strings.ContainsAny(rest, "{}") {
				return nil, fmt.Errorf("%w %q: unknown placeholder", ErrMaskPattern, pattern)
			}
			m.parts = append(m.parts, maskPart{kind: 'l', literal: rest})
			break
		}
		if loc[0] > 0 {
			lit := rest[:loc[0]]
			if strings.ContainsAny(lit, "{}") {
				return nil, fmt.Errorf("%w %q: unknown placeholder", ErrMaskPattern, pattern)
			}
			m.parts = append(m.parts, maskPart{kind: 'l', literal: lit})
		}
		switch tok := rest[loc[0]:loc[1]]; tok {
		case "{domain}":
			m.parts = append(m.parts, maskPart{kind: 'd'})
		default:
			n, err := strconv.Atoi(rest[loc[4]:loc[5]])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%w %q: bad count", ErrMaskPattern, pattern)
			}
			kind := byte('f')
			if rest[loc[2]:loc[3]] == "last" {
				kind = 'e'
			}
			m.parts = append(m.parts, maskPart{kind: kind, n: n})
		}
		rest = rest[loc[1]:]
	}
	if len(m.parts) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrMaskPattern)
	}
	return m, nil
}

// Apply masks one value.
func (m *Mask) Apply(v string) string {
	var b strings.Builder
	for _, p := range m.parts {
		switch p.kind {
		case 'l':
			b.WriteString(p.literal)
		case 'f':
			b.WriteString(firstRunes(v, p.n))
		case 'e':
			b.WriteString(lastRunes(v, p.n))
		case 'd':
			if i := strings.LastIndexByte(v, '@'); i >= 0 {
				b.WriteString(v[i+1:])
			}
		}
	}
	return b.String()
}

func firstRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for range n {
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	return s[:i]
}

func lastRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := len(s)
	for range n {
		_, w := utf8.DecodeLastRuneInString(s[:i])
		i -= w
	}
	return s[i:]
}
