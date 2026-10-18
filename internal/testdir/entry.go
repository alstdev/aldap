package testdir

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// Entry is one directory object. Attribute names keep the spelling of the
// source; lookups are case-insensitive.
type Entry struct {
	DN    string
	Attrs []Attribute

	dn *ldapfilter.DN
}

// Attribute is one attribute with its values (raw bytes in strings).
type Attribute struct {
	Name   string
	Values []string
}

// Get returns the values of the attribute, or nil.
func (e *Entry) Get(name string) []string {
	for i := range e.Attrs {
		if strings.EqualFold(e.Attrs[i].Name, name) {
			return e.Attrs[i].Values
		}
	}
	return nil
}

// First returns the first value of the attribute, or "".
func (e *Entry) First(name string) string {
	if v := e.Get(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// Has reports whether the attribute is present.
func (e *Entry) Has(name string) bool { return e.Get(name) != nil }

// Set replaces (or adds) the attribute.
func (e *Entry) Set(name string, values ...string) {
	for i := range e.Attrs {
		if strings.EqualFold(e.Attrs[i].Name, name) {
			e.Attrs[i].Values = values
			return
		}
	}
	e.Attrs = append(e.Attrs, Attribute{Name: name, Values: values})
}

// Add appends values to the attribute, creating it when missing.
func (e *Entry) Add(name string, values ...string) {
	for i := range e.Attrs {
		if strings.EqualFold(e.Attrs[i].Name, name) {
			e.Attrs[i].Values = append(e.Attrs[i].Values, values...)
			return
		}
	}
	e.Attrs = append(e.Attrs, Attribute{Name: name, Values: values})
}

// Clone returns a deep copy.
func (e *Entry) Clone() *Entry {
	c := &Entry{DN: e.DN, dn: e.dn, Attrs: make([]Attribute, len(e.Attrs))}
	for i, a := range e.Attrs {
		c.Attrs[i] = Attribute{Name: a.Name, Values: append([]string(nil), a.Values...)}
	}
	return c
}

// parsedDN returns the parsed DN, parsing it on first use.
func (e *Entry) parsedDN() (*ldapfilter.DN, error) {
	if e.dn != nil {
		return e.dn, nil
	}
	dn, err := ldapfilter.ParseDN(e.DN)
	if err != nil {
		return nil, fmt.Errorf("entry %q: %w", e.DN, err)
	}
	e.dn = dn
	return dn, nil
}

// ParseLDIF reads LDIF content records (RFC 2849): "dn:" lines, "attr: value",
// "attr:: base64", line continuations (leading space) and "#" comments.
// Change records ("changetype:") are not supported.
func ParseLDIF(r io.Reader) ([]*Entry, error) {
	var (
		entries []*Entry
		cur     *Entry
		lines   []string
	)
	flush := func() error {
		if len(lines) == 0 {
			return nil
		}
		defer func() { lines = lines[:0]; cur = nil }()
		for _, l := range lines {
			name, value, err := parseLDIFLine(l)
			if err != nil {
				return err
			}
			switch {
			case strings.EqualFold(name, "dn"):
				if cur != nil {
					return fmt.Errorf("ldif: duplicate dn in record %q", cur.DN)
				}
				cur = &Entry{DN: value}
			case strings.EqualFold(name, "changetype"):
				return fmt.Errorf("ldif: change records are not supported (%s)", value)
			case cur == nil:
				return fmt.Errorf("ldif: attribute %q before dn", name)
			default:
				cur.Add(name, value)
			}
		}
		if cur == nil {
			return nil
		}
		if _, err := cur.parsedDN(); err != nil {
			return err
		}
		entries = append(entries, cur)
		return nil
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := flush(); err != nil {
				return nil, err
			}
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, " ") && len(lines) > 0:
			lines[len(lines)-1] += line[1:]
		case strings.HasPrefix(line, "version:"):
		default:
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ldif: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return entries, nil
}

func parseLDIFLine(l string) (name, value string, err error) {
	i := strings.IndexByte(l, ':')
	if i <= 0 {
		return "", "", fmt.Errorf("ldif: malformed line %q", l)
	}
	name = l[:i]
	rest := l[i+1:]
	switch {
	case strings.HasPrefix(rest, ":"):
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest[1:]))
		if err != nil {
			return "", "", fmt.Errorf("ldif: %s: %w", name, err)
		}
		return name, string(b), nil
	case strings.HasPrefix(rest, "<"):
		return "", "", fmt.Errorf("ldif: %s: URL values are not supported", name)
	default:
		return name, strings.TrimLeft(rest, " "), nil
	}
}

// LoadLDIF reads entries from a file.
func LoadLDIF(path string) ([]*Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ldif: %w", err)
	}
	defer f.Close()
	return ParseLDIF(f)
}
