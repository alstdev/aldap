package vdir

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/upstream"
)

// Mock serves a profile from a file instead of an upstream (mode = mock,
// SPEC §3.4): a TOML file with [[users]] tables (base_dn optional) or a
// CSV file whose header names the attributes (dn column optional,
// multi-valued cells separated by '|'). Users without dn are placed at
// cn=<cn>,<base_dn>; users without objectClass get top/person/
// organizationalPerson/user. Binds compare userPassword.
type Mock struct {
	base    string
	entries []mockEntry
}

type mockEntry struct {
	e  *entry
	dn *ldapfilter.DN
}

// ErrMockFile reports an unreadable or malformed mock file.
var ErrMockFile = errors.New("mock file")

// LoadMock reads a mock file; the format follows the extension (.toml or
// .csv). defaultBase is used when the file sets no base_dn.
func LoadMock(path, defaultBase string) (*Mock, error) {
	m := &Mock{base: defaultBase}
	var rows []map[string]any
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		var doc struct {
			BaseDN string           `toml:"base_dn"`
			Users  []map[string]any `toml:"users"`
		}
		md, err := toml.DecodeFile(path, &doc)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %w", ErrMockFile, path, err)
		}
		if undec := md.Undecoded(); len(undec) > 0 {
			return nil, fmt.Errorf("%w %s: unknown key %s", ErrMockFile, path, undec[0].String())
		}
		if doc.BaseDN != "" {
			m.base = doc.BaseDN
		}
		rows = doc.Users
	case ".csv":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMockFile, err)
		}
		recs, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
		if err != nil {
			return nil, fmt.Errorf("%w %s: %w", ErrMockFile, path, err)
		}
		if len(recs) == 0 {
			return nil, fmt.Errorf("%w %s: empty", ErrMockFile, path)
		}
		for _, rec := range recs[1:] {
			row := map[string]any{}
			for i, h := range recs[0] {
				if i < len(rec) && rec[i] != "" {
					row[strings.TrimSpace(h)] = strings.Split(rec[i], "|")
				}
			}
			rows = append(rows, row)
		}
	default:
		return nil, fmt.Errorf("%w %s: use a .toml or .csv file", ErrMockFile, path)
	}
	if m.base == "" {
		return nil, fmt.Errorf("%w %s: base_dn is required (set it in the file or as the profile's first base)", ErrMockFile, path)
	}
	if _, err := ldapfilter.ParseDN(m.base); err != nil {
		return nil, fmt.Errorf("%w %s: base_dn: %w", ErrMockFile, path, err)
	}
	for i, row := range rows {
		if err := m.add(row); err != nil {
			return nil, fmt.Errorf("%w %s: user %d: %w", ErrMockFile, path, i+1, err)
		}
	}
	return m, nil
}

func (m *Mock) add(row map[string]any) error {
	e := &entry{}
	for k, v := range row {
		if strings.EqualFold(k, "dn") {
			continue
		}
		e.add(k, mockValues(v)...)
	}
	dn := ""
	if v, ok := row["dn"]; ok {
		dn = strings.Join(mockValues(v), "")
	}
	if dn == "" {
		cn := e.get("cn")
		if len(cn) == 0 {
			return errors.New("dn or cn is required")
		}
		dn = "cn=" + ldapfilter.EscapeRDNValue(cn[0]) + "," + m.base
	}
	p, err := ldapfilter.ParseDN(dn)
	if err != nil {
		return fmt.Errorf("dn: %w", err)
	}
	e.dn = dn
	if len(e.get("distinguishedName")) == 0 {
		e.add("distinguishedName", dn)
	}
	if len(e.get("objectClass")) == 0 {
		e.add("objectClass", "top", "person", "organizationalPerson", "user")
	}
	m.entries = append(m.entries, mockEntry{e: e, dn: p})
	return nil
}

func mockValues(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, i := range x {
			out = append(out, mockValues(i)...)
		}
		return out
	case int64:
		return []string{strconv.FormatInt(x, 10)}
	case float64:
		return []string{strconv.FormatFloat(x, 'f', -1, 64)}
	case bool:
		return []string{strconv.FormatBool(x)}
	default:
		return []string{fmt.Sprint(x)}
	}
}

// BaseDN returns the base under which users without dn were placed.
func (m *Mock) BaseDN() string { return m.base }

// Len returns the number of entries.
func (m *Mock) Len() int { return len(m.entries) }

// Name implements Searcher.
func (m *Mock) Name() string { return "mock" }

// Search implements Searcher over the in-memory entries.
func (m *Mock) Search(_ context.Context, req upstream.SearchRequest) (*upstream.Result, error) {
	base, err := ldapfilter.ParseDN(req.Base)
	if err != nil {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, err)
	}
	f := req.Filter
	if f == nil {
		f = ldapfilter.True()
	}
	res := &upstream.Result{Pages: 1, Server: "mock"}
	for _, me := range m.entries {
		var in bool
		switch req.Scope {
		case upstream.ScopeBase:
			in = me.dn.Equal(base)
		case upstream.ScopeOne:
			in = me.dn.Parent() != nil && me.dn.Parent().Equal(base)
		default:
			in = me.dn.IsUnder(base)
		}
		if !in || !me.e.matches(f) {
			continue
		}
		if req.SizeLimit > 0 && len(res.Entries) >= req.SizeLimit {
			res.Truncated = true
			break
		}
		res.Entries = append(res.Entries, mockProject(me.e, req.Attrs))
	}
	return res, nil
}

func mockProject(e *entry, attrs []string) upstream.Entry {
	out := upstream.Entry{DN: e.dn, Attrs: map[string][]string{}}
	want := map[string]bool{}
	for _, a := range attrs {
		want[strings.ToLower(a)] = true
	}
	for _, a := range e.attrs {
		l := strings.ToLower(a.Name)
		if l == "userpassword" {
			continue
		}
		if len(attrs) == 0 || want[l] {
			out.Attrs[l] = append([]string(nil), a.Values...)
		}
	}
	return out
}

// UserBind implements Searcher: name is a DN of an entry or one of its
// identity attributes; the password is compared with userPassword.
func (m *Mock) UserBind(_ context.Context, name, password string) error {
	var found *entry
	if dn, err := ldapfilter.ParseDN(name); err == nil && strings.Contains(name, "=") {
		for _, me := range m.entries {
			if me.dn.Equal(dn) {
				found = me.e
			}
		}
	} else {
		for _, me := range m.entries {
			for _, a := range identityAttrs {
				for _, v := range me.e.get(a) {
					if strings.EqualFold(v, name) {
						found = me.e
					}
				}
			}
		}
	}
	if found == nil {
		return &upstream.BindError{Reason: upstream.ReasonUnknownAccount}
	}
	for _, pw := range found.get("userPassword") {
		if subtle.ConstantTimeCompare([]byte(pw), []byte(password)) == 1 {
			return nil
		}
	}
	return &upstream.BindError{Reason: upstream.ReasonInvalidPassword}
}
