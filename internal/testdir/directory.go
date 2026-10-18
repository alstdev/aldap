package testdir

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// Directory is the in-memory entry store shared by one or more servers.
// It is safe for concurrent use.
type Directory struct {
	mu      sync.RWMutex
	entries []*Entry
	byDN    map[string]*Entry // canonical DN → entry
	baseDN  string
}

// NewDirectory builds a store from entries; DNs must parse (RFC 4514).
func NewDirectory(entries ...*Entry) (*Directory, error) {
	d := &Directory{byDN: map[string]*Entry{}}
	for _, e := range entries {
		if err := d.add(e); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *Directory) add(e *Entry) error {
	dn, err := e.parsedDN()
	if err != nil {
		return err
	}
	key := dn.Canonical()
	if _, dup := d.byDN[key]; dup {
		return fmt.Errorf("duplicate entry %q", e.DN)
	}
	if !e.Has("distinguishedName") {
		e.Add("distinguishedName", e.DN)
	}
	d.byDN[key] = e
	d.entries = append(d.entries, e)
	if d.baseDN == "" || dn.Depth() < mustDepth(d.baseDN) {
		d.baseDN = e.DN
	}
	return nil
}

func mustDepth(s string) int {
	dn, err := ldapfilter.ParseDN(s)
	if err != nil {
		return 0
	}
	return dn.Depth()
}

// Upsert adds or replaces an entry.
func (d *Directory) Upsert(e *Entry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	dn, err := e.parsedDN()
	if err != nil {
		return err
	}
	key := dn.Canonical()
	if old, ok := d.byDN[key]; ok {
		for i := range d.entries {
			if d.entries[i] == old {
				d.entries = append(d.entries[:i], d.entries[i+1:]...)
				break
			}
		}
		delete(d.byDN, key)
	}
	return d.add(e)
}

// Lookup returns the entry with the DN (case-insensitive), or nil.
func (d *Directory) Lookup(dn string) *Entry {
	p, err := ldapfilter.ParseDN(dn)
	if err != nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.byDN[p.Canonical()]
}

// BaseDN is the shallowest DN in the store (the naming context).
func (d *Directory) BaseDN() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.baseDN
}

// Len returns the number of entries.
func (d *Directory) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}

// FindByAttr returns entries whose attribute equals value (case-insensitive).
func (d *Directory) FindByAttr(attr, value string) []*Entry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []*Entry
	for _, e := range d.entries {
		for _, v := range e.Get(attr) {
			if strings.EqualFold(v, value) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// Scope of a search.
type Scope int

// Search scopes (RFC 4511 §4.5.1.2).
const (
	ScopeBase Scope = iota
	ScopeOne
	ScopeSub
)

// Search evaluates a filter under base with scope and returns matching
// entries in stable DN order. ErrNoSuchObject is returned when base does
// not exist.
func (d *Directory) Search(base string, scope Scope, f *ldapfilter.Filter) ([]*Entry, error) {
	bdn, err := ldapfilter.ParseDN(base)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSuchObject, err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if _, ok := d.byDN[bdn.Canonical()]; !ok {
		return nil, ErrNoSuchObject
	}
	m := &matcher{dir: d}
	var out []*Entry
	for _, e := range d.entries {
		edn, _ := e.parsedDN()
		switch scope {
		case ScopeBase:
			if !edn.Equal(bdn) {
				continue
			}
		case ScopeOne:
			p := edn.Parent()
			if p == nil || !p.Equal(bdn) {
				continue
			}
		case ScopeSub:
			if !edn.IsUnder(bdn) {
				continue
			}
		}
		if m.match(f, e) {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out, nil
}

// transitiveMembers returns the canonical DNs of every entry that is a
// member of group transitively (member attribute walk).
func (d *Directory) transitiveMembers(group *Entry) map[string]bool {
	seen := map[string]bool{}
	var walk func(g *Entry)
	walk = func(g *Entry) {
		for _, m := range g.Get("member") {
			mdn, err := ldapfilter.ParseDN(m)
			if err != nil {
				continue
			}
			key := mdn.Canonical()
			if seen[key] {
				continue
			}
			seen[key] = true
			if child, ok := d.byDN[key]; ok {
				walk(child)
			}
		}
	}
	walk(group)
	return seen
}

// transitiveGroups returns the canonical DNs of every group the entry is in
// transitively (memberOf attribute walk).
func (d *Directory) transitiveGroups(e *Entry) map[string]bool {
	seen := map[string]bool{}
	var walk func(x *Entry)
	walk = func(x *Entry) {
		for _, g := range x.Get("memberOf") {
			gdn, err := ldapfilter.ParseDN(g)
			if err != nil {
				continue
			}
			key := gdn.Canonical()
			if seen[key] {
				continue
			}
			seen[key] = true
			if grp, ok := d.byDN[key]; ok {
				walk(grp)
			}
		}
	}
	walk(e)
	return seen
}
