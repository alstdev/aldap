package vdir

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/alstdev/aldap/internal/listener"
	"github.com/alstdev/aldap/internal/upstream"
)

// errNoReplica reports a replica profile that has not synced yet.
var errNoReplica = errors.New("replica not synced")

// replicaData is one synced copy of a replica profile (SPEC §5.1): every
// user of the profile bases × filter with its virtual entry, and the group
// membership computed at the same time. Virtual DNs (RDN collision
// suffix) are decided over the whole set, so a user has the same DN in
// searches and in group member values.
type replicaData struct {
	users []replicaUser // sorted by virtual DN
	mem   *membership
}

type replicaUser struct {
	rdn  string
	full *entry // transformed, unmasked
}

// SyncReplica fetches a complete copy of the profile from the upstream
// for cache.mode = replica: every base with the profile filter and every
// attribute the profile can return, then the group membership. It
// returns the copy (for ReplicaSource) and its user count. The cache is
// not used; any failure discards the partial copy.
func (d *Directory) SyncReplica(ctx context.Context) (any, int, error) {
	if d.up == nil {
		return nil, 0, errors.New("replica: profile has no upstream")
	}
	sc := &searchCtx{all: true}
	attrs := d.upstreamAttrs(sc)
	f := d.profileFilter(nil)
	var users []upstream.Entry
	seen := map[string]bool{}
	for _, base := range d.rules.Bases {
		r, err := d.up.Search(ctx, upstream.SearchRequest{Base: base, Scope: upstream.ScopeSub, Filter: f, Attrs: attrs})
		if err != nil {
			return nil, 0, fmt.Errorf("replica: base %s: %w", base, err)
		}
		for _, e := range r.Entries {
			if k := d.dedupeKey(e); !seen[k] {
				seen[k] = true
				users = append(users, e)
			}
		}
	}
	// Membership comes from the upstream at the same time (src is the
	// upstream itself in replica mode).
	all := users
	for _, h := range d.rules.Honeytokens() {
		all = append(all, honeytokenEntry(h))
	}
	mem, err := d.computeMembership(ctx, all)
	if err != nil {
		return nil, 0, fmt.Errorf("replica: %w", err)
	}
	var memberOf *membership
	if d.rules.HasGroups() {
		memberOf = mem
	}
	rd := &replicaData{mem: mem, users: make([]replicaUser, 0, len(users))}
	for _, e := range users {
		rdn := e.First(d.rules.RDNAttr)
		rd.users = append(rd.users, replicaUser{rdn: rdn, full: d.transform(e, memberOf, mem.collides(rdn, e.DN))})
	}
	sort.Slice(rd.users, func(i, j int) bool { return rd.users[i].full.dn < rd.users[j].full.dn })
	return rd, len(rd.users), nil
}

// collides reports whether an RDN value is shared by several users of the
// set the membership was computed over (an empty RDN falls back to the DN
// like transform does).
func (m *membership) collides(rdn, dn string) bool {
	if rdn == "" {
		rdn = dn
	}
	return m.rdns[strings.ToLower(rdn)] > 1
}

func (d *Directory) replicaData() (*replicaData, error) {
	data, _, ok := d.o.Replica.Current()
	if !ok {
		return nil, errNoReplica
	}
	rd, ok := data.(*replicaData)
	if !ok {
		return nil, errNoReplica
	}
	return rd, nil
}

// replicaUsers answers a user search from the replica: the client filter
// is evaluated on the virtual entries (like for honeytokens and mock
// profiles), then masking and projection as for upstream results.
func (d *Directory) replicaUsers(sc *searchCtx, rdn string) ([]listener.Entry, listener.Result) {
	rd, err := d.replicaData()
	if err != nil {
		return nil, d.upstreamError(sc, err)
	}
	sc.replica = true
	var out []listener.Entry
	keep := func(full *entry) {
		if !full.matches(sc.filter) {
			return
		}
		e := &entry{dn: full.dn, attrs: append([]listener.Attribute(nil), full.attrs...)}
		d.mask(e)
		out = append(out, e.project(sc.want, sc.all))
	}
	for _, u := range rd.users {
		if rdn == "" || strings.EqualFold(u.rdn, rdn) {
			keep(u.full)
		}
	}
	var memberOf *membership
	if d.rules.HasGroups() {
		memberOf = rd.mem
	}
	for _, h := range d.rules.Honeytokens() {
		he := honeytokenEntry(h)
		hr := he.First(d.rules.RDNAttr)
		if rdn == "" || strings.EqualFold(hr, rdn) {
			keep(d.transform(he, memberOf, rd.mem.collides(hr, he.DN)))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out, listener.Success
}
