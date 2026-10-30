package vdir

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/ldapfilter"
	"github.com/alstdev/aldap/internal/profile"
	"github.com/alstdev/aldap/internal/upstream"
)

// ruleInChain is LDAP_MATCHING_RULE_IN_CHAIN (transitive membership in AD).
const ruleInChain = "1.2.840.113556.1.4.1941"

// identityAttrs are the upstream attributes that identify a user for
// include/exclude lists and binds.
var identityAttrs = []string{"userPrincipalName", "sAMAccountName", "mail", "uid"}

// groupClasses mark an upstream entry as a group on generic directories.
var groupClasses = map[string]bool{"group": true, "groupofnames": true, "groupofuniquenames": true, "posixgroup": true}

// member is one user in the membership snapshot.
type member struct {
	key  string // dedupe key (objectGUID or canonical DN)
	rdn  string
	dn   string // virtual DN
	ids  []string
	guid string
	up   string // upstream DN
}

// groupData is one virtual group with its computed members.
type groupData struct {
	g       *profile.Group
	members []member // sorted by virtual DN
}

// membership is the cached result of evaluating every virtual group
// (SPEC §4.4): computed lazily, reused for rules.MembershipTTL so that
// member and memberOf agree within that window.
type membership struct {
	expires    time.Time
	groups     []*groupData
	byName     map[string]*groupData
	userGroups map[string][]string // user key → virtual group DNs, sorted
	// rdns counts the distinct users per lower-cased RDN value over the
	// set the virtual DNs were decided on (RDN collision suffix).
	rdns map[string]int
}

// membership returns the current snapshot, computing it when missing or
// expired. Computation is serialized; a failure is not cached.
func (d *Directory) membership(ctx context.Context) (*membership, error) {
	if d.o.Replica != nil {
		rd, err := d.replicaData()
		if err != nil {
			return nil, err
		}
		return rd.mem, nil
	}
	d.memMu.Lock()
	defer d.memMu.Unlock()
	if d.mem != nil && d.now().Before(d.mem.expires) {
		return d.mem, nil
	}
	m, err := d.computeMembership(ctx, nil)
	if err != nil {
		return nil, err
	}
	d.mem = m
	return m, nil
}

// InvalidateMembership drops the cached group membership (tests, reload).
func (d *Directory) InvalidateMembership() {
	d.memMu.Lock()
	d.mem = nil
	d.memMu.Unlock()
}

// computeMembership evaluates every group. RDN collisions are decided over
// the members of all groups together with users (the whole replica; nil
// otherwise).
func (d *Directory) computeMembership(ctx context.Context, users []upstream.Entry) (*membership, error) {
	m := &membership{expires: d.now().Add(d.rules.MembershipTTL), byName: map[string]*groupData{}, userGroups: map[string][]string{}, rdns: map[string]int{}}
	all := map[string]*member{} // key → member, across groups (for RDN collisions)
	for _, e := range users {
		mb := d.newMember(e)
		all[mb.key] = mb
	}
	sets := make([]map[string]*member, 0, len(d.rules.Groups()))
	for _, g := range d.rules.Groups() {
		set, err := d.groupMembers(ctx, g)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		for k, mb := range set {
			all[k] = mb
		}
		sets = append(sets, set)
	}
	rdns := m.rdns
	for _, mb := range all {
		rdns[strings.ToLower(mb.rdn)]++
	}
	for i, g := range d.rules.Groups() {
		gd := &groupData{g: g}
		for _, mb := range sets[i] {
			mb.dn = d.virtualUserDN(mb.rdn, mb.guid, mb.up, rdns[strings.ToLower(mb.rdn)] > 1)
			gd.members = append(gd.members, *mb)
			m.userGroups[mb.key] = append(m.userGroups[mb.key], g.DN)
		}
		sort.Slice(gd.members, func(a, b int) bool { return gd.members[a].dn < gd.members[b].dn })
		m.groups = append(m.groups, gd)
		m.byName[strings.ToLower(g.Name)] = gd
	}
	for k := range m.userGroups {
		sort.Strings(m.userGroups[k])
	}
	return m, nil
}

// groupMembers evaluates one group: (bases+filter) ∪ ad_groups ∪ include −
// exclude, every source intersected with the profile filter.
func (d *Directory) groupMembers(ctx context.Context, g *profile.Group) (map[string]*member, error) {
	set := map[string]*member{}
	add := func(es []upstream.Entry) {
		for _, e := range es {
			mb := d.newMember(e)
			if _, dup := set[mb.key]; !dup {
				set[mb.key] = mb
			}
		}
	}
	if d.up != nil {
		if len(g.Bases) > 0 {
			f := d.profileFilter(g.Filter)
			for _, base := range g.Bases {
				es, err := d.searchAll(ctx, base, upstream.ScopeSub, f)
				if err != nil {
					return nil, err
				}
				add(es)
			}
		}
		for _, gdn := range g.ADGroups {
			es, err := d.adGroupMembers(ctx, gdn)
			if err != nil {
				return nil, err
			}
			add(es)
		}
		for _, acct := range g.Include {
			es, err := d.findAccount(ctx, acct)
			if err != nil {
				return nil, err
			}
			add(es)
		}
	}
	if d.rules.HoneytokenInGroups || d.up == nil {
		for _, h := range d.rules.Honeytokens() {
			add([]upstream.Entry{honeytokenEntry(h)})
		}
	}
	for _, acct := range g.Exclude {
		for k, mb := range set {
			if mb.is(acct) {
				delete(set, k)
			}
		}
	}
	return set, nil
}

// profileFilter ANDs f (nil = none) with the profile filter and NOT exclude.
func (d *Directory) profileFilter(f *ldapfilter.Filter) *ldapfilter.Filter {
	if f == nil {
		f = ldapfilter.True()
	}
	if d.rules.Filter != nil {
		f = ldapfilter.Inject(f, d.rules.Filter)
	}
	if d.rules.Exclude != nil {
		f = ldapfilter.Exclude(f, d.rules.Exclude)
	}
	return f
}

// memberAttrs are fetched for membership entries.
func (d *Directory) memberAttrs() []string {
	attrs := append([]string{d.rules.RDNAttr, attrObjectGUID}, identityAttrs...)
	return attrs
}

// searchAll runs one upstream search and returns its entries; a base that
// does not exist (noSuchObject) yields none.
func (d *Directory) searchAll(ctx context.Context, base string, scope upstream.Scope, f *ldapfilter.Filter) ([]upstream.Entry, error) {
	r, err := d.src.Search(ctx, upstream.SearchRequest{Base: base, Scope: scope, Filter: f, Attrs: d.memberAttrs()})
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, err
	}
	return r.Entries, nil
}

// adGroupMembers lists the users of an upstream group that pass the
// profile filter within the profile bases: AD answers memberOf (in chain
// when nested_groups) itself; generic directories are walked by member.
func (d *Directory) adGroupMembers(ctx context.Context, groupDN string) ([]upstream.Entry, error) {
	if d.rules.Kind == "ad" {
		term := &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: profile.AttrMemberOf, Value: groupDN}
		if d.rules.NestedGroups {
			term = &ldapfilter.Filter{Kind: ldapfilter.Extensible, Attr: profile.AttrMemberOf, MatchingRule: ruleInChain, Value: groupDN}
		}
		f := d.profileFilter(term)
		var out []upstream.Entry
		for _, base := range d.rules.Bases {
			es, err := d.searchAll(ctx, base, upstream.ScopeSub, f)
			if err != nil {
				return nil, err
			}
			out = append(out, es...)
		}
		return out, nil
	}
	var out []upstream.Entry
	seen := map[string]bool{}
	if err := d.walkGroup(ctx, groupDN, 0, seen, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// walkGroup reads the member attribute of a generic group and resolves
// each member: nested groups recurse up to nested_depth (when enabled),
// users are kept when they lie in a profile base and pass the filter.
func (d *Directory) walkGroup(ctx context.Context, groupDN string, depth int, seen map[string]bool, out *[]upstream.Entry) error {
	key := canonicalDN(groupDN)
	if seen[key] {
		return nil
	}
	seen[key] = true
	r, err := d.src.Search(ctx, upstream.SearchRequest{Base: groupDN, Scope: upstream.ScopeBase, Filter: ldapfilter.True(), Attrs: []string{profile.AttrMember, "uniqueMember", "objectClass"}})
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil
		}
		return err
	}
	for _, g := range r.Entries {
		members := append(g.Get(profile.AttrMember), g.Get("uniqueMember")...)
		for _, mdn := range members {
			mkey := canonicalDN(mdn)
			if seen[mkey] {
				continue
			}
			probe, err := d.src.Search(ctx, upstream.SearchRequest{Base: mdn, Scope: upstream.ScopeBase, Filter: ldapfilter.True(), Attrs: []string{"objectClass", profile.AttrMember}})
			if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return err
			}
			if err != nil || len(probe.Entries) == 0 {
				seen[mkey] = true
				continue
			}
			if isGroup(probe.Entries[0]) {
				if d.rules.NestedGroups && depth+1 < d.rules.NestedDepth {
					if err := d.walkGroup(ctx, mdn, depth+1, seen, out); err != nil {
						return err
					}
				}
				seen[mkey] = true
				continue
			}
			seen[mkey] = true
			if !d.inBases(mdn) {
				continue
			}
			es, err := d.searchAll(ctx, mdn, upstream.ScopeBase, d.profileFilter(nil))
			if err != nil {
				return err
			}
			*out = append(*out, es...)
		}
	}
	return nil
}

func isGroup(e upstream.Entry) bool {
	if len(e.Get(profile.AttrMember)) > 0 {
		return true
	}
	for _, oc := range e.Get("objectClass") {
		if groupClasses[strings.ToLower(oc)] {
			return true
		}
	}
	return false
}

// inBases reports whether an upstream DN lies under one of the profile bases.
func (d *Directory) inBases(dn string) bool {
	p, err := ldapfilter.ParseDN(dn)
	if err != nil {
		return false
	}
	for _, b := range d.rules.Bases {
		if bd, err := ldapfilter.ParseDN(b); err == nil && p.IsUnder(bd) {
			return true
		}
	}
	return false
}

// findAccount resolves an include entry (UPN, mail, sAMAccountName/uid or
// upstream DN) to the matching users that pass the profile filter.
func (d *Directory) findAccount(ctx context.Context, acct string) ([]upstream.Entry, error) {
	acct = strings.TrimSpace(acct)
	if acct == "" {
		return nil, nil
	}
	if strings.Contains(acct, "=") {
		if _, err := ldapfilter.ParseDN(acct); err == nil {
			if !d.inBases(acct) {
				return nil, nil
			}
			return d.searchAll(ctx, acct, upstream.ScopeBase, d.profileFilter(nil))
		}
	}
	f := d.identityFilter(acct)
	var out []upstream.Entry
	for _, base := range d.rules.Bases {
		es, err := d.searchAll(ctx, base, upstream.ScopeSub, d.profileFilter(f))
		if err != nil {
			return nil, err
		}
		out = append(out, es...)
	}
	return out, nil
}

// identityFilter matches an include/exclude entry with '@' by
// userPrincipalName on AD and by mail on generic directories (which have
// no UPN); without '@' by sAMAccountName or uid. On AD, mail is never an
// identity: it is not unique and often self-writable, so a user could add
// themselves to a group by setting mail to an included administrator's UPN.
func (d *Directory) identityFilter(acct string) *ldapfilter.Filter {
	eq := func(attr string) *ldapfilter.Filter {
		return &ldapfilter.Filter{Kind: ldapfilter.Equality, Attr: attr, Value: acct}
	}
	if strings.Contains(acct, "@") {
		if d.rules.Kind == "ad" {
			return eq("userPrincipalName")
		}
		return eq("mail")
	}
	return &ldapfilter.Filter{Kind: ldapfilter.Or, Children: []*ldapfilter.Filter{eq("sAMAccountName"), eq("uid")}}
}

// newMember describes a group member; an entry without an rdn_attr value
// gets the same opaque RDN transform gives it.
func (d *Directory) newMember(e upstream.Entry) *member {
	mb := &member{key: d.dedupeKey(e), rdn: d.virtualRDN(e), guid: e.First(attrObjectGUID), up: e.DN}
	for _, a := range identityAttrs {
		for _, v := range e.Get(a) {
			mb.ids = append(mb.ids, strings.ToLower(v))
		}
	}
	mb.ids = append(mb.ids, canonicalDN(e.DN))
	return mb
}

// is reports whether an exclude entry names this member.
func (mb *member) is(acct string) bool {
	acct = strings.TrimSpace(acct)
	want := strings.ToLower(acct)
	if strings.Contains(acct, "=") {
		if _, err := ldapfilter.ParseDN(acct); err == nil {
			want = canonicalDN(acct)
		}
	}
	for _, id := range mb.ids {
		if id == want {
			return true
		}
	}
	return false
}

func canonicalDN(dn string) string {
	if p, err := ldapfilter.ParseDN(dn); err == nil {
		return p.Canonical()
	}
	return strings.ToLower(dn)
}

// virtualUserDN builds cn=<rdn>,ou=users,<virtual_base>; an RDN shared by
// several users gets a +objectGUID suffix (SPEC §4.2 step 6).
func (d *Directory) virtualUserDN(rdn, guid, upstreamDN string, collision bool) string {
	if !collision {
		return d.rules.UserDN(rdn)
	}
	id := hex.EncodeToString([]byte(guid))
	if id == "" {
		id = hex.EncodeToString([]byte(upstreamDN))
	}
	return d.rules.UsersBase.Child(ldapfilter.RDN{AVAs: []ldapfilter.AVA{{Type: "cn", Value: rdn}, {Type: "objectGUID", Value: id}}}).String()
}

// groupEntry renders a virtual group (SPEC §4.4) with the attributes of
// its object class: groupOfNames (member), group (AD-like, member and
// sAMAccountName) or posixGroup (gidNumber, memberUid and member).
func (d *Directory) groupEntry(gd *groupData) *entry {
	g := gd.g
	e := &entry{dn: g.DN}
	e.add("objectClass", "top", g.ObjectClass)
	e.add("cn", g.Name)
	if g.Description != "" {
		e.add("description", g.Description)
	}
	switch g.ObjectClass {
	case "group":
		e.add("sAMAccountName", g.Name)
		e.add("groupType", "-2147483646")
	case "posixGroup":
		e.add("gidNumber", strconv.Itoa(g.GIDNumber))
		for _, mb := range gd.members {
			e.add(profile.AttrMemberUID, mb.rdn)
		}
	}
	for _, mb := range gd.members {
		e.add(profile.AttrMember, mb.dn)
	}
	return e
}

// groupAttrs are attributes of group entries that any client may request.
var groupAttrs = map[string]bool{"member": true, "memberuid": true, "gidnumber": true, "samaccountname": true, "grouptype": true, "cn": true, "description": true, "objectclass": true}
