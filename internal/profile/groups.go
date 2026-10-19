package profile

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

// Virtual attributes of the tree that never come from the upstream.
const (
	AttrMemberOf  = "memberOf"
	AttrMember    = "member"
	AttrMemberUID = "memberUid"
)

// Group is one compiled virtual group (SPEC §4.4).
type Group struct {
	Name        string
	DN          string
	Description string
	ObjectClass string
	GIDNumber   int
	// Bases and Filter are the member sources; nil Filter means the profile filter.
	Bases  []string
	Filter *ldapfilter.Filter
	// ADGroups are upstream group DNs whose (nested) members are included.
	ADGroups []string
	// Include and Exclude are account identifiers (UPN, sAMAccountName/uid, mail or upstream DN).
	Include []string
	Exclude []string
}

// Honeytoken is one trap account (SPEC §4.5) rendered as an upstream-like
// entry so that it goes through the same transformation as real users.
type Honeytoken struct {
	Account string
	// User and Domain split the account at '@' (Domain may be empty).
	User, Domain string
	// DN is a plausible upstream DN; GUID is a stable pseudo objectGUID.
	DN   string
	GUID string
	// Attrs are upstream attribute names → values.
	Attrs map[string][]string
}

// defaultHoneytokenTemplate renders plausible attributes when
// honeytoken_template leaves them unset.
var defaultHoneytokenTemplate = map[string]string{
	"cn":                 "{{ .given }} {{ .sn }}",
	"sn":                 "{{ .sn }}",
	"givenName":          "{{ .given }}",
	"displayName":        "{{ .given }} {{ .sn }}",
	"name":               "{{ .given }} {{ .sn }}",
	"sAMAccountName":     "{{ .user }}",
	"userPrincipalName":  "{{ .account }}",
	"mail":               "{{ .account }}",
	"uid":                "{{ .user }}",
	"title":              "Specialist",
	"objectCategory":     "person",
	"userAccountControl": "512",
}

var honeytokenObjectClasses = []string{"top", "person", "organizationalPerson", "user"}

func (r *Rules) compileGroups(name string, p *config.Profile) error {
	names := make([]string, 0, len(p.Groups))
	for g := range p.Groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, gname := range names {
		gc := p.Groups[gname]
		g := &Group{Name: gname, DN: r.GroupDN(gname), Description: gc.Description, ObjectClass: gc.ObjectClass, GIDNumber: gc.GIDNumber,
			Bases: append([]string(nil), gc.Members.Bases...), ADGroups: append([]string(nil), gc.Members.ADGroups...),
			Include: append([]string(nil), gc.Members.Include...), Exclude: append([]string(nil), gc.Members.Exclude...)}
		if g.ObjectClass == "" {
			g.ObjectClass = "groupOfNames"
		}
		if gc.Members.Filter != "" {
			f, err := ldapfilter.Parse(gc.Members.Filter)
			if err != nil {
				return fmt.Errorf("profile %s: groups.%s.members.filter: %w", name, gname, err)
			}
			g.Filter = f
		}
		if len(g.Bases) == 0 && len(g.ADGroups) == 0 && len(g.Include) == 0 && g.Filter == nil {
			// No explicit source: every user of the profile is a member.
			g.Bases = append([]string(nil), r.Bases...)
		} else if len(g.Bases) == 0 && (g.Filter != nil) {
			g.Bases = append([]string(nil), r.Bases...)
		}
		r.groups = append(r.groups, g)
		r.groupByName[strings.ToLower(gname)] = g
	}
	return nil
}

func (r *Rules) compileHoneytokens(name string, p *config.Profile) error {
	tpls := map[string]string{}
	for k, v := range defaultHoneytokenTemplate {
		tpls[k] = v
	}
	for k, v := range p.HoneytokenTemplate {
		tpls[k] = v
	}
	keys := make([]string, 0, len(tpls))
	for k := range tpls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, account := range p.Honeytokens {
		account = strings.TrimSpace(account)
		if account == "" {
			continue
		}
		user, domain := account, ""
		if i := strings.IndexByte(account, '@'); i >= 0 {
			user, domain = account[:i], account[i+1:]
		}
		given, sn := splitName(user)
		data := map[string]string{"account": account, "user": user, "domain": domain, "given": given, "sn": sn}
		h := &Honeytoken{Account: account, User: user, Domain: domain, Attrs: map[string][]string{}}
		for _, k := range keys {
			tpl, err := ParseTemplate(k, tpls[k])
			if err != nil {
				return fmt.Errorf("profile %s: honeytoken_template.%s: %w", name, k, err)
			}
			var b strings.Builder
			if err := tpl.Execute(&b, data); err != nil {
				return fmt.Errorf("profile %s: honeytoken_template.%s: %w", name, k, err)
			}
			if v := strings.TrimSpace(b.String()); v != "" {
				h.Attrs[k] = []string{v}
			}
		}
		h.Attrs["objectClass"] = append([]string(nil), honeytokenObjectClasses...)
		sum := sha256.Sum256([]byte("aldap-honeytoken:" + strings.ToLower(account)))
		h.GUID = string(sum[:16])
		h.Attrs["objectGUID"] = []string{h.GUID}
		cn := user
		if v := h.Attrs["cn"]; len(v) > 0 {
			cn = v[0]
		}
		base := "ou=honeytokens"
		if len(r.Bases) > 0 {
			base = r.Bases[0]
		}
		h.DN = "CN=" + ldapfilter.EscapeRDNValue(cn) + "," + base
		h.Attrs["distinguishedName"] = []string{h.DN}
		r.honeytokens = append(r.honeytokens, h)
	}
	return nil
}

// splitName derives a given name and surname from an account's user part
// ("h.petrenko" → "H", "Petrenko"; "backup-admin" → "Backup", "Admin").
func splitName(user string) (given, sn string) {
	parts := strings.FieldsFunc(user, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	switch len(parts) {
	case 0:
		return "User", "Unknown"
	case 1:
		return title(parts[0]), "User"
	default:
		return title(parts[0]), title(parts[len(parts)-1])
	}
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Groups returns the virtual groups in name order.
func (r *Rules) Groups() []*Group { return r.groups }

// Group finds a virtual group by name (case-insensitive).
func (r *Rules) Group(name string) *Group { return r.groupByName[strings.ToLower(name)] }

// HasGroups reports whether the profile defines virtual groups.
func (r *Rules) HasGroups() bool { return len(r.groups) > 0 }

// Honeytokens returns the compiled trap accounts.
func (r *Rules) Honeytokens() []*Honeytoken { return r.honeytokens }

// MatchHoneytoken returns the honeytoken an account name targets: the UPN,
// the user part (sAMAccountName/uid), DOMAIN\user, or the rdn_attr value
// of the trap entry; nil when none.
func (r *Rules) MatchHoneytoken(account string) *Honeytoken {
	a := strings.TrimSpace(account)
	if a == "" {
		return nil
	}
	if i := strings.IndexByte(a, '\\'); i >= 0 {
		a = a[i+1:]
	}
	for _, h := range r.honeytokens {
		if strings.EqualFold(a, h.Account) || strings.EqualFold(a, h.User) {
			return h
		}
		for _, v := range h.Attrs[r.RDNAttr] {
			if strings.EqualFold(a, v) {
				return h
			}
		}
	}
	return nil
}

// HoneytokenValue reports the honeytoken whose upstream attribute attr
// equals value (identity attributes only, SPEC §4.5).
func (r *Rules) HoneytokenValue(attr, value string) *Honeytoken {
	switch strings.ToLower(attr) {
	case "samaccountname", "userprincipalname", "mail", "cn", "uid", "displayname", "name", "distinguishedname":
	default:
		return nil
	}
	for _, h := range r.honeytokens {
		for _, v := range h.Attrs[canonicalAttr(h.Attrs, attr)] {
			if strings.EqualFold(v, value) {
				return h
			}
		}
	}
	return nil
}

// canonicalAttr finds the key of attrs spelled like name, case-insensitively.
func canonicalAttr(attrs map[string][]string, name string) string {
	if _, ok := attrs[name]; ok {
		return name
	}
	for k := range attrs {
		if strings.EqualFold(k, name) {
			return k
		}
	}
	return name
}
