// Package profile compiles one [profile.<name>] table into the runtime rules
// the virtual directory applies: virtual base, upstream bases, mandatory and
// exclude filters, attribute allowlist and renames, bind policy (SPEC §3.4,
// §4.2, §4.3).
package profile

import (
	"errors"
	"fmt"
	"strings"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

// Container RDNs of the virtual tree (SPEC §4.1).
const (
	UsersOU  = "users"
	GroupsOU = "groups"
	// Subschema is the DN of the minimal schema entry.
	Subschema = "cn=Subschema"
)

// Rules are the compiled, immutable rules of one profile.
type Rules struct {
	Name string
	// Kind is the upstream kind: ad or generic.
	Kind string
	// VirtualBase is the DN clients see; UsersBase and GroupsBase are its children.
	VirtualBase *ldapfilter.DN
	UsersBase   *ldapfilter.DN
	GroupsBase  *ldapfilter.DN
	// Bases are the real upstream subtrees.
	Bases []string
	// Filter is AND-ed to every client filter; Exclude is NOT-ed (nil = none).
	Filter  *ldapfilter.Filter
	Exclude *ldapfilter.Filter
	// RDNAttr is the upstream attribute whose value becomes the virtual RDN.
	RDNAttr string
	// Limits of the profile.
	Limits config.Limits
	// UserBind policy and anonymous bind flag.
	UserBind      config.UserBind
	AnonymousBind bool
	// ClientBindDN is the service login of the application (nil = none).
	ClientBindDN *ldapfilter.DN
	clientHash   *PasswordHash

	allow   map[string]string // lower client name → canonical client name
	toUp    map[string]string // lower client name → upstream name (attrs.map)
	fromUp  map[string][]string
	allowed []string
}

// Options tune Compile.
type Options struct {
	// ClientPassword is the resolved client_bind password ("" when none).
	ClientPassword string
	// Argon2 overrides the hash cost (tests); zero = DefaultArgon2.
	Argon2 Argon2Params
}

// Compile builds the rules of profile name from its validated configuration.
func Compile(name string, p *config.Profile, u *config.Upstream, o Options) (*Rules, error) {
	if p == nil {
		return nil, errors.New("profile: nil config")
	}
	r := &Rules{Name: name, Bases: append([]string(nil), p.Bases...), RDNAttr: p.RDNAttr, Limits: p.Limits,
		UserBind: p.UserBind, AnonymousBind: p.AnonymousBind, allow: map[string]string{}, toUp: map[string]string{}, fromUp: map[string][]string{}}
	if u != nil {
		r.Kind = u.Kind
	}
	if r.Kind == "" {
		r.Kind = "ad"
	}
	if r.RDNAttr == "" {
		r.RDNAttr = "cn"
	}
	var err error
	if r.VirtualBase, err = ldapfilter.ParseDN(p.VirtualBase); err != nil {
		return nil, fmt.Errorf("profile %s: virtual_base: %w", name, err)
	}
	if len(r.VirtualBase.RDNs) == 0 {
		return nil, fmt.Errorf("profile %s: virtual_base must not be empty", name)
	}
	r.UsersBase = r.VirtualBase.Child(ldapfilter.RDN{AVAs: []ldapfilter.AVA{{Type: "ou", Value: UsersOU}}})
	r.GroupsBase = r.VirtualBase.Child(ldapfilter.RDN{AVAs: []ldapfilter.AVA{{Type: "ou", Value: GroupsOU}}})
	if p.Filter != "" {
		if r.Filter, err = ldapfilter.Parse(p.Filter); err != nil {
			return nil, fmt.Errorf("profile %s: filter: %w", name, err)
		}
	}
	if p.ExcludeFilter != "" {
		if r.Exclude, err = ldapfilter.Parse(p.ExcludeFilter); err != nil {
			return nil, fmt.Errorf("profile %s: exclude_filter: %w", name, err)
		}
	}
	if err := r.compileAttrs(name, p.Attrs); err != nil {
		return nil, err
	}
	if err := r.compileClientBind(name, p.ClientBind, o); err != nil {
		return nil, err
	}
	return r, nil
}

// compileAttrs builds the allow and rename tables.
func (r *Rules) compileAttrs(name string, a config.Attrs) error {
	p := &config.Profile{Attrs: a}
	for _, a := range p.Attrs.Allow {
		if a == "*" {
			return fmt.Errorf("profile %s: attrs.allow: '*' is not allowed", name)
		}
		l := strings.ToLower(a)
		if _, dup := r.allow[l]; !dup {
			r.allow[l] = a
			r.allowed = append(r.allowed, a)
		}
	}
	for client, up := range p.Attrs.Map {
		l := strings.ToLower(client)
		if _, dup := r.allow[l]; !dup {
			r.allow[l] = client
			r.allowed = append(r.allowed, client)
		}
		r.toUp[l] = up
		r.fromUp[strings.ToLower(up)] = append(r.fromUp[strings.ToLower(up)], client)
	}
	for _, a := range p.Attrs.Allow {
		l := strings.ToLower(a)
		if _, mapped := r.toUp[l]; !mapped {
			r.fromUp[l] = append(r.fromUp[l], a)
		}
	}
	return nil
}

// compileClientBind parses client_bind.dn and prepares the password hash.
func (r *Rules) compileClientBind(name string, cb config.ClientBind, o Options) error {
	p := &config.Profile{ClientBind: cb}
	var err error
	if p.ClientBind.DN != "" {
		if r.ClientBindDN, err = ldapfilter.ParseDN(p.ClientBind.DN); err != nil {
			return fmt.Errorf("profile %s: client_bind.dn: %w", name, err)
		}
		switch {
		case p.ClientBind.PasswordHash != "":
			if r.clientHash, err = ParsePasswordHash(p.ClientBind.PasswordHash); err != nil {
				return fmt.Errorf("profile %s: client_bind.password_hash: %w", name, err)
			}
		case o.ClientPassword != "":
			params := o.Argon2
			if params.Time == 0 {
				params = DefaultArgon2
			}
			if r.clientHash, err = HashPassword([]byte(o.ClientPassword), params); err != nil {
				return fmt.Errorf("profile %s: client_bind.password: %w", name, err)
			}
		default:
			return fmt.Errorf("profile %s: client_bind.dn is set but no password or password_hash", name)
		}
	}
	return nil
}

// HasClientBind reports whether the profile has a service login.
func (r *Rules) HasClientBind() bool { return r.ClientBindDN != nil && r.clientHash != nil }

// IsClientBindDN reports whether dn is the configured client_bind.dn.
func (r *Rules) IsClientBindDN(dn *ldapfilter.DN) bool {
	return r.ClientBindDN != nil && dn != nil && dn.Equal(r.ClientBindDN)
}

// VerifyClientPassword checks a client_bind password in constant time.
func (r *Rules) VerifyClientPassword(password []byte) bool {
	return r.clientHash != nil && r.clientHash.Verify(password)
}

// AllowedAttrs returns the client attribute names that may be returned, in
// configuration order (attrs.allow followed by attrs.map keys).
func (r *Rules) AllowedAttrs() []string { return append([]string(nil), r.allowed...) }

// IsAllowed reports whether a client attribute name may be returned.
func (r *Rules) IsAllowed(client string) bool {
	_, ok := r.allow[strings.ToLower(client)]
	return ok
}

// UpstreamAttr maps a client attribute name to its upstream name (attrs.map);
// names without a mapping are returned unchanged.
func (r *Rules) UpstreamAttr(client string) string {
	if up, ok := r.toUp[strings.ToLower(client)]; ok {
		return up
	}
	return client
}

// ClientAttrs returns the client names an upstream attribute is exposed as
// (several when it is both allowed directly and mapped); nil when none.
func (r *Rules) ClientAttrs(upstream string) []string {
	return r.fromUp[strings.ToLower(upstream)]
}

// AttrMap returns the client → upstream rename table for ldapfilter.MapAttrs.
func (r *Rules) AttrMap() map[string]string {
	out := make(map[string]string, len(r.toUp))
	for k, v := range r.toUp {
		out[k] = v
	}
	return out
}

// Classify says where a filter term on attr can be evaluated: allowed or
// mapped attributes (and objectClass, which every client uses) go upstream;
// everything else is denied and becomes absolute false (SPEC §4.2 step 3).
func (r *Rules) Classify(attr string) ldapfilter.Class {
	l := strings.ToLower(attr)
	if l == "objectclass" {
		return ldapfilter.Upstream
	}
	if _, ok := r.allow[l]; ok {
		return ldapfilter.Upstream
	}
	if i := strings.IndexByte(l, ';'); i > 0 {
		if _, ok := r.allow[l[:i]]; ok {
			return ldapfilter.Upstream
		}
	}
	return ldapfilter.Denied
}

// BaseKind classifies a search base against the virtual tree.
type BaseKind int

// Base kinds (SPEC §4.2 step 2).
const (
	BaseOutside BaseKind = iota
	BaseRootDSE
	BaseSubschema
	BaseVirtual
	BaseUsers
	BaseGroups
	BaseUser
	BaseGroup
)

// String names the kind for diagnostics.
func (k BaseKind) String() string {
	return [...]string{"outside", "rootdse", "subschema", "virtual_base", "users", "groups", "user", "group"}[k]
}

// ClassifyBase parses base and places it in the virtual tree. For BaseUser
// and BaseGroup, rdn is the leaf value (the rdn_attr value or group name).
func (r *Rules) ClassifyBase(base string) (kind BaseKind, rdn string, err error) {
	if strings.TrimSpace(base) == "" {
		return BaseRootDSE, "", nil
	}
	dn, err := ldapfilter.ParseDN(base)
	if err != nil {
		return BaseOutside, "", err
	}
	if len(dn.RDNs) == 1 && len(dn.RDNs[0].AVAs) == 1 && strings.EqualFold(dn.RDNs[0].AVAs[0].Type, "cn") &&
		strings.EqualFold(dn.RDNs[0].AVAs[0].Value, "subschema") {
		return BaseSubschema, "", nil
	}
	switch {
	case dn.Equal(r.VirtualBase):
		return BaseVirtual, "", nil
	case dn.Equal(r.UsersBase):
		return BaseUsers, "", nil
	case dn.Equal(r.GroupsBase):
		return BaseGroups, "", nil
	}
	if !dn.IsUnder(r.VirtualBase) {
		return BaseOutside, "", nil
	}
	parent := dn.Parent()
	leaf := dn.RDN()
	if parent != nil && len(leaf.AVAs) >= 1 && strings.EqualFold(leaf.AVAs[0].Type, "cn") {
		switch {
		case parent.Equal(r.UsersBase):
			return BaseUser, leaf.AVAs[0].Value, nil
		case parent.Equal(r.GroupsBase):
			return BaseGroup, leaf.AVAs[0].Value, nil
		}
	}
	return BaseOutside, "", nil
}

// UserDN builds the virtual DN of a user from its rdn_attr value.
func (r *Rules) UserDN(rdnValue string) string {
	return r.UsersBase.Child(ldapfilter.RDN{AVAs: []ldapfilter.AVA{{Type: "cn", Value: rdnValue}}}).String()
}

// GroupDN builds the virtual DN of a group.
func (r *Rules) GroupDN(name string) string {
	return r.GroupsBase.Child(ldapfilter.RDN{AVAs: []ldapfilter.AVA{{Type: "cn", Value: name}}}).String()
}

// BindForm is how a user bind name was presented (SPEC §4.3).
type BindForm string

// Bind name forms.
const (
	FormUPN       BindForm = "upn"
	FormDomain    BindForm = "domain"
	FormAccount   BindForm = "account"
	FormVirtualDN BindForm = "virtual_dn"
	FormOtherDN   BindForm = "other_dn"
)

// BindName is a normalized user bind name.
type BindName struct {
	Form BindForm
	// Upstream is the name sent to the upstream (UPN or DOMAIN\user); empty
	// for FormVirtualDN, which is resolved through a search first.
	Upstream string
	// Account is the bare account part (for lookups and events).
	Account string
	// RDN is the virtual RDN value for FormVirtualDN.
	RDN string
}

// NormalizeBindName classifies and rewrites a bind name (SPEC §4.3): UPN as
// is, DOMAIN\user → user@default_domain when set, bare account →
// account@default_domain when set, a DN under the virtual base → RDN
// lookup, any other DN → FormOtherDN (refused by the caller).
func (r *Rules) NormalizeBindName(name string) BindName {
	name = strings.TrimSpace(name)
	if strings.ContainsAny(name, "=,") {
		if kind, rdn, err := r.ClassifyBase(name); err == nil && kind == BaseUser {
			return BindName{Form: FormVirtualDN, RDN: rdn, Account: rdn}
		}
		if _, err := ldapfilter.ParseDN(name); err == nil {
			return BindName{Form: FormOtherDN, Account: name}
		}
	}
	if strings.Contains(name, "@") {
		return BindName{Form: FormUPN, Upstream: name, Account: name}
	}
	if i := strings.IndexByte(name, '\\'); i >= 0 {
		acct := name[i+1:]
		up := name
		if r.UserBind.DefaultDomain != "" {
			up = acct + "@" + r.UserBind.DefaultDomain
		}
		return BindName{Form: FormDomain, Upstream: up, Account: acct}
	}
	up := name
	if r.UserBind.DefaultDomain != "" {
		up = name + "@" + r.UserBind.DefaultDomain
	}
	return BindName{Form: FormAccount, Upstream: up, Account: name}
}
