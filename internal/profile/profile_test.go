package profile

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

var fastArgon = Argon2Params{Time: 1, Memory: 1024, Threads: 1, KeyLen: 16, SaltLen: 8}

func testProfile() *config.Profile {
	p := config.DefaultProfile()
	p.Listen = []string{":636"}
	p.VirtualBase = "ou=virola,dc=aldap"
	p.Bases = []string{"OU=Office,DC=test,DC=aldap", "OU=Branch,DC=test,DC=aldap"}
	p.Filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	p.ExcludeFilter = "(sAMAccountName=svc-*)"
	p.RDNAttr = "sAMAccountName"
	p.Attrs.Allow = []string{"userPrincipalName", "sAMAccountName", "displayName", "mail", "objectGUID", "objectClass"}
	p.Attrs.Map = map[string]string{"uid": "sAMAccountName", "cn": "displayName"}
	p.ClientBind.DN = "cn=virola,ou=services,dc=aldap"
	p.UserBind.DefaultDomain = "test.aldap"
	return p
}

func compile(t *testing.T, p *config.Profile, pw string) *Rules {
	t.Helper()
	r, err := Compile("virola", p, &config.Upstream{Kind: "ad"}, Options{ClientPassword: pw, Argon2: fastArgon})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return r
}

func TestCompile_Errors(t *testing.T) {
	bad := func(mut func(p *config.Profile)) *config.Profile {
		p := testProfile()
		mut(p)
		return p
	}
	cases := map[string]*config.Profile{
		"nil-handled-below": nil,
		"bad-vb":            bad(func(p *config.Profile) { p.VirtualBase = "not a dn" }),
		"empty-vb":          bad(func(p *config.Profile) { p.VirtualBase = "" }),
		"bad-filter":        bad(func(p *config.Profile) { p.Filter = "(x=" }),
		"bad-exclude":       bad(func(p *config.Profile) { p.ExcludeFilter = "(" }),
		"star":              bad(func(p *config.Profile) { p.Attrs.Allow = []string{"*"} }),
		"bad-client-dn":     bad(func(p *config.Profile) { p.ClientBind.DN = "nope" }),
		"bad-hash":          bad(func(p *config.Profile) { p.ClientBind.PasswordHash = "$md5$x" }),
	}
	for name, p := range cases {
		if _, err := Compile("x", p, nil, Options{ClientPassword: "pw", Argon2: fastArgon}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Compile("x", testProfile(), nil, Options{}); err == nil {
		t.Error("client_bind.dn without password must fail")
	}
	// Without client bind and with defaults filled in.
	p := testProfile()
	p.ClientBind.DN = ""
	p.RDNAttr = ""
	r, err := Compile("x", p, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.HasClientBind() || r.RDNAttr != "cn" || r.Kind != "ad" || r.VerifyClientPassword([]byte("x")) {
		t.Errorf("defaults: %+v", r)
	}
}

func TestClientBind(t *testing.T) {
	r := compile(t, testProfile(), "S3CR3T-client")
	dn, _ := ldapfilter.ParseDN("CN=virola, OU=services, DC=aldap")
	if !r.HasClientBind() || !r.IsClientBindDN(dn) || r.IsClientBindDN(nil) {
		t.Error("client bind dn")
	}
	other, _ := ldapfilter.ParseDN("cn=other,ou=services,dc=aldap")
	if r.IsClientBindDN(other) {
		t.Error("other dn matched")
	}
	if !r.VerifyClientPassword([]byte("S3CR3T-client")) || r.VerifyClientPassword([]byte("S3CR3T-clienT")) || r.VerifyClientPassword(nil) {
		t.Error("password verification")
	}
	// password_hash form.
	h, err := HashPassword([]byte("from-hash"), fastArgon)
	if err != nil {
		t.Fatal(err)
	}
	p := testProfile()
	p.ClientBind.PasswordHash = h.String()
	r2 := compile(t, p, "")
	if !r2.VerifyClientPassword([]byte("from-hash")) || r2.VerifyClientPassword([]byte("wrong")) {
		t.Error("hash form verification")
	}
}

func TestArgon2_PHC(t *testing.T) {
	h, err := HashPassword([]byte("pw"), fastArgon)
	if err != nil {
		t.Fatal(err)
	}
	s := h.String()
	if !strings.HasPrefix(s, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Errorf("phc = %s", s)
	}
	back, err := ParsePasswordHash(s)
	if err != nil {
		t.Fatal(err)
	}
	if back.Params() != h.Params() || !back.Verify([]byte("pw")) || back.Verify([]byte("pw2")) || back.String() != s {
		t.Error("round trip")
	}
	if _, err := HashPassword([]byte("pw"), Argon2Params{}); err == nil {
		t.Error("zero params")
	}
	for _, bad := range []string{
		"", "$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=18$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1,x=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=999$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$!!$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$c2hvcnQ",
		"$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$!!",
		"$argon2id$v=19$m,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
	} {
		if _, err := ParsePasswordHash(bad); !errors.Is(err, ErrBadHash) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestAttrs(t *testing.T) {
	r := compile(t, testProfile(), "pw")
	if got := strings.Join(r.AllowedAttrs(), ","); got != "userPrincipalName,sAMAccountName,displayName,mail,objectGUID,objectClass,cn,uid" &&
		got != "userPrincipalName,sAMAccountName,displayName,mail,objectGUID,objectClass,uid,cn" {
		t.Errorf("allowed = %s", got)
	}
	if !r.IsAllowed("MAIL") || !r.IsAllowed("uid") || r.IsAllowed("telephoneNumber") {
		t.Error("IsAllowed")
	}
	if r.UpstreamAttr("UID") != "sAMAccountName" || r.UpstreamAttr("mail") != "mail" || r.UpstreamAttr("telephoneNumber") != "telephoneNumber" {
		t.Error("UpstreamAttr")
	}
	got := r.ClientAttrs("samaccountname")
	sort.Strings(got)
	if strings.Join(got, ",") != "sAMAccountName,uid" {
		t.Errorf("ClientAttrs(sAMAccountName) = %v", got)
	}
	if c := r.ClientAttrs("displayName"); len(c) != 2 {
		t.Errorf("ClientAttrs(displayName) = %v", c)
	}
	if c := r.ClientAttrs("telephoneNumber"); c != nil {
		t.Errorf("ClientAttrs(telephoneNumber) = %v", c)
	}
	if m := r.AttrMap(); m["uid"] != "sAMAccountName" || len(m) != 2 {
		t.Errorf("AttrMap = %v", m)
	}
	for attr, want := range map[string]ldapfilter.Class{
		"objectClass": ldapfilter.Upstream, "OBJECTCLASS": ldapfilter.Upstream, "mail": ldapfilter.Upstream, "uid": ldapfilter.Upstream,
		"mail;binary": ldapfilter.Upstream, "telephoneNumber": ldapfilter.Denied, "": ldapfilter.Denied, ";x": ldapfilter.Denied,
	} {
		if r.Classify(attr) != want {
			t.Errorf("Classify(%q) = %v, want %v", attr, r.Classify(attr), want)
		}
	}
}

func TestClassifyBase(t *testing.T) {
	r := compile(t, testProfile(), "pw")
	cases := []struct {
		base string
		kind BaseKind
		rdn  string
		err  bool
	}{
		{"", BaseRootDSE, "", false},
		{"  ", BaseRootDSE, "", false},
		{"cn=Subschema", BaseSubschema, "", false},
		{"CN=SUBSCHEMA", BaseSubschema, "", false},
		{"ou=virola,dc=aldap", BaseVirtual, "", false},
		{"OU=Virola, DC=Aldap", BaseVirtual, "", false},
		{"ou=users,ou=virola,dc=aldap", BaseUsers, "", false},
		{"ou=groups,ou=virola,dc=aldap", BaseGroups, "", false},
		{"cn=alice.adams,ou=users,ou=virola,dc=aldap", BaseUser, "alice.adams", false},
		{"cn=Adams\\, Alice,ou=users,ou=virola,dc=aldap", BaseUser, "Adams, Alice", false},
		{"cn=staff,ou=groups,ou=virola,dc=aldap", BaseGroup, "staff", false},
		{"uid=x,ou=users,ou=virola,dc=aldap", BaseOutside, "", false},
		{"cn=x,cn=y,ou=users,ou=virola,dc=aldap", BaseOutside, "", false},
		{"ou=other,ou=virola,dc=aldap", BaseOutside, "", false},
		{"dc=aldap", BaseOutside, "", false},
		{"DC=test,DC=aldap", BaseOutside, "", false},
		{"not a dn", BaseOutside, "", true},
	}
	for _, tc := range cases {
		kind, rdn, err := r.ClassifyBase(tc.base)
		if kind != tc.kind || rdn != tc.rdn || (err != nil) != tc.err {
			t.Errorf("ClassifyBase(%q) = %v %q %v, want %v %q err=%v", tc.base, kind, rdn, err, tc.kind, tc.rdn, tc.err)
		}
	}
	if r.UserDN("a,b") != "cn=a\\,b,ou=users,ou=virola,dc=aldap" || r.GroupDN("g") != "cn=g,ou=groups,ou=virola,dc=aldap" {
		t.Errorf("UserDN=%s GroupDN=%s", r.UserDN("a,b"), r.GroupDN("g"))
	}
	for k := BaseOutside; k <= BaseGroup; k++ {
		if k.String() == "" {
			t.Error("empty kind name")
		}
	}
}

func TestNormalizeBindName(t *testing.T) {
	r := compile(t, testProfile(), "pw")
	cases := []struct {
		in   string
		want BindName
	}{
		{"alice.adams@test.aldap", BindName{Form: FormUPN, Upstream: "alice.adams@test.aldap", Account: "alice.adams@test.aldap"}},
		{`TEST\alice.adams`, BindName{Form: FormDomain, Upstream: "alice.adams@test.aldap", Account: "alice.adams"}},
		{"alice.adams", BindName{Form: FormAccount, Upstream: "alice.adams@test.aldap", Account: "alice.adams"}},
		{" alice.adams ", BindName{Form: FormAccount, Upstream: "alice.adams@test.aldap", Account: "alice.adams"}},
		{"cn=alice.adams,ou=users,ou=virola,dc=aldap", BindName{Form: FormVirtualDN, RDN: "alice.adams", Account: "alice.adams"}},
		{"CN=Alice Adams,OU=Office,DC=test,DC=aldap", BindName{Form: FormOtherDN, Account: "CN=Alice Adams,OU=Office,DC=test,DC=aldap"}},
		{"cn=x,ou=groups,ou=virola,dc=aldap", BindName{Form: FormOtherDN, Account: "cn=x,ou=groups,ou=virola,dc=aldap"}},
		{"a=b,c", BindName{Form: FormAccount, Upstream: "a=b,c@test.aldap", Account: "a=b,c"}},
	}
	for _, tc := range cases {
		if got := r.NormalizeBindName(tc.in); got != tc.want {
			t.Errorf("NormalizeBindName(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
	// Without default_domain names pass through.
	p := testProfile()
	p.UserBind.DefaultDomain = ""
	r2 := compile(t, p, "pw")
	if got := r2.NormalizeBindName(`TEST\bob`); got.Upstream != `TEST\bob` || got.Account != "bob" {
		t.Errorf("domain form without default domain = %+v", got)
	}
	if got := r2.NormalizeBindName("bob"); got.Upstream != "bob" {
		t.Errorf("bare without default domain = %+v", got)
	}
}
