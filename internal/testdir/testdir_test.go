package testdir

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

const (
	base   = "DC=test,DC=aldap"
	svcDN  = "CN=svc-aldap,CN=Users,DC=test,DC=aldap"
	svcPW  = "svc-aldap-pass"
	diagAD = "AcceptSecurityContext error, data "
)

func dial(t *testing.T, s *Server) *ldap.Conn {
	t.Helper()
	var opts []ldap.DialOpt
	if s.scheme == "ldaps" {
		opts = append(opts, ldap.DialWithTLSConfig(s.ClientTLS()))
	}
	c, err := ldap.DialURL(s.URL(), opts...)
	if err != nil {
		t.Fatalf("dial %s: %v", s.URL(), err)
	}
	t.Cleanup(func() { _ = c.Close() })
	c.SetTimeout(5 * time.Second)
	return c
}

func bound(t *testing.T, s *Server) *ldap.Conn {
	t.Helper()
	c := dial(t, s)
	if err := c.Bind(svcDN, svcPW); err != nil {
		t.Fatalf("service bind: %v", err)
	}
	return c
}

func search(t *testing.T, c *ldap.Conn, baseDN string, scope int, filter string, attrs ...string) *ldap.SearchResult {
	t.Helper()
	res, err := c.Search(ldap.NewSearchRequest(baseDN, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
	if err != nil {
		t.Fatalf("search %s: %v", filter, err)
	}
	return res
}

func TestParseLDIF_Fixture(t *testing.T) {
	entries, err := LoadLDIF(FixturePath())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 46 {
		t.Fatalf("entries = %d, want 46", len(entries))
	}
	var users, disabled, computers int
	for _, e := range entries {
		classes := e.Get("objectClass")
		isUser, isComputer := false, false
		for _, c := range classes {
			switch c {
			case "user":
				isUser = true
			case "computer":
				isComputer = true
			}
		}
		if isComputer {
			computers++
			continue
		}
		if isUser {
			users++
			if e.First("userAccountControl") == "514" {
				disabled++
			}
		}
		if len(e.First("objectGUID")) != 16 {
			t.Errorf("%s: objectGUID length %d", e.DN, len(e.First("objectGUID")))
		}
	}
	if users != 25 || disabled != 3 || computers != 6 {
		t.Fatalf("users=%d disabled=%d computers=%d", users, disabled, computers)
	}
}

func TestParseLDIF_Cases(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string
		wantDN  string
		wantCN  string
	}{
		{name: "continuation", in: "dn: cn=a,dc=x\ncn: a\ndescription: long\n  line\n", wantDN: "cn=a,dc=x", wantCN: "a"},
		{name: "base64", in: "dn:: Y249YixkYz14\ncn:: Yg==\n", wantDN: "cn=b,dc=x", wantCN: "b"},
		{name: "comment_and_version", in: "version: 1\n# c\ndn: cn=c,dc=x\ncn: c\n", wantDN: "cn=c,dc=x", wantCN: "c"},
		{name: "attr_before_dn", in: "cn: x\ndn: cn=x,dc=x\n", wantErr: "before dn"},
		{name: "changetype", in: "dn: cn=x,dc=x\nchangetype: modify\n", wantErr: "change records"},
		{name: "bad_dn", in: "dn: not a dn\ncn: x\n", wantErr: "syntax"},
		{name: "malformed", in: "dn: cn=x,dc=x\nnocolon\n", wantErr: "malformed"},
		{name: "bad_base64", in: "dn: cn=x,dc=x\ncn:: %%%\n", wantErr: "illegal base64"},
		{name: "url", in: "dn: cn=x,dc=x\ncn:< file:///x\n", wantErr: "URL values"},
		{name: "dup_dn", in: "dn: cn=x,dc=x\ndn: cn=y,dc=x\n", wantErr: "duplicate dn"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			es, err := ParseLDIF(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || len(es) != 1 || es[0].DN != tc.wantDN || es[0].First("cn") != tc.wantCN {
				t.Fatalf("got %v, %v", es, err)
			}
		})
	}
}

func TestDirectory_Ops(t *testing.T) {
	d, err := NewDirectory(&Entry{DN: "dc=x"}, &Entry{DN: "cn=a,dc=x"}, &Entry{DN: "cn=b,cn=a,dc=x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectory(&Entry{DN: "dc=x"}, &Entry{DN: "DC=X"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := NewDirectory(&Entry{DN: "bad"}); err == nil {
		t.Fatal("bad dn accepted")
	}
	if d.BaseDN() != "dc=x" || d.Len() != 3 || d.Lookup("CN=A, DC=X") == nil || d.Lookup("nope") != nil || d.Lookup("cn=z,dc=x") != nil {
		t.Fatalf("store state wrong: base=%q len=%d", d.BaseDN(), d.Len())
	}
	all := ldapfilter.True()
	for _, tc := range []struct {
		base  string
		scope Scope
		want  int
	}{
		{"dc=x", ScopeBase, 1}, {"dc=x", ScopeOne, 1}, {"dc=x", ScopeSub, 3}, {"cn=a,dc=x", ScopeOne, 1}, {"cn=b,cn=a,dc=x", ScopeOne, 0},
	} {
		got, err := d.Search(tc.base, tc.scope, all)
		if err != nil || len(got) != tc.want {
			t.Errorf("search %s/%d: %d, %v (want %d)", tc.base, tc.scope, len(got), err, tc.want)
		}
	}
	if _, err := d.Search("cn=missing,dc=x", ScopeSub, all); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("missing base err = %v", err)
	}
	if _, err := d.Search("??", ScopeSub, all); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("bad base err = %v", err)
	}
	e := &Entry{DN: "cn=a,dc=x"}
	e.Set("description", "new")
	if err := d.Upsert(e); err != nil || d.Len() != 3 || d.Lookup("cn=a,dc=x").First("description") != "new" {
		t.Fatalf("upsert: %v", err)
	}
	if err := d.Upsert(&Entry{DN: "zzz"}); err == nil {
		t.Fatal("upsert of bad dn accepted")
	}
	c := e.Clone()
	c.Add("description", "more")
	c.Add("fresh", "1")
	if len(e.Get("description")) != 1 || len(c.Get("description")) != 2 || !c.Has("fresh") || e.First("missing") != "" {
		t.Fatal("clone shares state")
	}
}

func TestMatch_Filters(t *testing.T) {
	s := StartFixture(t)
	c := bound(t, s)
	tests := []struct {
		filter string
		want   int
	}{
		{"(objectClass=*)", 46},
		{"(&(objectCategory=person)(objectClass=user))", 25},
		{"(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", 22},
		{"(userAccountControl:1.2.840.113556.1.4.804:=514)", 25},
		{"(objectClass=computer)", 6},
		{"(objectCategory=CN=Person,CN=Schema,CN=Configuration,DC=test,DC=aldap)", 25},
		{"(objectCategory=computer)", 6},
		{"(sAMAccountName=alice.adams)", 1},
		{"(SAMACCOUNTNAME=ALICE.ADAMS)", 1},
		{"(sAMAccountName=*.adams)", 1},
		{"(mail=a*ad*aldap)", 1},
		{"(cn=*Adams)", 1},
		{"(cn=Alice*)", 1},
		{"(cn~=alice adams)", 1},
		{"(userAccountControl>=514)", 10},
		{"(userAccountControl<=512)", 21},
		{"(title>=Manager)", 9},
		{"(memberOf=cn=directors,cn=users,dc=test,dc=aldap)", 2},
		{"(memberOf=CN=Directors, CN=Users, DC=test, DC=aldap)", 2},
		{"(memberOf:1.2.840.113556.1.4.1941:=CN=Staff,CN=Users,DC=test,DC=aldap)", 21},
		{"(member:1.2.840.113556.1.4.1941:=CN=Alice Adams,OU=Office,DC=test,DC=aldap)", 4},
		{"(member:1.2.840.113556.1.4.1941:=not a dn)", 0},
		{"(foo:1.2.840.113556.1.4.1941:=CN=Staff,CN=Users,DC=test,DC=aldap)", 0},
		{"(userAccountControl:1.2.840.113556.1.4.803:=x)", 0},
		{"(cn:caseExactMatch:=Alice Adams)", 0},
		{"(cn:=Alice Adams)", 1},
		{"(|(cn=Alice Adams)(cn=Bob Brown))", 2},
		{"(!(objectClass=user))", 15},
		{"(&)", 46},
		{"(|)", 0},
		{"(nonexistent=*)", 0},
		{"(userPassword=alice.adams-pass)", 1},
	}
	for _, tc := range tests {
		t.Run(tc.filter, func(t *testing.T) {
			res := search(t, c, base, ldap.ScopeWholeSubtree, tc.filter, "cn")
			if len(res.Entries) != tc.want {
				t.Fatalf("got %d entries, want %d", len(res.Entries), tc.want)
			}
		})
	}
	res := search(t, c, base, ldap.ScopeWholeSubtree, "(sAMAccountName=alice.adams)")
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("userPassword") != "" || len(res.Entries[0].GetRawAttributeValue("objectGUID")) != 16 {
		t.Fatalf("password leaked or guid missing: %+v", res.Entries)
	}
	if got := search(t, c, base, ldap.ScopeWholeSubtree, "(sAMAccountName=alice.adams)", "1.1").Entries[0].Attributes; len(got) != 0 {
		t.Fatalf("1.1 returned attributes: %v", got)
	}
	if got := search(t, c, base, ldap.ScopeWholeSubtree, "(sAMAccountName=alice.adams)", "MAIL", "distinguishedName").Entries[0]; got.GetAttributeValue("mail") == "" || got.GetAttributeValue("distinguishedName") != got.DN {
		t.Fatalf("selected attributes wrong: %+v", got)
	}
}

func TestSearch_ScopesAndErrors(t *testing.T) {
	s := StartFixture(t)
	c := bound(t, s)
	if n := len(search(t, c, "OU=Office,"+base, ldap.ScopeSingleLevel, "(objectClass=user)").Entries); n != 14 {
		t.Fatalf("one-level office = %d", n)
	}
	if n := len(search(t, c, "OU=Office,"+base, ldap.ScopeBaseObject, "(objectClass=*)").Entries); n != 1 {
		t.Fatalf("base office = %d", n)
	}
	_, err := c.Search(ldap.NewSearchRequest("OU=Nope,"+base, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=*)", nil, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("missing base: %v", err)
	}
	_, err = c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(my_attr=1)", nil, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Fatalf("bad filter: %v", err)
	}
	_, err = c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, 0, 3, 0, false, "(objectClass=user)", nil, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		t.Fatalf("size limit: %v", err)
	}
}

func TestSearch_UnboundDenied(t *testing.T) {
	s := StartFixture(t)
	c := dial(t, s)
	_, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", nil, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultOperationsError) {
		t.Fatalf("unbound search: %v", err)
	}
	root := search(t, c, "", ldap.ScopeBaseObject, "(objectClass=*)", "*")
	if len(root.Entries) != 1 || root.Entries[0].GetAttributeValue("defaultNamingContext") != base {
		t.Fatalf("rootDSE: %+v", root.Entries)
	}
	if n := len(search(t, c, "", ldap.ScopeBaseObject, "(vendorName=other)").Entries); n != 0 {
		t.Fatalf("rootDSE filter ignored: %d", n)
	}
	if calls := s.Calls(); calls.RootDSE != 2 || calls.Searches != 3 || calls.Conns != 1 {
		t.Fatalf("counts = %+v", calls)
	}
	anon := Start(t, WithDirectory(s.Dir), WithAnonymousSearch())
	if n := len(search(t, dial(t, anon), base, ldap.ScopeBaseObject, "(objectClass=*)").Entries); n != 1 {
		t.Fatalf("anonymous search = %d", n)
	}
}

func TestBind_ADCodes(t *testing.T) {
	s := StartFixture(t)
	tests := []struct {
		name, user, pass, data string
		ok                     bool
	}{
		{name: "dn", user: svcDN, pass: svcPW, ok: true},
		{name: "upn", user: "alice.adams@test.aldap", pass: "alice.adams-pass", ok: true},
		{name: "netbios", user: `TEST\alice.adams`, pass: "alice.adams-pass", ok: true},
		{name: "sam", user: "alice.adams", pass: "alice.adams-pass", ok: true},
		{name: "dn_case", user: "cn=alice adams,ou=office,dc=test,dc=aldap", pass: "alice.adams-pass", ok: true},
		{name: "bad_password", user: "alice.adams", pass: "nope", data: ADDataBadPassword},
		{name: "unknown", user: "nobody", pass: "x", data: ADDataNoSuchUser},
		{name: "unknown_upn", user: "nobody@test.aldap", pass: "x", data: ADDataNoSuchUser},
		{name: "disabled", user: "carol.clark", pass: "carol.clark-pass", data: ADDataDisabled},
		{name: "locked", user: "eve.evans", pass: "eve.evans-pass", data: ADDataLocked},
		{name: "must_change", user: "leo.lewis", pass: "leo.lewis-pass", data: ADDataMustChange},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := dial(t, s)
			err := c.Bind(tc.user, tc.pass)
			if tc.ok {
				if err != nil {
					t.Fatalf("bind: %v", err)
				}
				return
			}
			if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || !strings.Contains(err.Error(), diagAD+tc.data) {
				t.Fatalf("err = %v, want data %s", err, tc.data)
			}
		})
	}
	t.Run("expired", func(t *testing.T) {
		e := s.Dir.Lookup("CN=Bob Brown,OU=Office," + base).Clone()
		e.Set("accountExpires", "116444736000000000") // 1970-01-01
		if err := s.Dir.Upsert(e); err != nil {
			t.Fatal(err)
		}
		err := dial(t, s).Bind("bob.brown", "bob.brown-pass")
		if err == nil || !strings.Contains(err.Error(), diagAD+ADDataAccountExpired) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("anonymous_and_unauthenticated", func(t *testing.T) {
		c := dial(t, s)
		if err := c.UnauthenticatedBind(""); err != nil {
			t.Fatalf("anonymous: %v", err)
		}
		if err := c.UnauthenticatedBind("alice.adams"); err != nil {
			t.Fatalf("unauthenticated: %v", err)
		}
		_, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", nil, nil))
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultOperationsError) {
			t.Fatalf("anonymous may not search: %v", err)
		}
	})
	t.Run("plain_codes", func(t *testing.T) {
		p := Start(t, WithDirectory(s.Dir), WithADBindCodes(false))
		err := dial(t, p).Bind("alice.adams", "nope")
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || strings.Contains(err.Error(), diagAD) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSearch_Paging(t *testing.T) {
	s := StartFixture(t, WithMaxPageSize(10))
	c := bound(t, s)
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=user)", []string{"cn"}, nil)
	res, err := c.SearchWithPaging(req, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 31 || s.Calls().Searches != 4 {
		t.Fatalf("entries=%d searches=%d", len(res.Entries), s.Calls().Searches)
	}
	// Manual control: abandon and bad cookie.
	ctl := ldap.NewControlPaging(0)
	ctl.SetCookie([]byte("10"))
	req.Controls = []ldap.Control{ctl}
	if _, err := c.Search(req); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	ctl = ldap.NewControlPaging(5)
	ctl.SetCookie([]byte("bogus"))
	req.Controls = []ldap.Control{ctl}
	if _, err := c.Search(req); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		t.Fatalf("bad cookie: %v", err)
	}
}

func TestServer_StartTLSAndLDAPS(t *testing.T) {
	plain := StartFixture(t)
	c := dial(t, plain)
	if err := c.StartTLS(plain.ClientTLS()); err != nil {
		t.Fatalf("starttls: %v", err)
	}
	if err := c.Bind(svcDN, svcPW); err != nil {
		t.Fatalf("bind over starttls: %v", err)
	}
	if err := c.StartTLS(plain.ClientTLS()); err == nil {
		t.Fatal("second StartTLS accepted")
	}
	secure := Start(t, WithDirectory(plain.Dir), WithTLS())
	if !strings.HasPrefix(secure.URL(), "ldaps://") {
		t.Fatalf("url = %s", secure.URL())
	}
	sc := dial(t, secure)
	if err := sc.Bind(svcDN, svcPW); err != nil {
		t.Fatalf("ldaps bind: %v", err)
	}
	if err := sc.StartTLS(secure.ClientTLS()); err == nil {
		t.Fatal("StartTLS on ldaps accepted")
	}
	if _, err := ldap.DialURL(secure.URL(), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})); err == nil {
		t.Fatal("untrusted CA accepted")
	}
	noTLS := Start(t, WithDirectory(plain.Dir), WithoutStartTLS())
	nc := dial(t, noTLS)
	if err := nc.StartTLS(noTLS.ClientTLS()); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension) {
		t.Fatalf("StartTLS refusal: %v", err)
	}
	// go-ldap does not resume reading after a refused StartTLS; use a fresh connection.
	if root := search(t, dial(t, noTLS), "", ldap.ScopeBaseObject, "(objectClass=*)", "supportedExtension").Entries[0]; root.GetAttributeValue("supportedExtension") != "" {
		t.Fatal("StartTLS advertised")
	}
	caFile := secure.CAFile(t)
	if !strings.HasSuffix(caFile, "ca.pem") || len(secure.CAPEM()) == 0 {
		t.Fatalf("ca file %q", caFile)
	}
}

func TestServer_KillRestartDelay(t *testing.T) {
	s := StartFixture(t)
	c := bound(t, s)
	s.SetDelay(30 * time.Millisecond)
	start := time.Now()
	search(t, c, base, ldap.ScopeBaseObject, "(objectClass=*)")
	if time.Since(start) < 30*time.Millisecond {
		t.Fatal("delay not applied")
	}
	s.SetDelay(0)
	if s.OpenConns() != 1 || !s.Alive() {
		t.Fatalf("open=%d alive=%v", s.OpenConns(), s.Alive())
	}
	s.Kill()
	s.Kill()
	if s.Alive() {
		t.Fatal("alive after kill")
	}
	if _, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", nil, nil)); err == nil {
		t.Fatal("search on killed connection succeeded")
	}
	if _, err := ldap.DialURL(s.URL()); err == nil {
		t.Fatal("dial of killed server succeeded")
	}
	if err := s.Restart(); err != nil {
		t.Fatal(err)
	}
	if err := s.Restart(); err != nil {
		t.Fatal(err)
	}
	c2 := bound(t, s)
	if n := len(search(t, c2, base, ldap.ScopeBaseObject, "(objectClass=*)").Entries); n != 1 {
		t.Fatalf("after restart = %d", n)
	}
	s.ResetCalls()
	if s.Calls() != (Counts{}) {
		t.Fatal("counters not reset")
	}
	s.Stop()
	if err := s.Restart(); !errors.Is(err, ErrKilled) {
		t.Fatalf("restart after stop: %v", err)
	}
}

func TestServer_ReadOnly(t *testing.T) {
	s := StartFixture(t)
	c := bound(t, s)
	add := ldap.NewAddRequest("cn=new,"+base, nil)
	add.Attribute("objectClass", []string{"top"})
	if err := c.Add(add); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Fatalf("add: %v", err)
	}
	mod := ldap.NewModifyRequest(svcDN, nil)
	mod.Replace("description", []string{"x"})
	if err := c.Modify(mod); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Fatalf("modify: %v", err)
	}
	if err := c.Del(ldap.NewDelRequest(svcDN, nil)); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest(svcDN, "a", "b")); err == nil {
		t.Fatal("password modify accepted")
	}
	if s.Dir.Len() != 46 {
		t.Fatal("directory changed")
	}
}

func TestNew_Errors(t *testing.T) {
	if _, err := New(WithLDIF("/nonexistent/ad.ldif")); err == nil {
		t.Fatal("missing ldif accepted")
	}
	if _, err := New(WithEntries(&Entry{DN: "bad"})); err == nil {
		t.Fatal("bad entry accepted")
	}
	d, _ := NewDirectory(&Entry{DN: "dc=x"})
	if _, err := New(WithDirectory(d), WithEntries(&Entry{DN: "bad"})); err == nil {
		t.Fatal("bad extra entry accepted")
	}
	s, err := New(WithDirectory(d), WithEntries(&Entry{DN: "cn=a,dc=x"}), WithHostName("h"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if d.Len() != 2 || s.rootDSEEntry().First("dnsHostName") != "h" {
		t.Fatal("extra entries not merged")
	}
}
