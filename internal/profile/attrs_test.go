package profile

import (
	"strings"
	"testing"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

func TestComputed(t *testing.T) {
	for _, tc := range []struct {
		name, tpl string
		data      map[string]string
		deps      []string
		want      string
	}{
		{"or", `{{ or .mail (printf "%s@corp.local" .sAMAccountName) }}`, map[string]string{"mail": "", "sAMAccountName": "jd"}, []string{"mail", "sAMAccountName"}, "jd@corp.local"},
		{"or-set", `{{ or .mail (printf "%s@corp.local" .sAMAccountName) }}`, map[string]string{"mail": "x@y", "sAMAccountName": "jd"}, nil, "x@y"},
		{"concat", "{{ .sn }} {{ .givenName }}", map[string]string{"sn": "Doe", "givenName": "John"}, []string{"sn", "givenName"}, "Doe John"},
		{"funcs", `{{ .a | lower }}-{{ .a | upper }}-{{ .b | trim }}-{{ .c | default "d" }}-{{ first .c .a }}-{{ join "," .a .c .b }}`, map[string]string{"a": "Ab", "b": " x ", "c": ""}, []string{"a", "b", "c"}, "ab-AB-x-d-Ab-Ab, x"},
		{"regex", `{{ regexReplace "(\\w+)\\.(\\w+)" "$2 $1" .u }}`, map[string]string{"u": "john.doe"}, []string{"u"}, "doe john"},
		{"if", `{{ if .x }}{{ .x }}{{ else }}{{ .y }}{{ end }}{{ with .z }}{{ . }}{{ end }}`, map[string]string{"x": "", "y": "Y", "z": ""}, []string{"x", "y", "z"}, "Y"},
		{"missing", `{{ .nothere }}`, map[string]string{}, []string{"nothere"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := CompileComputed(tc.name, tc.tpl)
			if err != nil {
				t.Fatal(err)
			}
			if tc.deps != nil && strings.Join(c.Deps, ",") != strings.Join(tc.deps, ",") {
				t.Errorf("deps = %v, want %v", c.Deps, tc.deps)
			}
			got, err := c.Eval(tc.data)
			if err != nil || got != tc.want {
				t.Errorf("eval = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := CompileComputed("bad", "{{ .x "); err == nil {
		t.Error("syntax error accepted")
	}
	c, _ := CompileComputed("re", `{{ regexReplace "(" "" .x }}`)
	if _, err := c.Eval(map[string]string{"x": "a"}); err == nil {
		t.Error("bad regex accepted")
	}
	if _, err := regexReplace("a", "b", "a"); err != nil {
		t.Error(err)
	}
	for i := 0; i < 300; i++ { // cache bound
		_, _ = regexReplace("p"+strings.Repeat("x", i%5)+string(rune('a'+i%26)), "", "")
	}
}

func TestMask(t *testing.T) {
	for _, tc := range []struct{ pattern, in, want string }{
		{"***{last4}", "+380441234567", "***4567"},
		{"{first1}***@{domain}", "alice.adams@corp.local", "a***@corp.local"},
		{"{first1}***@{domain}", "nodomain", "n***@"},
		{"***", "anything", "***"},
		{"{first3}", "ab", "ab"},
		{"{last2}{first2}", "abcdef", "efab"},
		{"x{first1}y{last1}z", "Q", "xQyQz"},
	} {
		m, err := CompileMask("a", tc.pattern)
		if err != nil {
			t.Fatalf("%s: %v", tc.pattern, err)
		}
		if got := m.Apply(tc.in); got != tc.want {
			t.Errorf("%s(%s) = %q, want %q", tc.pattern, tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "{first0}", "{middle3}", "{first}", "a{b}c", "{last4"} {
		if _, err := CompileMask("a", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCompile_Stage5(t *testing.T) {
	p := testProfile()
	p.Attrs.Computed = map[string]string{"mail": "{{ .mail }}", "tag": "{{ .department }}"}
	p.Attrs.Mask = map[string]string{"telephoneNumber": "***{last4}"}
	p.ObjectClass.Map = map[string]string{"user": "inetOrgPerson"}
	p.Groups = map[string]config.Group{
		"all":   {},
		"staff": {Description: "d", ObjectClass: "group", Members: config.GroupMembers{ADGroups: []string{"CN=Staff,DC=x"}, Filter: "(sn=*)"}},
		"inc":   {Members: config.GroupMembers{Include: []string{"a@x"}}},
	}
	p.Honeytokens = []string{"h.petrenko@corp.local", " backup-admin ", ""}
	p.HoneytokenTemplate = map[string]string{"title": "{{ .domain }} {{ .user }}", "department": "Finance", "cn": ""}
	p.NestedDepth = 0
	r := compile(t, p, "pw")
	if !r.IsComputed("MAIL") || !r.IsAllowed("tag") || !r.IsVirtualAttr("memberof") || r.IsAllowed("department") || r.Classify("tag") != ldapfilter.Local || r.Classify("memberOf;x") != ldapfilter.Local || r.Classify("mail") != ldapfilter.Local {
		t.Error("computed classification")
	}
	if len(r.Computed()) != 2 || r.Computed()[0].Name != "mail" || len(r.Masks()) != 1 || r.Masks()[0].Name != "telephoneNumber" {
		t.Errorf("computed/masks = %v %v", r.Computed(), r.Masks())
	}
	if got := r.MapObjectClass([]string{"top", "USER"}); got[1] != "inetOrgPerson" || r.UpstreamObjectClass("InetOrgPerson") != "user" || r.UpstreamObjectClass("x") != "x" {
		t.Errorf("objectclass map = %v", got)
	}
	if r.NestedDepth != 10 || r.MembershipTTL <= 0 || r.Mode != "proxy" {
		t.Errorf("defaults = %+v", r)
	}
	gs := r.Groups()
	if len(gs) != 3 || gs[0].Name != "all" || gs[1].Name != "inc" || gs[2].Name != "staff" || !r.HasGroups() {
		t.Fatalf("groups = %+v", gs)
	}
	if all := r.Group("ALL"); all == nil || len(all.Bases) != len(p.Bases) || all.ObjectClass != "groupOfNames" || all.DN != r.GroupDN("all") {
		t.Errorf("all = %+v", all)
	}
	if staff := r.Group("staff"); staff.Filter == nil || len(staff.Bases) != len(p.Bases) || len(staff.ADGroups) != 1 || staff.ObjectClass != "group" {
		t.Errorf("staff = %+v", staff)
	}
	if inc := r.Group("inc"); len(inc.Bases) != 0 || len(inc.Include) != 1 || r.Group("none") != nil {
		t.Errorf("inc = %+v", inc)
	}
	hs := r.Honeytokens()
	if len(hs) != 2 || hs[0].Account != "h.petrenko@corp.local" || hs[0].User != "h.petrenko" || hs[0].Domain != "corp.local" || hs[1].Account != "backup-admin" || hs[1].Domain != "" {
		t.Fatalf("honeytokens = %+v", hs)
	}
	h := hs[0]
	if h.Attrs["title"][0] != "corp.local h.petrenko" || h.Attrs["department"][0] != "Finance" || h.Attrs["cn"] != nil || h.Attrs["sn"][0] != "Petrenko" ||
		h.Attrs["givenName"][0] != "H" || h.Attrs["sAMAccountName"][0] != "h.petrenko" || h.Attrs["mail"][0] != h.Account || len(h.GUID) != 16 ||
		!strings.HasPrefix(h.DN, "CN=h.petrenko,") || h.Attrs["objectClass"][3] != "user" {
		t.Errorf("honeytoken attrs = %+v", h.Attrs)
	}
	if hs[1].Attrs["cn"] != nil || hs[1].Attrs["givenName"][0] != "Backup" || hs[1].Attrs["sn"][0] != "Admin" {
		t.Errorf("backup-admin = %+v", hs[1].Attrs)
	}
	for name, want := range map[string]*Honeytoken{"H.Petrenko@corp.local": h, "h.petrenko": h, "CORP\\h.petrenko": h, "backup-admin": hs[1], "nobody": nil, "": nil, " ": nil} {
		if got := r.MatchHoneytoken(name); got != want {
			t.Errorf("MatchHoneytoken(%q) = %v", name, got)
		}
	}
	if r.HoneytokenValue("mail", "H.PETRENKO@corp.local") != h || r.HoneytokenValue("samaccountname", "h.petrenko") != h || r.HoneytokenValue("title", "corp.local h.petrenko") != nil || r.HoneytokenValue("sn", "Petrenko") != nil || r.HoneytokenValue("cn", "x") != nil {
		t.Error("HoneytokenValue")
	}
	// rdn_attr value of the trap matches a bind name too.
	p.RDNAttr = "displayName"
	r = compile(t, p, "pw")
	if r.MatchHoneytoken("H Petrenko") != r.Honeytokens()[0] {
		t.Error("rdn match")
	}
	// Errors.
	for _, mut := range []func(p *config.Profile){
		func(p *config.Profile) { p.Attrs.Computed = map[string]string{"x": "{{ .a "} },
		func(p *config.Profile) { p.Attrs.Mask = map[string]string{"x": "{bad}"} },
		func(p *config.Profile) { p.ObjectClass.Map = map[string]string{"": "x"} },
		func(p *config.Profile) {
			p.Groups = map[string]config.Group{"g": {Members: config.GroupMembers{Filter: "(bad"}}}
		},
		func(p *config.Profile) { p.HoneytokenTemplate = map[string]string{"cn": "{{ .x "} },
		func(p *config.Profile) {
			p.HoneytokenTemplate = map[string]string{"cn": `{{ regexReplace "(" "" .user }}`}
		},
	} {
		p := testProfile()
		p.Honeytokens = []string{"h@x"}
		mut(p)
		if _, err := Compile("p", p, nil, Options{ClientPassword: "pw", Argon2: fastArgon}); err == nil {
			t.Error("error expected")
		}
	}
	if given, sn := splitName(""); given != "User" || sn != "Unknown" {
		t.Error(given, sn)
	}
	if given, sn := splitName("solo"); given != "Solo" || sn != "User" {
		t.Error(given, sn)
	}
}
