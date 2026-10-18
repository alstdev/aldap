package ldapfilter

import (
	"reflect"
	"testing"
)

func TestInjectExclude_Cases(t *testing.T) {
	tests := []struct {
		name       string
		f, extra   string
		exclude    bool
		want       string
		nilF, nilX bool
	}{
		{name: "leaf_and_leaf", f: "(cn=a)", extra: "(sn=b)", want: "(&(cn=a)(sn=b))"},
		{name: "and_extended", f: "(&(cn=a)(sn=b))", extra: "(mail=*)", want: "(&(cn=a)(sn=b)(mail=*))"},
		{name: "extra_and_flattened", f: "(cn=a)", extra: "(&(sn=b)(mail=*))", want: "(&(cn=a)(sn=b)(mail=*))"},
		{name: "or_not_flattened", f: "(|(cn=a)(cn=b))", extra: "(sn=c)", want: "(&(|(cn=a)(cn=b))(sn=c))"},
		{name: "nil_extra", f: "(cn=a)", nilX: true, want: "(cn=a)"},
		{name: "true_extra", f: "(cn=a)", extra: "(&)", want: "(cn=a)"},
		{name: "nil_f", extra: "(sn=b)", nilF: true, want: "(sn=b)"},
		{name: "true_f", f: "(&)", extra: "(sn=b)", want: "(sn=b)"},
		{name: "exclude_leaf", f: "(cn=a)", extra: "(sn=b)", exclude: true, want: "(&(cn=a)(!(sn=b)))"},
		{name: "exclude_and", f: "(&(cn=a)(sn=b))", extra: "(|(mail=x)(mail=y))", exclude: true, want: "(&(cn=a)(sn=b)(!(|(mail=x)(mail=y))))"},
		{name: "exclude_nil", f: "(cn=a)", nilX: true, exclude: true, want: "(cn=a)"},
		{name: "exclude_false", f: "(cn=a)", extra: "(|)", exclude: true, want: "(cn=a)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f, x *Filter
			if !tt.nilF {
				f = mustParse(t, tt.f)
			}
			if !tt.nilX {
				x = mustParse(t, tt.extra)
			}
			before := f.String() + "|" + x.String()
			var got *Filter
			if tt.exclude {
				got = Exclude(f, x)
			} else {
				got = Inject(f, x)
			}
			if got.String() != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if after := f.String() + "|" + x.String(); after != before {
				t.Errorf("arguments modified: %q -> %q", before, after)
			}
		})
	}
}

func TestMapAttrs_Cases(t *testing.T) {
	m := map[string]string{"uid": "sAMAccountName", "Mail": "proxyAddresses", "memberOf": "memberOf", "cn": "name"}
	tests := []struct{ in, want string }{
		{"(uid=j)", "(sAMAccountName=j)"},
		{"(UID=j)", "(sAMAccountName=j)"},
		{"(mail=*)", "(proxyAddresses=*)"},
		{"(cn;lang-uk=x)", "(name;lang-uk=x)"},
		{"(cn;binary;x-y=x)", "(name;binary;x-y=x)"},
		{"(sn=x)", "(sn=x)"},
		{"(&(uid=j)(|(mail=*)(!(cn=a*b))))", "(&(sAMAccountName=j)(|(proxyAddresses=*)(!(name=a*b))))"},
		{"(uid:dn:caseIgnoreMatch:=j)", "(sAMAccountName:dn:caseIgnoreMatch:=j)"},
		{"(:caseIgnoreMatch:=j)", "(:caseIgnoreMatch:=j)"},
		{"(cn:cn:=j)", "(name:cn:=j)"},
	}
	for _, tt := range tests {
		f := mustParse(t, tt.in)
		got := MapAttrs(f, m)
		if got.String() != tt.want {
			t.Errorf("MapAttrs(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if f.String() != tt.in {
			t.Errorf("MapAttrs modified input: %q", f)
		}
	}
	if MapAttrs(nil, m) != nil {
		t.Error("nil input")
	}
}

func TestWalkAttrs_Cases(t *testing.T) {
	f := mustParse(t, "(&(cn=a)(|(sn=b)(cn=c)(:dn:2.5.13.2:=d))(!(mail=*)))")
	var kinds []Kind
	Walk(f, func(n *Filter) bool {
		kinds = append(kinds, n.Kind)
		return n.Kind != Or // do not descend into the Or
	})
	wantKinds := []Kind{And, Equality, Or, Not, Present}
	if !reflect.DeepEqual(kinds, wantKinds) {
		t.Errorf("Walk order = %v, want %v", kinds, wantKinds)
	}
	if got, want := f.Attrs(), []string{"cn", "sn", "mail"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Attrs = %v, want %v", got, want)
	}
	Walk(nil, func(*Filter) bool { t.Error("visited nil"); return true })
	var nilF *Filter
	if nilF.Attrs() != nil {
		t.Error("nil Attrs")
	}
}

func TestSimplify_Cases(t *testing.T) {
	tests := []struct{ in, want string }{
		{"(cn=a)", "(cn=a)"},
		{"(&(cn=a)(&))", "(cn=a)"},
		{"(&(cn=a)(|))", "(|)"},
		{"(|(cn=a)(|))", "(cn=a)"},
		{"(|(cn=a)(&))", "(&)"},
		{"(&(cn=a)(sn=b)(&)(&))", "(&(cn=a)(sn=b))"},
		{"(!(&))", "(|)"},
		{"(!(|))", "(&)"},
		{"(!(cn=a))", "(!(cn=a))"},
		{"(!(&(cn=a)(|)))", "(&)"},
		{"(&(|(cn=a)(&))(sn=b))", "(sn=b)"},
		{"(&(&(&(cn=a))))", "(cn=a)"},
		{"(&)", "(&)"},
		{"(|)", "(|)"},
		{"(&(|))", "(|)"},
		{"(|(&))", "(&)"},
	}
	for _, tt := range tests {
		if got := Simplify(mustParse(t, tt.in)).String(); got != tt.want {
			t.Errorf("Simplify(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if Simplify(nil) != nil {
		t.Error("nil")
	}
	if got := Simplify(&Filter{Kind: Not}).String(); got != "(!)" {
		t.Errorf("empty Not = %q", got)
	}
	if !True().IsTrue() || !False().IsFalse() || True().IsFalse() || False().IsTrue() {
		t.Error("constants")
	}
	var nilF *Filter
	if nilF.IsTrue() || nilF.IsFalse() {
		t.Error("nil constants")
	}
}

func classifier(local, denied []string) func(string) Class {
	set := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	l, d := set(local), set(denied)
	return func(attr string) Class {
		switch {
		case l[attr]:
			return Local
		case d[attr]:
			return Denied
		}
		return Upstream
	}
}

func TestSplit_Cases(t *testing.T) {
	cl := classifier([]string{"memberOf", "computedX"}, []string{"userPassword", "secret"})
	tests := []struct {
		name           string
		in             string
		wantExec, want string // want is the postfilter
	}{
		{"pure_upstream", "(&(objectClass=user)(sn=a))", "(&(objectClass=user)(sn=a))", "(&)"},
		{"pure_local", "(memberOf=cn=g)", "(&)", "(memberOf=cn=g)"},
		{"denied_leaf", "(userPassword=x)", "(|)", "(&)"},
		{"and_mixed", "(&(objectClass=user)(memberOf=cn=g)(sn=a))", "(&(objectClass=user)(sn=a))", "(memberOf=cn=g)"},
		{"and_with_denied", "(&(objectClass=user)(userPassword=x))", "(|)", "(&)"},
		{"and_local_and_denied", "(&(memberOf=g)(secret=1))", "(|)", "(memberOf=g)"},
		{"or_mixed_whole_local", "(|(sn=a)(memberOf=g))", "(&)", "(|(sn=a)(memberOf=g))"},
		{"or_upstream_only", "(|(sn=a)(cn=b))", "(|(sn=a)(cn=b))", "(&)"},
		{"or_with_denied", "(|(sn=a)(userPassword=x))", "(sn=a)", "(&)"},
		{"or_all_denied", "(|(secret=a)(userPassword=x))", "(|)", "(&)"},
		{"or_local_and_denied", "(|(memberOf=g)(userPassword=x))", "(&)", "(memberOf=g)"},
		{"not_upstream", "(!(sn=a))", "(!(sn=a))", "(&)"},
		{"not_local", "(!(memberOf=g))", "(&)", "(!(memberOf=g))"},
		{"not_denied", "(!(userPassword=x))", "(&)", "(&)"},
		{"not_mixed_and", "(!(&(sn=a)(memberOf=g)))", "(&)", "(!(&(sn=a)(memberOf=g)))"},
		{"nested_and_in_and", "(&(objectClass=user)(&(memberOf=g)(cn=x)))", "(&(objectClass=user)(cn=x))", "(memberOf=g)"},
		{"nested_or_in_and", "(&(objectClass=user)(|(memberOf=g)(cn=x)))", "(objectClass=user)", "(|(memberOf=g)(cn=x))"},
		{"deep_or_denied_inside_not", "(&(cn=a)(!(|(sn=b)(secret=c))))", "(&(cn=a)(!(sn=b)))", "(&)"},
		{"extensible_local", "(memberOf:1.2.840.113556.1.4.1941:=g)", "(&)", "(memberOf:1.2.840.113556.1.4.1941:=g)"},
		{"present_local", "(computedX=*)", "(&)", "(computedX=*)"},
		{"substring_denied", "(secret=a*b)", "(|)", "(&)"},
		{"rule_only_extensible", "(:2.5.13.2:=x)", "(:2.5.13.2:=x)", "(&)"},
		{"absolute_true", "(&)", "(&)", "(&)"},
		{"absolute_false", "(|)", "(|)", "(&)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := mustParse(t, tt.in)
			exec, post := Split(in, cl)
			if exec.String() != tt.wantExec || post.String() != tt.want {
				t.Errorf("Split(%q) = %q, %q; want %q, %q", tt.in, exec, post, tt.wantExec, tt.want)
			}
			if in.String() != tt.in {
				t.Errorf("Split modified input: %q", in)
			}
		})
	}
	exec, post := Split(nil, cl)
	if !exec.IsTrue() || !post.IsTrue() {
		t.Errorf("Split(nil) = %q, %q", exec, post)
	}
}

// TestSplit_NoLocalInExecutable checks the invariant that the executable
// part never names a Local or Denied attribute, over the whole corpus.
func TestSplit_NoLocalInExecutable(t *testing.T) {
	cl := classifier([]string{"memberof", "member"}, []string{"userpassword", "unicodepwd", "ntpwdhistory", "supplementalcredentials"})
	lower := func(attr string) Class { return cl(toLower(attr)) }
	for _, line := range corpus(t) {
		f := mustParse(t, line)
		exec, post := Split(f, lower)
		Walk(exec, func(n *Filter) bool {
			if n.Attr != "" && lower(n.Attr) != Upstream {
				t.Errorf("%q: executable %q contains %q", line, exec, n.Attr)
			}
			return true
		})
		Walk(post, func(n *Filter) bool {
			if n.Attr != "" && lower(n.Attr) == Denied {
				t.Errorf("%q: postfilter %q contains denied %q", line, post, n.Attr)
			}
			return true
		})
	}
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
