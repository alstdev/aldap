package ldapfilter

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) *Filter {
	t.Helper()
	f, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return f
}

func TestParse_Shapes(t *testing.T) {
	tests := []struct {
		in   string
		want Filter
	}{
		{"(cn=John)", Filter{Kind: Equality, Attr: "cn", Value: "John"}},
		{"(cn=)", Filter{Kind: Equality, Attr: "cn", Value: ""}},
		{"(cn=*)", Filter{Kind: Present, Attr: "cn"}},
		{"(cn~=Jon)", Filter{Kind: Approx, Attr: "cn", Value: "Jon"}},
		{"(uidNumber>=10)", Filter{Kind: GreaterOrEqual, Attr: "uidNumber", Value: "10"}},
		{"(uidNumber<=10)", Filter{Kind: LessOrEqual, Attr: "uidNumber", Value: "10"}},
		{"(cn=J*)", Filter{Kind: Substring, Attr: "cn", Initial: "J"}},
		{"(cn=*n)", Filter{Kind: Substring, Attr: "cn", Final: "n"}},
		{"(cn=*o*)", Filter{Kind: Substring, Attr: "cn", Any: []string{"o"}}},
		{"(cn=J*o*h*n)", Filter{Kind: Substring, Attr: "cn", Initial: "J", Any: []string{"o", "h"}, Final: "n"}},
		{"(cn=\\2a*)", Filter{Kind: Substring, Attr: "cn", Initial: "*"}},
		{"(cn=a\\28b\\29c\\5c\\00)", Filter{Kind: Equality, Attr: "cn", Value: "a(b)c\\\x00"}},
		{"(cn=\\4A\\6f)", Filter{Kind: Equality, Attr: "cn", Value: "Jo"}},
		{"(cn=Іван)", Filter{Kind: Equality, Attr: "cn", Value: "Іван"}},
		{"(userCertificate;binary=*)", Filter{Kind: Present, Attr: "userCertificate;binary"}},
		{"(2.5.4.3=x)", Filter{Kind: Equality, Attr: "2.5.4.3", Value: "x"}},
		{"(cn:=x)", Filter{Kind: Extensible, Attr: "cn", Value: "x"}},
		{"(cn:dn:=x)", Filter{Kind: Extensible, Attr: "cn", DNAttributes: true, Value: "x"}},
		{"(cn:caseExactMatch:=x)", Filter{Kind: Extensible, Attr: "cn", MatchingRule: "caseExactMatch", Value: "x"}},
		{"(cn:dn:2.5.13.2:=x)", Filter{Kind: Extensible, Attr: "cn", DNAttributes: true, MatchingRule: "2.5.13.2", Value: "x"}},
		{"(:2.5.13.2:=x)", Filter{Kind: Extensible, MatchingRule: "2.5.13.2", Value: "x"}},
		{"(:dn:2.5.13.2:=x)", Filter{Kind: Extensible, DNAttributes: true, MatchingRule: "2.5.13.2", Value: "x"}},
		{"(userAccountControl:1.2.840.113556.1.4.803:=2)", Filter{Kind: Extensible, Attr: "userAccountControl", MatchingRule: "1.2.840.113556.1.4.803", Value: "2"}},
		{"(&)", Filter{Kind: And}},
		{"(|)", Filter{Kind: Or}},
		{"(&(cn=a)(sn=b))", Filter{Kind: And, Children: []*Filter{{Kind: Equality, Attr: "cn", Value: "a"}, {Kind: Equality, Attr: "sn", Value: "b"}}}},
		{"(|(cn=a))", Filter{Kind: Or, Children: []*Filter{{Kind: Equality, Attr: "cn", Value: "a"}}}},
		{"(!(cn=a))", Filter{Kind: Not, Children: []*Filter{{Kind: Equality, Attr: "cn", Value: "a"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := mustParse(t, tt.in)
			if !got.Equal(&tt.want) {
				t.Errorf("got %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParse_Errors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrSyntax},
		{"no_parens", "cn=x", ErrSyntax},
		{"unclosed", "(cn=x", ErrSyntax},
		{"trailing", "(cn=x))", ErrSyntax},
		{"two_filters", "(cn=x)(sn=y)", ErrSyntax},
		{"missing_attr", "(=x)", ErrSyntax},
		{"missing_op", "(cn)", ErrSyntax},
		{"bad_attr_lead", "(-cn=x)", ErrSyntax},
		{"bad_attr_char", "(c_n=x)", ErrSyntax},
		{"bad_attr_space", "(c n=x)", ErrSyntax},
		{"bad_oid_arc", "(2..5=x)", ErrSyntax},
		{"bad_oid_leading_zero", "(2.05.4=x)", ErrSyntax},
		{"bad_option", "(cn;=x)", ErrSyntax},
		{"ge_without_eq", "(cn>x)", ErrSyntax},
		{"approx_without_eq", "(cn~x)", ErrSyntax},
		{"empty_any", "(cn=a**b)", ErrSyntax},
		{"present_star_star", "(cn=**)", ErrSyntax},
		{"truncated_escape", "(cn=\\4)", ErrSyntax},
		{"bad_escape", "(cn=\\zz)", ErrSyntax},
		{"old_style_escape", "(cn=\\*)", ErrSyntax},
		{"raw_nul", "(cn=\x00)", ErrSyntax},
		{"not_without_child", "(!)", ErrSyntax},
		{"not_two_children", "(!(cn=a)(cn=b))", ErrSyntax},
		{"not_item", "(!cn=a)", ErrSyntax},
		{"and_item", "(&cn=a)", ErrSyntax},
		{"ext_no_value_sep", "(cn:dn)", ErrSyntax},
		{"ext_dn_after_rule", "(cn:caseIgnoreMatch:dn:=x)", ErrSyntax},
		{"ext_two_rules", "(cn:a:b:=x)", ErrSyntax},
		{"ext_nothing", "(:=x)", ErrSyntax},
		{"ext_bad_rule", "(cn:1..2:=x)", ErrSyntax},
		{"ext_empty_tok", "(cn::=x)", ErrSyntax},
		{"too_long", "(cn=" + strings.Repeat("a", DefaultMaxLen) + ")", ErrTooLong},
		{"too_deep", strings.Repeat("(!", DefaultMaxDepth+1) + "(cn=a)" + strings.Repeat(")", DefaultMaxDepth+1), ErrTooDeep},
		{"too_deep_and", strings.Repeat("(&", DefaultMaxDepth+1) + "(cn=a)" + strings.Repeat(")", DefaultMaxDepth+1), ErrTooDeep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse(%q) = %v, %v; want %v", tt.in, f, err, tt.want)
			}
			if !strings.HasPrefix(err.Error(), "filter: ") {
				t.Errorf("error %q lacks the filter: prefix", err)
			}
		})
	}
}

func TestParseWithLimits_Cases(t *testing.T) {
	deep := strings.Repeat("(!", 30) + "(cn=a)" + strings.Repeat(")", 30)
	tests := []struct {
		name string
		in   string
		lim  Limits
		want error
	}{
		{"depth_30_ok_with_40", deep, Limits{MaxDepth: 40}, nil},
		{"depth_30_too_deep_with_5", deep, Limits{MaxDepth: 5}, ErrTooDeep},
		{"hard_cap_64", strings.Repeat("(!", 65) + "(cn=a)" + strings.Repeat(")", 65), Limits{MaxDepth: 1000, MaxLen: 1 << 16}, ErrTooDeep},
		{"len_short", "(cn=abc)", Limits{MaxLen: 5}, ErrTooLong},
		{"len_exact", "(cn=abc)", Limits{MaxLen: 8}, nil},
		{"leaf_depth_zero", "(cn=a)", Limits{MaxDepth: 1}, nil},
		{"one_and_depth_one", "(&(cn=a))", Limits{MaxDepth: 1}, nil},
		{"two_levels_exceed_one", "(&(!(cn=a)))", Limits{MaxDepth: 1}, ErrTooDeep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWithLimits(tt.in, tt.lim)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestFilter_String(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"(cn=John)", "(cn=John)"},
		{"(cn=\\4A\\6f)", "(cn=Jo)"},
		{"(cn=a\\28b\\29c\\5c\\00\\2a)", "(cn=a\\28b\\29c\\5c\\00\\2a)"},
		{"(cn=\\2A*)", "(cn=\\2a*)"},
		{"(cn=\\0A\\7F\\e2\\9c\\93)", "(cn=\\0a\\7f✓)"},
		{"(cn=J*o*h*n)", "(cn=J*o*h*n)"},
		{"(cn=*)", "(cn=*)"},
		{"(cn~=x)", "(cn~=x)"},
		{"(a>=1)", "(a>=1)"},
		{"(a<=1)", "(a<=1)"},
		{"(cn:dn:2.5.13.2:=x)", "(cn:dn:2.5.13.2:=x)"},
		{"(:dn:2.5.13.2:=x)", "(:dn:2.5.13.2:=x)"},
		{"(&(cn=a)(!(sn=b)))", "(&(cn=a)(!(sn=b)))"},
		{"(&)", "(&)"},
		{"(|)", "(|)"},
	}
	for _, tt := range tests {
		if got := mustParse(t, tt.in).String(); got != tt.want {
			t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	var nilF *Filter
	if nilF.String() != "" {
		t.Errorf("nil String = %q", nilF.String())
	}
	if (&Filter{Kind: Not}).String() != "(!)" {
		t.Errorf("empty Not = %q", (&Filter{Kind: Not}).String())
	}
}

func TestFilter_Normalize(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"(CN=John)", "(cn=John)"},
		{"(ObjectClass=*)", "(objectclass=*)"},
		{"(&(sn=b)(cn=a))", "(&(cn=a)(sn=b))"},
		{"(|(sn=b)(cn=a)(cn=a))", "(|(cn=a)(sn=b))"},
		{"(&(|(SN=b)(CN=a))(!(Mail=*)))", "(&(!(mail=*))(|(cn=a)(sn=b)))"},
		{"(UserAccountControl:1.2.840.113556.1.4.803:=2)", "(useraccountcontrol:1.2.840.113556.1.4.803:=2)"},
		{"(cn:CaseExactMatch:=John)", "(cn:caseexactmatch:=John)"},
		{"(&(cn=a)(cn=A))", "(&(cn=A)(cn=a))"},
		{"(&)", "(&)"},
	}
	for _, tt := range tests {
		f := mustParse(t, tt.in)
		n := f.Normalize()
		if got := n.String(); got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if again := n.Normalize().String(); again != tt.want {
			t.Errorf("Normalize not idempotent: %q -> %q", tt.want, again)
		}
		if f.String() == tt.want && tt.in != tt.want {
			t.Errorf("Normalize modified its receiver: %q", f)
		}
	}
	var nilF *Filter
	if nilF.Normalize() != nil || nilF.Clone() != nil {
		t.Error("nil Normalize/Clone must return nil")
	}
}

func TestFilter_EqualClone(t *testing.T) {
	a := mustParse(t, "(&(cn=J*o*n)(sn:dn:2.5.13.2:=x)(!(mail=*)))")
	b := a.Clone()
	if !a.Equal(b) || !b.Equal(a) {
		t.Fatal("clone not equal")
	}
	b.Children[0].Any[0] = "z"
	if a.Equal(b) {
		t.Error("clone shares Any slice")
	}
	b = a.Clone()
	b.Children[2].Children[0].Attr = "x"
	if a.Equal(b) {
		t.Error("clone shares children")
	}
	diffs := []string{
		"(&(cn=J*o*n)(sn:dn:2.5.13.2:=x))",
		"(&(cn=J*o*n)(sn:2.5.13.2:=x)(!(mail=*)))",
		"(&(cn=J*o*n)(sn:dn:2.5.13.3:=x)(!(mail=*)))",
		"(&(cn=J*o*n)(sn:dn:2.5.13.2:=y)(!(mail=*)))",
		"(&(cn=J*o)(sn:dn:2.5.13.2:=x)(!(mail=*)))",
		"(&(cn=J*n)(sn:dn:2.5.13.2:=x)(!(mail=*)))",
		"(&(cn=K*o*n)(sn:dn:2.5.13.2:=x)(!(mail=*)))",
		"(|(cn=J*o*n)(sn:dn:2.5.13.2:=x)(!(mail=*)))",
	}
	for _, d := range diffs {
		if a.Equal(mustParse(t, d)) {
			t.Errorf("%q should differ from %q", d, a)
		}
	}
	var nilF *Filter
	if !nilF.Equal(nil) || a.Equal(nil) || nilF.Equal(a) {
		t.Error("nil comparisons wrong")
	}
}

func TestFilter_Depth(t *testing.T) {
	tests := map[string]int{
		"(cn=a)":             0,
		"(&(cn=a))":          1,
		"(&)":                1,
		"(!(cn=a))":          1,
		"(&(|(cn=a))(sn=b))": 2,
		"(!(&(|(!(cn=a)))))": 4,
	}
	for in, want := range tests {
		if got := mustParse(t, in).Depth(); got != want {
			t.Errorf("Depth(%q) = %d, want %d", in, got, want)
		}
	}
	var nilF *Filter
	if nilF.Depth() != 0 {
		t.Error("nil depth")
	}
}

func TestKind_String(t *testing.T) {
	if And.String() != "and" || Extensible.String() != "extensible" || Kind(99).String() != "kind(99)" {
		t.Errorf("%s %s %s", And, Extensible, Kind(99))
	}
}

func TestEscapeValue_RoundTrip(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"a*b", "a\\2ab"},
		{"(x)", "\\28x\\29"},
		{"back\\slash", "back\\5cslash"},
		{"\x00", "\\00"},
		{"\n\t\x7f", "\\0a\\09\\7f"},
		{"Іван ✓", "Іван ✓"},
		{"", ""},
	}
	for _, tt := range tests {
		got := EscapeValue(tt.in)
		if got != tt.want {
			t.Errorf("EscapeValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
		back, err := UnescapeValue(got)
		if err != nil || back != tt.in {
			t.Errorf("UnescapeValue(%q) = %q, %v", got, back, err)
		}
	}
	for _, bad := range []string{"a*b", "(", ")", "\\4", "\\zz", "\x00"} {
		if _, err := UnescapeValue(bad); !errors.Is(err, ErrSyntax) {
			t.Errorf("UnescapeValue(%q) err = %v", bad, err)
		}
	}
}

// corpus reads testdata/filters.txt.
func corpus(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("testdata/filters.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCorpus_RoundTrip is the Stage 2 acceptance check: parse → serialize
// → parse is the identity for every corpus filter (≥ 200 entries).
func TestCorpus_RoundTrip(t *testing.T) {
	lines := corpus(t)
	if len(lines) < 200 {
		t.Fatalf("corpus has %d filters, want >= 200", len(lines))
	}
	for _, line := range lines {
		f, err := Parse(line)
		if err != nil {
			t.Errorf("Parse(%q): %v", line, err)
			continue
		}
		s := f.String()
		g, err := Parse(s)
		if err != nil {
			t.Errorf("re-Parse(%q) from %q: %v", s, line, err)
			continue
		}
		if !f.Equal(g) {
			t.Errorf("round trip changed %q -> %q", line, s)
		}
		if g.String() != s {
			t.Errorf("String not stable: %q -> %q", s, g.String())
		}
		n := f.Normalize()
		if n2 := n.Normalize(); !n.Equal(n2) {
			t.Errorf("Normalize not idempotent for %q", line)
		}
		if m, err := Parse(n.String()); err != nil || !m.Equal(n) {
			t.Errorf("normalised %q does not round-trip: %v", n, err)
		}
	}
}
