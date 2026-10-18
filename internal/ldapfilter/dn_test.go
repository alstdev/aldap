package ldapfilter

import (
	"errors"
	"strings"
	"testing"
)

func mustDN(t *testing.T, s string) *DN {
	t.Helper()
	d, err := ParseDN(s)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", s, err)
	}
	return d
}

func TestParseDN_Shapes(t *testing.T) {
	tests := []struct {
		in   string
		want string // canonical String()
		rdns int
	}{
		{"", "", 0},
		{"   ", "", 0},
		{"dc=example,dc=com", "dc=example,dc=com", 2},
		{"DC=Example, DC=Com", "dc=Example,dc=Com", 2},
		{"CN=John Smith,OU=Office,DC=corp,DC=local", "cn=John Smith,ou=Office,dc=corp,dc=local", 4},
		{"cn=Smith\\, John,ou=x", "cn=Smith\\, John,ou=x", 2},
		{"cn=Smith\\2c John,ou=x", "cn=Smith\\, John,ou=x", 2},
		{`cn=a\+b\"c\<d\>e\;f\\g\=h`, `cn=a\+b\"c\<d\>e\;f\\g=h`, 1},
		{"cn=\\#hash", "cn=\\#hash", 1},
		{"cn=in#side", "cn=in#side", 1},
		{"cn=\\ lead", "cn=\\ lead", 1},
		{"cn=trail\\ ", "cn=trail\\ ", 1},
		{"cn=two  spaces", "cn=two  spaces", 1},
		{"cn=x , ou=y", "cn=x,ou=y", 2},
		{"cn = x,ou= y", "cn=x,ou=y", 2},
		{"cn=#04024869", "cn=\\04\\02Hi", 1}, // BER-encoded value, kept as raw bytes
		{"cn=#00", "cn=\\00", 1},
		{"cn=Іван Петренко,ou=users,dc=aldap", "cn=Іван Петренко,ou=users,dc=aldap", 3},
		{"cn=\\d0\\86\\d0\\b2\\d0\\b0\\d0\\bd", "cn=Іван", 1},
		{"ou=Sales+cn=J. Smith,dc=example,dc=net", "cn=J. Smith+ou=Sales,dc=example,dc=net", 3},
		{"CN=b+cn=a", "cn=a+cn=b", 1},
		{"2.5.4.3=x,0.9.2342.19200300.100.1.25=y", "2.5.4.3=x,0.9.2342.19200300.100.1.25=y", 2},
		{"cn=", "cn=", 1},
		{"cn=,ou=x", "cn=,ou=x", 2},
		{"cn=\\0a\\7f", "cn=\\0a\\7f", 1},
		{"uid=jsmith,ou=people,dc=example,dc=com", "uid=jsmith,ou=people,dc=example,dc=com", 4},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			d := mustDN(t, tt.in)
			if got := d.String(); got != tt.want {
				t.Errorf("String = %q, want %q", got, tt.want)
			}
			if d.Depth() != tt.rdns {
				t.Errorf("Depth = %d, want %d", d.Depth(), tt.rdns)
			}
			again := mustDN(t, d.String())
			if !again.Equal(d) || again.String() != d.String() {
				t.Errorf("round trip %q -> %q", d, again)
			}
		})
	}
}

func TestParseDN_Errors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"no_eq", "cn", ErrSyntax},
		{"no_type", "=x", ErrSyntax},
		{"bad_type", "c_n=x", ErrSyntax},
		{"bad_type_option", "cn;binary=x", ErrSyntax},
		{"bad_oid", "2..5=x", ErrSyntax},
		{"trailing_comma", "cn=x,", ErrSyntax},
		{"leading_comma", ",cn=x", ErrSyntax},
		{"double_comma", "cn=x,,ou=y", ErrSyntax},
		{"trailing_plus", "cn=x+", ErrSyntax},
		{"semicolon_sep", "cn=x;ou=y", ErrSyntax},
		{"raw_quote", "cn=\"x\"", ErrSyntax},
		{"raw_lt", "cn=<x", ErrSyntax},
		{"raw_gt", "cn=x>", ErrSyntax},
		{"raw_nul", "cn=\x00", ErrSyntax},
		{"truncated_escape", "cn=x\\", ErrSyntax},
		{"bad_escape", "cn=\\zz", ErrSyntax},
		{"half_hex_escape", "cn=\\4", ErrSyntax},
		{"escape_letter", "cn=\\n", ErrSyntax},
		{"hex_empty", "cn=#", ErrSyntax},
		{"hex_odd", "cn=#abc", ErrSyntax},
		{"hex_then_junk", "cn=#abzz", ErrSyntax},
		{"space_in_type", "c n=x", ErrSyntax},
		{"too_long", "cn=" + strings.Repeat("a", DefaultMaxDNLen), ErrTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := ParseDN(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseDN(%q) = %v, %v; want %v", tt.in, d, err, tt.want)
			}
			if !strings.HasPrefix(err.Error(), "dn: ") {
				t.Errorf("error %q lacks the dn: prefix", err)
			}
		})
	}
	if _, err := ParseDNWithLimit("cn=abcd", 5); !errors.Is(err, ErrTooLong) {
		t.Errorf("limit 5: %v", err)
	}
	if _, err := ParseDNWithLimit("cn=abcd", 0); err != nil {
		t.Errorf("limit 0 means default: %v", err)
	}
}

func TestDN_EqualCanonical(t *testing.T) {
	tests := []struct {
		a, b  string
		equal bool
	}{
		{"cn=John Smith,ou=x", "CN=john  smith , OU=X", true},
		{"cn=a+ou=b", "ou=b+cn=a", true},
		{"cn=a+ou=b", "OU=B+CN=A", true},
		{"cn=a,ou=b", "cn=a,ou=c", false},
		{"cn=a,ou=b", "cn=a", false},
		{"cn=a", "cn=a+ou=b", false},
		{"", "", true},
		{"cn=a", "", false},
		{"cn=Smith\\, John", "cn=Smith\\2c John", true},
		{"cn=Smith\\, John", "cn=Smith John", false},
		{"cn=x", "cn=\\ x\\ ", true},
	}
	for _, tt := range tests {
		a, b := mustDN(t, tt.a), mustDN(t, tt.b)
		if got := a.Equal(b); got != tt.equal {
			t.Errorf("Equal(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.equal)
		}
		if got := b.Equal(a); got != tt.equal {
			t.Errorf("Equal(%q, %q) = %v, want %v (symmetry)", tt.b, tt.a, got, tt.equal)
		}
		if got := a.Canonical() == b.Canonical(); got != tt.equal {
			t.Errorf("Canonical(%q)=%q vs Canonical(%q)=%q, equal=%v", tt.a, a.Canonical(), tt.b, b.Canonical(), got)
		}
	}
	var nilDN *DN
	root := mustDN(t, "")
	if !nilDN.Equal(root) || !root.Equal(nilDN) || !nilDN.Equal(nil) || nilDN.Canonical() != "" || nilDN.String() != "" {
		t.Error("nil DN must behave as the root")
	}
	if nilDN.Equal(mustDN(t, "cn=a")) {
		t.Error("nil equals non-root")
	}
	if got := mustDN(t, "CN=John  Smith,OU=X").Canonical(); got != "cn=john smith,ou=x" {
		t.Errorf("Canonical = %q", got)
	}
}

func TestDN_IsUnder(t *testing.T) {
	tests := []struct {
		dn, base string
		want     bool
	}{
		{"cn=a,ou=users,dc=aldap", "ou=users,dc=aldap", true},
		{"cn=a,ou=users,dc=aldap", "OU=Users, DC=Aldap", true},
		{"ou=users,dc=aldap", "ou=users,dc=aldap", true},
		{"dc=aldap", "ou=users,dc=aldap", false},
		{"cn=a,ou=groups,dc=aldap", "ou=users,dc=aldap", false},
		{"cn=a,ou=users,dc=other", "ou=users,dc=aldap", false},
		{"cn=a,ou=users,dc=aldap", "", true},
		{"", "", true},
		{"", "dc=aldap", false},
		{"cn=ou=users,dc=aldap", "ou=users,dc=aldap", false},
	}
	for _, tt := range tests {
		if got := mustDN(t, tt.dn).IsUnder(mustDN(t, tt.base)); got != tt.want {
			t.Errorf("IsUnder(%q, %q) = %v, want %v", tt.dn, tt.base, got, tt.want)
		}
	}
	if !mustDN(t, "cn=a").IsUnder(nil) {
		t.Error("nil base is the root")
	}
}

func TestDN_Rewrite(t *testing.T) {
	tests := []struct {
		dn, oldBase, newBase string
		want                 string
		err                  error
	}{
		{"CN=John Smith,OU=Office,DC=corp,DC=local", "ou=office,dc=corp,dc=local", "ou=users,ou=virola,dc=aldap", "cn=John Smith,ou=users,ou=virola,dc=aldap", nil},
		{"ou=office,dc=corp,dc=local", "ou=office,dc=corp,dc=local", "dc=aldap", "dc=aldap", nil},
		{"cn=a,dc=x", "", "dc=new", "cn=a,dc=x,dc=new", nil},
		{"cn=a,dc=x", "dc=x", "", "cn=a", nil},
		{"cn=a,dc=y", "dc=x", "dc=new", "", ErrNotUnder},
		{"dc=x", "cn=a,dc=x", "dc=new", "", ErrNotUnder},
	}
	for _, tt := range tests {
		in := mustDN(t, tt.dn)
		got, err := in.Rewrite(mustDN(t, tt.oldBase), mustDN(t, tt.newBase))
		if !errors.Is(err, tt.err) {
			t.Fatalf("Rewrite(%q, %q, %q) err = %v, want %v", tt.dn, tt.oldBase, tt.newBase, err, tt.err)
		}
		if err == nil && got.String() != tt.want {
			t.Errorf("Rewrite(%q, %q, %q) = %q, want %q", tt.dn, tt.oldBase, tt.newBase, got, tt.want)
		}
		if in.String() != mustDN(t, tt.dn).String() {
			t.Errorf("Rewrite modified its receiver: %q", in)
		}
	}
	got, err := mustDN(t, "cn=a").Rewrite(nil, nil)
	if err != nil || got.String() != "cn=a" {
		t.Errorf("nil bases: %q, %v", got, err)
	}
	var nilDN *DN
	got, err = nilDN.Rewrite(nil, mustDN(t, "dc=x"))
	if err != nil || got.String() != "dc=x" {
		t.Errorf("nil receiver: %q, %v", got, err)
	}
}

func TestDN_Navigation(t *testing.T) {
	d := mustDN(t, "cn=a,ou=users,dc=aldap")
	if got := d.RDN().String(); got != "cn=a" {
		t.Errorf("RDN = %q", got)
	}
	if got := d.Parent().String(); got != "ou=users,dc=aldap" {
		t.Errorf("Parent = %q", got)
	}
	if got := d.Parent().Parent().Parent().Parent().String(); got != "" {
		t.Errorf("root parent = %q", got)
	}
	child := d.Parent().Child(RDN{AVAs: []AVA{{Type: "CN", Value: "Smith, John"}}})
	if got := child.String(); got != "cn=Smith\\, John,ou=users,dc=aldap" {
		t.Errorf("Child = %q", got)
	}
	if d.String() != "cn=a,ou=users,dc=aldap" {
		t.Errorf("receiver modified: %q", d)
	}
	var nilDN *DN
	if nilDN.Clone() != nil || nilDN.Depth() != 0 || len(nilDN.RDN().AVAs) != 0 || nilDN.Parent().Depth() != 0 {
		t.Error("nil navigation")
	}
	if got := nilDN.Child(RDN{AVAs: []AVA{{Type: "dc", Value: "x"}}}).String(); got != "dc=x" {
		t.Errorf("nil Child = %q", got)
	}
	c := d.Clone()
	c.RDNs[0].AVAs[0].Value = "zzz"
	if d.RDNs[0].AVAs[0].Value != "a" {
		t.Error("Clone shares AVAs")
	}
}

func TestEscapeRDNValue_Cases(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"Smith, John", "Smith\\, John"},
		{"a+b", "a\\+b"},
		{`a"b`, `a\"b`},
		{"a<b>c", "a\\<b\\>c"},
		{"a;b", "a" + `\` + ";b"},
		{`a\b`, `a\\b`},
		{"#lead", "\\#lead"},
		{"in#side", "in#side"},
		{" lead", "\\ lead"},
		{"trail ", "trail\\ "},
		{" ", "\\ "},
		{"  ", "\\ \\ "},
		{"a=b", "a=b"},
		{"\x00\n\x7f", "\\00\\0a\\7f"},
		{"Іван ✓", "Іван ✓"},
		{"", ""},
	}
	for _, tt := range tests {
		got := EscapeRDNValue(tt.in)
		if got != tt.want {
			t.Errorf("EscapeRDNValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
		d := mustDN(t, "cn="+got)
		if v := d.RDNs[0].AVAs[0].Value; v != tt.in {
			t.Errorf("parse back of %q = %q, want %q", got, v, tt.in)
		}
	}
}
