package ldapfilter

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func seedCorpus(f *testing.F) {
	f.Helper()
	fh, err := os.Open("testdata/filters.txt")
	if err != nil {
		f.Fatal(err)
	}
	defer func() {
		if err := fh.Close(); err != nil {
			f.Error(err)
		}
	}()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if line := sc.Text(); line != "" && !strings.HasPrefix(line, "#") {
			f.Add(line)
		}
	}
}

// FuzzParseFilter checks that Parse never panics and that whatever it
// accepts survives String → Parse unchanged, including after Normalize.
func FuzzParseFilter(f *testing.F) {
	seedCorpus(f)
	for _, s := range []string{"", "(", ")", "(&)", "(|)", "(!(a=b))", "(a=\\00)", "(a=*b*c*)", "(:dn:1.2:=x)", "(a;b:dn:=c)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		parsed, err := Parse(in)
		if err != nil {
			if parsed != nil {
				t.Fatal("non-nil filter with error")
			}
			return
		}
		// Canonical escaping can make the text up to 3x longer, so the
		// re-parse gets a wider length limit; the depth limit is unchanged.
		s := parsed.String()
		again, err := ParseWithLimits(s, Limits{MaxLen: 3 * DefaultMaxLen})
		if err != nil {
			t.Fatalf("re-parse of %q (from %q): %v", s, in, err)
		}
		if !parsed.Equal(again) || again.String() != s {
			t.Fatalf("round trip %q -> %q -> %q", in, s, again.String())
		}
		if parsed.Depth() > DefaultMaxDepth {
			t.Fatalf("depth %d accepted", parsed.Depth())
		}
		n := parsed.Normalize()
		if m, err := ParseWithLimits(n.String(), Limits{MaxLen: 3 * DefaultMaxLen}); err != nil || !m.Equal(n) {
			t.Fatalf("normalized %q does not round-trip: %v", n, err)
		}
		cl := func(attr string) Class {
			switch {
			case strings.HasPrefix(strings.ToLower(attr), "member"):
				return Local
			case strings.Contains(strings.ToLower(attr), "pwd"):
				return Denied
			}
			return Upstream
		}
		exec, post := Split(parsed, cl)
		if exec == nil || post == nil {
			t.Fatal("Split returned nil")
		}
		_ = Simplify(MapAttrs(Exclude(Inject(parsed, parsed), parsed), map[string]string{"cn": "name"}))
	})
}

// FuzzParseDN checks that ParseDN never panics and that accepted DNs
// survive String → ParseDN with Equal and String both stable.
func FuzzParseDN(f *testing.F) {
	for _, s := range []string{
		"", "dc=example,dc=com", "CN=John Smith,OU=Office,DC=corp,DC=local", "cn=Smith\\, John,ou=x",
		"ou=Sales+cn=J. Smith,dc=example,dc=net", "cn=#04024869", "cn=\\#x", "cn=a\\ ", "2.5.4.3=x",
		"cn=Іван Петренко,ou=users,dc=aldap", "cn=,ou=", "cn=x , ou = y",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		d, err := ParseDN(in)
		if err != nil {
			if d != nil {
				t.Fatal("non-nil DN with error")
			}
			return
		}
		s := d.String()
		again, err := ParseDNWithLimit(s, 3*DefaultMaxDNLen)
		if err != nil {
			t.Fatalf("re-parse of %q (from %q): %v", s, in, err)
		}
		if !d.Equal(again) || again.String() != s || again.Canonical() != d.Canonical() {
			t.Fatalf("round trip %q -> %q -> %q", in, s, again.String())
		}
		if !d.IsUnder(d) || !d.IsUnder(nil) {
			t.Fatal("IsUnder self/root")
		}
		if r, err := d.Rewrite(d.Parent(), &DN{}); err != nil || r.Depth() != min(d.Depth(), 1) {
			t.Fatalf("Rewrite to root: %v %q", err, r)
		}
		_ = d.Parent().Child(d.RDN())
	})
}
