package vdir

import (
	"testing"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

func TestEntryMatches(t *testing.T) {
	e := &entry{dn: "cn=x"}
	e.add("cn", "Alice Adams")
	e.add("mail", "alice@test.aldap", "Alice.Adams@corp.local")
	e.add("userAccountControl", "514")
	e.add("age", "42")
	e.add("name", "beta")
	e.add("member", "CN=Bob Brown, OU=Office, DC=test, DC=aldap")
	e.add("objectCategory", "CN=Person,CN=Schema,CN=Configuration,DC=test,DC=aldap")
	for _, tc := range []struct {
		filter string
		want   bool
	}{
		{"(objectClass=*)", true}, {"(cn=*)", true}, {"(sn=*)", false},
		{"(cn=alice adams)", true}, {"(cn~=alice adams)", true}, {"(cn=alice)", false},
		{"(mail=ALICE.ADAMS@corp.local)", true}, {"(mail=*@corp.local)", true}, {"(mail=al*ms*)", true}, {"(mail=*zz*)", false},
		{"(cn=A*e*ms)", true}, {"(cn=A*x)", false},
		{"(age>=42)", true}, {"(age>=43)", false}, {"(age<=42)", true}, {"(age<=41)", false}, {"(age>=4)", true},
		{"(name>=alpha)", true}, {"(name<=alpha)", false}, {"(nope>=1)", false},
		{"(userAccountControl:1.2.840.113556.1.4.803:=2)", true}, {"(userAccountControl:1.2.840.113556.1.4.803:=4)", false},
		{"(userAccountControl:1.2.840.113556.1.4.804:=6)", true}, {"(userAccountControl:1.2.840.113556.1.4.804:=8)", false},
		{"(userAccountControl:1.2.840.113556.1.4.803:=x)", false}, {"(cn:1.2.840.113556.1.4.803:=2)", false},
		{"(cn:caseIgnoreMatch:=alice adams)", false}, {"(cn:=alice adams)", true}, {"(:1.2.3:=x)", false},
		{"(member=cn=bob brown,ou=office,dc=test,dc=aldap)", true}, {"(member=cn=bob,ou=office,dc=test,dc=aldap)", false}, {"(member=not a dn)", false},
		{"(objectCategory=person)", true}, {"(objectCategory=group)", false}, {"(objectCategory=CN=Person,CN=Schema,CN=Configuration,DC=test,DC=aldap)", true},
		{"(&(cn=*)(age>=1))", true}, {"(|(sn=*)(age>=1))", true}, {"(!(age>=1))", false}, {"(&)", true}, {"(|)", false},
	} {
		f, err := ldapfilter.Parse(tc.filter)
		if err != nil {
			t.Fatalf("%s: %v", tc.filter, err)
		}
		if got := e.matches(f); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.filter, got, tc.want)
		}
	}
	if !e.matches(nil) {
		t.Error("nil filter")
	}
	e.set("mail")
	if e.get("mail") != nil {
		t.Error("set without values must remove")
	}
	e.set("new", "v")
	if e.get("new")[0] != "v" {
		t.Error("set adds")
	}
}
