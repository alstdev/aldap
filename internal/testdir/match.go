package testdir

import (
	"strconv"
	"strings"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// Matching rule OIDs implemented by the directory.
const (
	RuleBitAnd  = "1.2.840.113556.1.4.803"
	RuleBitOr   = "1.2.840.113556.1.4.804"
	RuleInChain = "1.2.840.113556.1.4.1941"
)

// dnAttrs are attributes with DN syntax; equality on them is DN equality.
var dnAttrs = map[string]bool{
	"member": true, "memberof": true, "distinguishedname": true, "manager": true, "managedby": true,
}

type matcher struct {
	dir *Directory
}

// match evaluates f against e. Attribute values are compared case-insensitively
// (caseIgnoreMatch), DN-syntax attributes with DN equality, and numbers
// numerically for ordering.
func (m *matcher) match(f *ldapfilter.Filter, e *Entry) bool {
	if f == nil {
		return true
	}
	switch f.Kind {
	case ldapfilter.And:
		for _, c := range f.Children {
			if !m.match(c, e) {
				return false
			}
		}
		return true
	case ldapfilter.Or:
		for _, c := range f.Children {
			if m.match(c, e) {
				return true
			}
		}
		return false
	case ldapfilter.Not:
		return len(f.Children) == 1 && !m.match(f.Children[0], e)
	case ldapfilter.Present:
		return strings.EqualFold(f.Attr, "objectClass") || e.Has(f.Attr)
	case ldapfilter.Equality, ldapfilter.Approx:
		return m.equal(f.Attr, f.Value, e)
	case ldapfilter.Substring:
		for _, v := range e.Get(f.Attr) {
			if substringMatch(strings.ToLower(v), f) {
				return true
			}
		}
		return false
	case ldapfilter.GreaterOrEqual:
		return m.ordering(f, e, func(c int) bool { return c >= 0 })
	case ldapfilter.LessOrEqual:
		return m.ordering(f, e, func(c int) bool { return c <= 0 })
	case ldapfilter.Extensible:
		return m.extensible(f, e)
	}
	return false
}

func (m *matcher) equal(attr, value string, e *Entry) bool {
	if strings.EqualFold(attr, "objectCategory") && !strings.Contains(value, "=") {
		// AD resolves a bare class name (objectCategory=person) to the schema DN.
		for _, v := range e.Get(attr) {
			if dn, err := ldapfilter.ParseDN(v); err == nil && len(dn.RDNs) > 0 && len(dn.RDNs[0].AVAs) == 1 && strings.EqualFold(dn.RDNs[0].AVAs[0].Value, value) {
				return true
			}
		}
		return false
	}
	if dnAttrs[strings.ToLower(attr)] {
		want, err := ldapfilter.ParseDN(value)
		if err == nil {
			for _, v := range e.Get(attr) {
				got, err := ldapfilter.ParseDN(v)
				if err == nil && got.Equal(want) {
					return true
				}
			}
			return false
		}
	}
	for _, v := range e.Get(attr) {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

func (m *matcher) ordering(f *ldapfilter.Filter, e *Entry, ok func(int) bool) bool {
	for _, v := range e.Get(f.Attr) {
		if ok(compareValues(v, f.Value)) {
			return true
		}
	}
	return false
}

func compareValues(a, b string) int {
	ai, errA := strconv.ParseInt(a, 10, 64)
	bi, errB := strconv.ParseInt(b, 10, 64)
	if errA == nil && errB == nil {
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
		return 0
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

func substringMatch(v string, f *ldapfilter.Filter) bool {
	if f.Initial != "" {
		p := strings.ToLower(f.Initial)
		if !strings.HasPrefix(v, p) {
			return false
		}
		v = v[len(p):]
	}
	for _, a := range f.Any {
		p := strings.ToLower(a)
		i := strings.Index(v, p)
		if i < 0 {
			return false
		}
		v = v[i+len(p):]
	}
	if f.Final != "" {
		return strings.HasSuffix(v, strings.ToLower(f.Final))
	}
	return true
}

func (m *matcher) extensible(f *ldapfilter.Filter, e *Entry) bool {
	switch f.MatchingRule {
	case RuleBitAnd, RuleBitOr:
		mask, err := strconv.ParseInt(f.Value, 10, 64)
		if err != nil {
			return false
		}
		for _, v := range e.Get(f.Attr) {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			if f.MatchingRule == RuleBitAnd && n&mask == mask {
				return true
			}
			if f.MatchingRule == RuleBitOr && n&mask != 0 {
				return true
			}
		}
		return false
	case RuleInChain:
		target, err := ldapfilter.ParseDN(f.Value)
		if err != nil {
			return false
		}
		key := target.Canonical()
		switch strings.ToLower(f.Attr) {
		case "member":
			// (member:1941:=user) matches groups that transitively contain user.
			return m.dir.transitiveMembers(e)[key]
		case "memberof":
			// (memberOf:1941:=group) matches entries transitively in group.
			return m.dir.transitiveGroups(e)[key]
		}
		return false
	case "":
		// No rule: plain equality (dnAttributes ignored).
		return f.Attr != "" && m.equal(f.Attr, f.Value, e)
	}
	return false
}
