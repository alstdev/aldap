package vdir

import (
	"strconv"
	"strings"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// Matching rule OIDs evaluated locally (AD bit matches).
const (
	ruleBitAnd = "1.2.840.113556.1.4.803"
	ruleBitOr  = "1.2.840.113556.1.4.804"
)

// dnAttrs are attributes with DN syntax: equality on them is DN equality.
var dnAttrs = map[string]bool{"member": true, "memberof": true, "distinguishedname": true, "manager": true}

// matches evaluates a filter against an in-memory entry (post-filtering of
// computed and virtual attributes, container and group entries, honeytoken
// and mock entries): case-insensitive equality, substring, presence,
// ordering (numeric when both sides are integers), approx as equality, DN
// equality for DN-syntax attributes, AD bit matching rules; any other
// extensible match does not match.
func (e *entry) matches(f *ldapfilter.Filter) bool {
	if f == nil {
		return true
	}
	switch f.Kind {
	case ldapfilter.And:
		for _, c := range f.Children {
			if !e.matches(c) {
				return false
			}
		}
		return true
	case ldapfilter.Or:
		for _, c := range f.Children {
			if e.matches(c) {
				return true
			}
		}
		return false
	case ldapfilter.Not:
		return len(f.Children) == 1 && !e.matches(f.Children[0])
	case ldapfilter.Present:
		// Every entry has an object class (AD answers (objectClass=*) for all).
		return strings.EqualFold(f.Attr, "objectClass") || len(e.get(f.Attr)) > 0
	case ldapfilter.Equality, ldapfilter.Approx:
		return e.equal(f.Attr, f.Value)
	case ldapfilter.Substring:
		for _, v := range e.get(f.Attr) {
			if substringMatch(strings.ToLower(v), f) {
				return true
			}
		}
		return false
	case ldapfilter.GreaterOrEqual:
		return e.ordering(f, func(c int) bool { return c >= 0 })
	case ldapfilter.LessOrEqual:
		return e.ordering(f, func(c int) bool { return c <= 0 })
	case ldapfilter.Extensible:
		return e.extensible(f)
	}
	return false
}

func (e *entry) equal(attr, value string) bool {
	if strings.EqualFold(attr, "objectCategory") && !strings.Contains(value, "=") {
		// AD resolves a bare class name (objectCategory=person) to the schema DN.
		for _, v := range e.get(attr) {
			if strings.EqualFold(v, value) {
				return true
			}
			if dn, err := ldapfilter.ParseDN(v); err == nil && len(dn.RDNs) > 0 && len(dn.RDNs[0].AVAs) == 1 && strings.EqualFold(dn.RDNs[0].AVAs[0].Value, value) {
				return true
			}
		}
		return false
	}
	if dnAttrs[strings.ToLower(attr)] {
		if want, err := ldapfilter.ParseDN(value); err == nil {
			w := want.Canonical()
			for _, got := range e.canonValues(attr) {
				if got == w {
					return true
				}
			}
			return false
		}
	}
	for _, v := range e.get(attr) {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

func (e *entry) ordering(f *ldapfilter.Filter, ok func(int) bool) bool {
	for _, v := range e.get(f.Attr) {
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

func (e *entry) extensible(f *ldapfilter.Filter) bool {
	switch f.MatchingRule {
	case ruleBitAnd, ruleBitOr:
		mask, err := strconv.ParseInt(f.Value, 10, 64)
		if err != nil || f.Attr == "" {
			return false
		}
		for _, v := range e.get(f.Attr) {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			if f.MatchingRule == ruleBitAnd && n&mask == mask || f.MatchingRule == ruleBitOr && n&mask != 0 {
				return true
			}
		}
		return false
	case "":
		return f.Attr != "" && e.equal(f.Attr, f.Value)
	}
	return false
}

func substringMatch(v string, f *ldapfilter.Filter) bool {
	if ini := strings.ToLower(f.Initial); ini != "" {
		if !strings.HasPrefix(v, ini) {
			return false
		}
		v = v[len(ini):]
	}
	for _, mid := range f.Any {
		a := strings.ToLower(mid)
		i := strings.Index(v, a)
		if i < 0 {
			return false
		}
		v = v[i+len(a):]
	}
	if fin := strings.ToLower(f.Final); fin != "" {
		return strings.HasSuffix(v, fin)
	}
	return true
}
