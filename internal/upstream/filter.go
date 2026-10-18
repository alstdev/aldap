package upstream

import (
	"fmt"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// PresentAll is the filter sent in place of an absolute true filter.
const PresentAll = "(objectClass=*)"

// SerializeFilter renders a filter for the upstream. RFC 4526 absolute
// filters are never sent (support in AD is unconfirmed): after Simplify, an
// absolute true filter (also when it was nested) becomes (objectClass=*) and
// an absolute false filter yields ErrAbsoluteFalse, which callers turn into
// an empty result without a query. A nil filter means (objectClass=*).
func SerializeFilter(f *ldapfilter.Filter) (string, error) {
	if f == nil {
		return PresentAll, nil
	}
	s := ldapfilter.Simplify(f)
	switch {
	case s.IsFalse():
		return "", ErrAbsoluteFalse
	case s.IsTrue():
		return PresentAll, nil
	}
	var bad error
	ldapfilter.Walk(s, func(n *ldapfilter.Filter) bool {
		switch n.Kind {
		case ldapfilter.And, ldapfilter.Or:
			if len(n.Children) == 0 {
				bad = fmt.Errorf("nested absolute %s filter left after simplification", n.Kind)
			}
		case ldapfilter.Not:
			if len(n.Children) != 1 {
				bad = fmt.Errorf("not filter with %d children", len(n.Children))
			}
		default:
		}
		return bad == nil
	})
	if bad != nil {
		return "", bad
	}
	return s.String(), nil
}
