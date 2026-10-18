package ldapfilter

import "strings"

// True returns the absolute-true filter "(&)" (RFC 4526).
func True() *Filter { return &Filter{Kind: And} }

// False returns the absolute-false filter "(|)" (RFC 4526).
func False() *Filter { return &Filter{Kind: Or} }

// IsTrue reports whether f is the absolute-true filter.
func (f *Filter) IsTrue() bool { return f != nil && f.Kind == And && len(f.Children) == 0 }

// IsFalse reports whether f is the absolute-false filter.
func (f *Filter) IsFalse() bool { return f != nil && f.Kind == Or && len(f.Children) == 0 }

// Inject returns "(&f extra)": the filter the client sent AND-ed with the
// profile filter. A nil or absolute-true extra returns a copy of f; an And
// f is extended instead of wrapped. Neither argument is modified.
func Inject(f, extra *Filter) *Filter {
	if extra == nil || extra.IsTrue() {
		return f.Clone()
	}
	if f == nil || f.IsTrue() {
		return extra.Clone()
	}
	out := &Filter{Kind: And}
	if f.Kind == And {
		out.Children = append(out.Children, f.Clone().Children...)
	} else {
		out.Children = append(out.Children, f.Clone())
	}
	if extra.Kind == And {
		out.Children = append(out.Children, extra.Clone().Children...)
	} else {
		out.Children = append(out.Children, extra.Clone())
	}
	return out
}

// Exclude returns "(&f(!ex))": f with the profile exclude_filter negated.
// A nil ex returns a copy of f. Neither argument is modified.
func Exclude(f, ex *Filter) *Filter {
	if ex == nil || ex.IsFalse() {
		return f.Clone()
	}
	return Inject(f, &Filter{Kind: Not, Children: []*Filter{ex.Clone()}})
}

// MapAttrs returns a copy of f with attribute descriptions renamed through
// m. Keys are matched case-insensitively against the whole description
// first and then against its type without ";options" (options are kept).
// Attributes absent from m are unchanged. The matching rule of an
// extensible match is never renamed.
func MapAttrs(f *Filter, m map[string]string) *Filter {
	lower := make(map[string]string, len(m))
	for k, v := range m {
		lower[strings.ToLower(k)] = v
	}
	out := f.Clone()
	Walk(out, func(n *Filter) bool {
		if n.Attr != "" {
			n.Attr = mapAttr(n.Attr, lower)
		}
		return true
	})
	return out
}

func mapAttr(attr string, lower map[string]string) string {
	if v, ok := lower[strings.ToLower(attr)]; ok {
		return v
	}
	typ, opts, hasOpts := strings.Cut(attr, ";")
	if !hasOpts {
		return attr
	}
	if v, ok := lower[strings.ToLower(typ)]; ok {
		return v + ";" + opts
	}
	return attr
}

// Walk visits f and its descendants in pre-order. fn returning false
// skips the children of that node.
func Walk(f *Filter, fn func(*Filter) bool) {
	if f == nil {
		return
	}
	if !fn(f) {
		return
	}
	for _, c := range f.Children {
		Walk(c, fn)
	}
}

// Attrs returns the distinct attribute descriptions used in f, in order of
// first appearance. The empty description of (:rule:=v) is skipped.
func (f *Filter) Attrs() []string {
	var out []string
	seen := map[string]bool{}
	Walk(f, func(n *Filter) bool {
		if n.Attr != "" && !seen[n.Attr] {
			seen[n.Attr] = true
			out = append(out, n.Attr)
		}
		return true
	})
	return out
}

// Class says where a filter term can be evaluated (SPEC §4.2 step 3).
type Class uint8

// Term classes returned by the Split classifier.
const (
	// Upstream terms are sent to the directory as they are (after MapAttrs).
	Upstream Class = iota
	// Local terms (computed attributes, virtual memberOf/member) can only
	// be evaluated by ALDAP on the transformed entries.
	Local
	// Denied terms name attributes outside allow/map/computed; they become
	// absolute false without an error, so the schema is not revealed.
	Denied
)

// Split separates f into the part the upstream can execute and the part
// ALDAP must evaluate itself afterwards. classify is called with the
// attribute description of every leaf (the empty string for (:rule:=v)).
//
// An And is split member by member. Any other node that mixes classes
// (an Or or Not containing a Local term) cannot be split without changing
// its meaning, so the upstream gets absolute true for it and the whole
// node is evaluated locally. Denied leaves become absolute false. Both
// results are simplified; an executable that IsFalse means no upstream
// query is needed. Entries matched by executable are a superset of the
// final result, and executable AND postfilter is equivalent to f with its
// denied terms replaced by false.
func Split(f *Filter, classify func(attr string) Class) (executable, postfilter *Filter) {
	if f == nil {
		return True(), True()
	}
	exec, post := split(f, classify)
	return Simplify(exec), Simplify(post)
}

func split(f *Filter, classify func(string) Class) (exec, post *Filter) {
	switch f.Kind {
	case And:
		exec = &Filter{Kind: And}
		post = &Filter{Kind: And}
		for _, c := range f.Children {
			e, p := split(c, classify)
			exec.Children = append(exec.Children, e)
			post.Children = append(post.Children, p)
		}
		return exec, post
	case Or, Not:
		if hasLocal(f, classify) {
			return True(), denyLeaves(f, classify)
		}
		return denyLeaves(f, classify), True()
	default:
		switch classify(f.Attr) {
		case Local:
			return True(), f.Clone()
		case Denied:
			return False(), True()
		default:
			return f.Clone(), True()
		}
	}
}

func hasLocal(f *Filter, classify func(string) Class) bool {
	found := false
	Walk(f, func(n *Filter) bool {
		if found {
			return false
		}
		if n.Kind != And && n.Kind != Or && n.Kind != Not && classify(n.Attr) == Local {
			found = true
		}
		return !found
	})
	return found
}

// denyLeaves copies f replacing Denied leaves with absolute false.
func denyLeaves(f *Filter, classify func(string) Class) *Filter {
	out := f.Clone()
	Walk(out, func(n *Filter) bool {
		if n.Kind != And && n.Kind != Or && n.Kind != Not && classify(n.Attr) == Denied {
			*n = *False()
		}
		return true
	})
	return out
}

// Simplify returns a copy of f with absolute true/false folded: an And
// drops true members and collapses to false on a false member, an Or
// drops false members and collapses to true on a true member, a single
// member And/Or becomes that member and a Not of a constant is inverted.
// Nothing else (no attribute semantics) is applied.
func Simplify(f *Filter) *Filter {
	if f == nil {
		return nil
	}
	switch f.Kind {
	case And, Or:
		absorb, drop := False(), True()
		if f.Kind == Or {
			absorb, drop = True(), False()
		}
		out := &Filter{Kind: f.Kind}
		for _, c := range f.Children {
			s := Simplify(c)
			if s.Kind == absorb.Kind && len(s.Children) == 0 {
				return absorb
			}
			if s.Kind == drop.Kind && len(s.Children) == 0 {
				continue
			}
			out.Children = append(out.Children, s)
		}
		if len(out.Children) == 1 {
			return out.Children[0]
		}
		return out
	case Not:
		if len(f.Children) == 0 {
			return f.Clone()
		}
		s := Simplify(f.Children[0])
		if s.IsTrue() {
			return False()
		}
		if s.IsFalse() {
			return True()
		}
		return &Filter{Kind: Not, Children: []*Filter{s}}
	default:
		return f.Clone()
	}
}
