package ldapfilter

import "strings"

const hexDigits = "0123456789abcdef"

// EscapeValue escapes an assertion value for use inside a filter string
// (RFC 4515 §3): '*', '(', ')', '\' and NUL must be escaped as \XX; this
// implementation also escapes the other C0 control bytes and DEL so that
// normalised filters are safe to log. Other bytes, including UTF-8, pass
// through unchanged.
func EscapeValue(v string) string {
	if !needsFilterEscape(v) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if filterEscaped(c) {
			b.WriteByte('\\')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func needsFilterEscape(v string) bool {
	for i := 0; i < len(v); i++ {
		if filterEscaped(v[i]) {
			return true
		}
	}
	return false
}

func filterEscaped(c byte) bool {
	return c == '*' || c == '(' || c == ')' || c == '\\' || c < 0x20 || c == 0x7f
}

// UnescapeValue decodes \XX escapes of a filter assertion value. It fails
// with ErrSyntax on a truncated or non-hex escape or on a raw NUL.
func UnescapeValue(v string) (string, error) {
	p := &parser{s: v, lim: Limits{}.withDefaults()}
	out, err := p.value()
	if err != nil {
		return "", err
	}
	if p.pos != len(v) {
		return "", p.errf("unescaped %q in value", v[p.pos])
	}
	return out, nil
}
