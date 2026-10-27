package events

import (
	"regexp"
	"unicode/utf8"
)

// passwordTerm matches a filter term on a password attribute; the value is
// replaced by *** (SPEC §6: unicodePwd/userPassword values never leave the
// process). The attribute may carry options (;binary) or a matching rule.
var passwordTerm = regexp.MustCompile(`(?i)\((userpassword|unicodepwd)([;:][^=~<>]*)?(=|~=|>=|<=)[^)]*\)`)

// RedactFilter replaces the values of password attributes in an RFC 4515
// filter string with ***.
func RedactFilter(s string) string {
	return passwordTerm.ReplaceAllString(s, "($1$2$3***)")
}

// redactData applies RedactFilter to the filter fields of an event's data.
func redactData(d map[string]any) {
	for _, k := range []string{"filter_norm", "filter"} {
		if s, ok := d[k].(string); ok {
			d[k] = RedactFilter(s)
		}
	}
}

// maxFieldBytes bounds every string a record carries (SPEC §9: the ring
// buffer is buffer_size records of bounded size, whatever a client sent).
// Producers clip tighter; this is the last line.
const maxFieldBytes = 64 << 10

// clipRecord cuts over-long strings in the envelope and in data (strings
// and string lists); other values are left alone.
func clipRecord(r *Record) {
	r.Account = clipField(r.Account)
	r.Reason = clipField(r.Reason)
	for k, v := range r.Data {
		switch x := v.(type) {
		case string:
			r.Data[k] = clipField(x)
		case []string:
			out := make([]string, len(x))
			for i, s := range x {
				out[i] = clipField(s)
			}
			r.Data[k] = out
		}
	}
}

func clipField(s string) string {
	if len(s) <= maxFieldBytes {
		return s
	}
	const marker = "…"
	cut := maxFieldBytes - len(marker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker
}
