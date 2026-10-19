package events

import "regexp"

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
