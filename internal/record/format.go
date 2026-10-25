package record

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/alstdev/aldap/internal/ldapfilter"
)

// MaxLine bounds one JSON line of a recording. The recorder leaves dns
// out of a search whose line would be longer (only the count is then
// compared by replay); the reader refuses longer lines.
const MaxLine = 1 << 20

// Search is one recorded client search: what the client asked and what it
// got. It is the format of the recorder and of `aldapctl replay`
// (docs/aldapctl.md «Replay»): JSON lines, `#` comments and blank lines
// skipped. Only filter is required on read; without dns only the count is
// compared, without entries/dns only the result code. The recording never
// holds passwords (password-like attribute values in the filter are
// replaced, see RedactFilter), bind data, paging cookies, client
// addresses or account names.
type Search struct {
	// TS is the time of the search (RFC 3339, UTC); informational.
	TS      string   `json:"ts,omitempty"`
	Profile string   `json:"profile,omitempty"`
	Base    string   `json:"base"`
	Scope   string   `json:"scope"`
	Filter  string   `json:"filter"`
	Attrs   []string `json:"attrs"`
	// SizeLimit is the client size limit (0 = none, omitted).
	SizeLimit  int      `json:"size_limit,omitempty"`
	ResultCode *int     `json:"result_code"`
	Entries    *int     `json:"entries"`
	DNList     []string `json:"dns"`
}

// Read parses a recording. It returns the searches and the line number of
// each (for reports).
func Read(r io.Reader) ([]Search, []int, error) {
	var recs []Search
	var lines []int
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), MaxLine+1)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var rec Search
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", n, err)
		}
		if rec.Filter == "" {
			return nil, nil, fmt.Errorf("line %d: filter is required", n)
		}
		if rec.SizeLimit < 0 {
			return nil, nil, fmt.Errorf("line %d: size_limit is negative", n)
		}
		recs = append(recs, rec)
		lines = append(lines, n)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("line %d: %w", n+1, err)
	}
	return recs, lines, nil
}

// Redacted replaces password-like values in recorded filters.
const Redacted = "***"

// nonSecretPwdAttrs are password-policy timestamps and counters whose
// names contain "pwd"/"password" but whose values are no secret (AD
// pwdLastSet, badPwdCount, badPasswordTime; OpenLDAP ppolicy
// pwdChangedTime, pwdAccountLockedTime, pwdFailureTime): recorded as
// they are so replay keeps their filters.
var nonSecretPwdAttrs = map[string]bool{
	"pwdlastset": true, "badpwdcount": true, "badpasswordtime": true,
	"pwdchangedtime": true, "pwdaccountlockedtime": true, "pwdfailuretime": true,
}

// IsSecretAttr reports an attribute whose values must not be recorded:
// its name contains pwd, password, credential or secret (userPassword,
// unicodePwd, dBCSPwd, ntPwdHistory, ms-Mcs-AdmPwd, msLAPS-Password,
// supplementalCredentials, …), case-insensitive, options included, except
// the policy timestamps and counters of nonSecretPwdAttrs.
func IsSecretAttr(attr string) bool {
	l := strings.ToLower(attr)
	if i := strings.IndexByte(l, ';'); i >= 0 {
		if nonSecretPwdAttrs[l[:i]] {
			return false
		}
	} else if nonSecretPwdAttrs[l] {
		return false
	}
	for _, s := range []string{"pwd", "password", "credential", "secret"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// RedactFilter renders f with every value of a secret attribute (and of
// an extensible match without attribute, whose target is unknown)
// replaced by "***" as an equality value; presence terms stay. f is not
// changed.
func RedactFilter(f *ldapfilter.Filter) string {
	if f == nil {
		return ""
	}
	c := f.Clone()
	ldapfilter.Walk(c, func(x *ldapfilter.Filter) bool {
		switch x.Kind {
		case ldapfilter.And, ldapfilter.Or, ldapfilter.Not, ldapfilter.Present:
		case ldapfilter.Extensible:
			if x.Attr == "" || IsSecretAttr(x.Attr) {
				x.Value = Redacted
			}
		case ldapfilter.Substring:
			if IsSecretAttr(x.Attr) {
				x.Kind, x.Value, x.Initial, x.Any, x.Final = ldapfilter.Equality, Redacted, "", nil, ""
			}
		case ldapfilter.Equality, ldapfilter.GreaterOrEqual, ldapfilter.LessOrEqual, ldapfilter.Approx:
			if IsSecretAttr(x.Attr) {
				x.Value = Redacted
			}
		}
		return true
	})
	return c.String()
}
