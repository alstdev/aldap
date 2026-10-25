package record

import (
	"sort"
	"strings"
)

// Diff is how an answer differs from a recorded search: [recorded,
// replayed] result codes and entry counts, recorded DNs missing from the
// answer and DNs only the answer has.
type Diff struct {
	ResultCode []int    `json:"result_code,omitempty"`
	Entries    []int    `json:"entries,omitempty"`
	Missing    []string `json:"missing,omitempty"`
	Extra      []string `json:"extra,omitempty"`
}

// Compare checks an answer against rec (aldapctl replay): the result code
// when it was recorded, the DN set (case-insensitive) when dns was
// recorded, otherwise the number of entries when it was recorded.
func Compare(rec Search, code int, dns []string) (Diff, bool) {
	var d Diff
	differs := false
	if rec.ResultCode != nil && *rec.ResultCode != code {
		d.ResultCode, differs = []int{*rec.ResultCode, code}, true
	}
	want := -1
	switch {
	case rec.DNList != nil:
		want = len(rec.DNList)
		d.Missing, d.Extra = DiffDNList(rec.DNList, dns)
		differs = differs || len(d.Missing) > 0 || len(d.Extra) > 0
	case rec.Entries != nil:
		want = *rec.Entries
	}
	if want >= 0 && want != len(dns) {
		d.Entries, differs = []int{want, len(dns)}, true
	}
	return d, differs
}

func dnKey(dn string) string { return strings.ToLower(strings.TrimSpace(dn)) }

// DiffDNList returns the DNs of want missing from got and those of got not
// in want, sorted, compared case-insensitively.
func DiffDNList(want, got []string) (missing, extra []string) {
	w, g := make(map[string]bool, len(want)), make(map[string]bool, len(got))
	for _, d := range want {
		w[dnKey(d)] = true
	}
	for _, d := range got {
		g[dnKey(d)] = true
		if !w[dnKey(d)] {
			extra = append(extra, d)
		}
	}
	for _, d := range want {
		if !g[dnKey(d)] {
			missing = append(missing, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
