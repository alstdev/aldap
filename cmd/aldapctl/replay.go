package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// replayRecord is one recorded search (JSON lines, docs/aldapctl.md
// «replay»): what the client asked and what it got. Fields other than
// filter are optional; without dns only the count is compared, without
// entries/dns only the result code.
type replayRecord struct {
	Profile    string   `json:"profile,omitempty"`
	Base       string   `json:"base"`
	Scope      string   `json:"scope"`
	Filter     string   `json:"filter"`
	Attrs      []string `json:"attrs"`
	ResultCode *int     `json:"result_code"`
	Entries    *int     `json:"entries"`
	DNList     []string `json:"dns"`
}

// replayDiff is one search whose answer differs from the recording.
type replayDiff struct {
	Line       int      `json:"line"`
	Filter     string   `json:"filter"`
	Base       string   `json:"base,omitempty"`
	Error      string   `json:"error,omitempty"`
	ResultCode []int    `json:"result_code,omitempty"`
	Entries    []int    `json:"entries,omitempty"`
	Missing    []string `json:"missing,omitempty"`
	Extra      []string `json:"extra,omitempty"`
}

type replayReport struct {
	Profile string       `json:"profile"`
	Total   int          `json:"total"`
	Same    int          `json:"same"`
	Diffs   []replayDiff `json:"diffs"`
}

// maxReplayLine bounds one recorded line.
const maxReplayLine = 1 << 20

func readReplay(r io.Reader) ([]replayRecord, []int, error) {
	var recs []replayRecord
	var lines []int
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxReplayLine)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var rec replayRecord
		dec := json.NewDecoder(strings.NewReader(line))
		if err := dec.Decode(&rec); err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", n, err)
		}
		if rec.Filter == "" {
			return nil, nil, fmt.Errorf("line %d: filter is required", n)
		}
		recs = append(recs, rec)
		lines = append(lines, n)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return recs, lines, nil
}

func dnKey(dn string) string { return strings.ToLower(strings.TrimSpace(dn)) }

// diffDNList returns the recorded DNs missing from got and the extra ones.
func diffDNList(want, got []string) (missing, extra []string) {
	w, g := map[string]string{}, map[string]string{}
	for _, d := range want {
		w[dnKey(d)] = d
	}
	for _, d := range got {
		g[dnKey(d)] = d
	}
	for k, d := range w {
		if _, ok := g[k]; !ok {
			missing = append(missing, d)
		}
	}
	for k, d := range g {
		if _, ok := w[k]; !ok {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

var errReplayDiffers = errors.New("replay: answers differ from the recording")

// replayOne runs one recorded search; an API refusal of the search is a
// difference, an unknown profile or a lost connection ends the replay.
func replayOne(s *session, c *client, rec replayRecord) (replayDiff, bool, error) {
	d := replayDiff{Filter: rec.Filter, Base: rec.Base}
	res, err := c.Test(s.ctx(), s.o.profile, testRequest{Base: rec.Base, Scope: rec.Scope, Filter: rec.Filter, Attrs: rec.Attrs})
	if err != nil {
		var ae *apiError
		if !errors.As(err, &ae) || ae.Status == 404 {
			return d, false, err
		}
		d.Error = err.Error()
		return d, true, nil
	}
	differs := false
	if rec.ResultCode != nil && *rec.ResultCode != res.ResultCode {
		d.ResultCode, differs = []int{*rec.ResultCode, res.ResultCode}, true
	}
	got := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		got = append(got, e.DN)
	}
	want := -1
	switch {
	case rec.DNList != nil:
		want = len(rec.DNList)
		d.Missing, d.Extra = diffDNList(rec.DNList, got)
		differs = differs || len(d.Missing) > 0 || len(d.Extra) > 0
	case rec.Entries != nil:
		want = *rec.Entries
	}
	if want >= 0 && want != len(got) {
		d.Entries, differs = []int{want, len(got)}, true
	}
	return d, differs, nil
}

func cmdReplay(s *session, args []string) error {
	if s.o.profile == "" {
		return usagef("replay: --profile is required")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	recs, lines, err := readReplay(f)
	_ = f.Close() //nolint:errcheck // read only
	if err != nil {
		return fmt.Errorf("replay %s: %w", args[0], err)
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	rep := replayReport{Profile: s.o.profile, Total: len(recs), Diffs: []replayDiff{}}
	for i, rec := range recs {
		d, differs, err := replayOne(s, c, rec)
		if err != nil {
			return err
		}
		d.Line = lines[i]
		if differs {
			rep.Diffs = append(rep.Diffs, d)
		} else {
			rep.Same++
		}
	}
	if s.o.json {
		if err := s.printJSON(rep); err != nil {
			return err
		}
	} else {
		writeReplay(s.out(), rep)
	}
	if len(rep.Diffs) > 0 {
		return errReplayDiffers
	}
	return nil
}

func writeReplay(w io.Writer, rep replayReport) {
	fmt.Fprintf(w, "replayed %d searches against %s: %d same, %d different\n", rep.Total, rep.Profile, rep.Same, len(rep.Diffs))
	const show = 5
	for _, d := range rep.Diffs {
		fmt.Fprintf(w, "\nline %d: %s", d.Line, d.Filter)
		if d.Base != "" {
			fmt.Fprintf(w, " base %s", d.Base)
		}
		fmt.Fprintln(w)
		if d.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", d.Error)
		}
		if d.ResultCode != nil {
			fmt.Fprintf(w, "  result code: %d -> %d\n", d.ResultCode[0], d.ResultCode[1])
		}
		if d.Entries != nil {
			fmt.Fprintf(w, "  entries: %d -> %d\n", d.Entries[0], d.Entries[1])
		}
		for _, l := range []struct {
			name string
			dns  []string
		}{{"missing", d.Missing}, {"extra", d.Extra}} {
			for i, dn := range l.dns {
				if i == show {
					fmt.Fprintf(w, "  %s: … %d more\n", l.name, len(l.dns)-show)
					break
				}
				fmt.Fprintf(w, "  %s: %s\n", l.name, dn)
			}
		}
	}
}
