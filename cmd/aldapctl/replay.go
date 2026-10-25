package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alstdev/aldap/internal/record"
)

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

var errReplayDiffers = errors.New("replay: answers differ from the recording")

// replayOne runs one recorded search; an API refusal of the search is a
// difference, an unknown profile or a lost connection ends the replay.
func replayOne(s *session, c *client, rec record.Search) (replayDiff, bool, error) {
	d := replayDiff{Filter: rec.Filter, Base: rec.Base}
	res, err := c.Test(s.ctx(), s.o.profile, testRequest{Base: rec.Base, Scope: rec.Scope, Filter: rec.Filter, Attrs: rec.Attrs, SizeLimit: rec.SizeLimit})
	if err != nil {
		var ae *apiError
		if !errors.As(err, &ae) || ae.Status == 404 {
			return d, false, err
		}
		d.Error = err.Error()
		return d, true, nil
	}
	got := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		got = append(got, e.DN)
	}
	diff, differs := record.Compare(rec, res.ResultCode, got)
	d.ResultCode, d.Entries, d.Missing, d.Extra = diff.ResultCode, diff.Entries, diff.Missing, diff.Extra
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
	recs, lines, err := record.Read(f)
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
