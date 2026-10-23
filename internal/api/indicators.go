package api

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/ratelimit"
)

// indicator is the API view of ids.Indicator (docs/openapi.yaml Indicator).
type indicator struct {
	Target    string         `json:"target"`
	Key       string         `json:"key"`
	Score     float64        `json:"score"`
	Reasons   []string       `json:"reasons"`
	Hits      map[string]int `json:"hits"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Locked    bool           `json:"locked"`
}

func (s *Server) indicators(minScore float64) []indicator {
	locked := map[string]bool{}
	for _, l := range s.o.Limiter.Locks() {
		locked[l.Target+":"+l.Key] = true
	}
	list := s.o.IDs.Indicators(minScore)
	out := make([]indicator, 0, len(list))
	for _, in := range list {
		out = append(out, indicator{Target: in.Type, Key: in.Key, Score: in.Score, Reasons: sortedReasons(in.Hits), Hits: in.Hits,
			FirstSeen: in.FirstSeen.UTC(), LastSeen: in.LastSeen.UTC(), Locked: locked[in.Type+":"+in.Key]})
	}
	return out
}

func (s *Server) handleIndicators(w http.ResponseWriter, r *http.Request, _ *call) {
	q := r.URL.Query()
	minScore := 0.0
	if v := q.Get("min_score"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || math.IsInf(f, 0) || math.IsNaN(f) {
			writeError(w, http.StatusBadRequest, "bad_request", "min_score must be a non-negative number")
			return
		}
		minScore = f
	}
	format := q.Get("format")
	switch format {
	case "", "json":
		writeJSON(w, http.StatusOK, s.indicators(minScore))
	case "stix-lite":
		writeJSON(w, http.StatusOK, stixBundle(s.indicators(minScore), s.o.Now()))
	case "plain":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, plainIndicators(s.indicators(minScore)))
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "format must be json, stix-lite or plain")
	}
}

// plainIndicators renders one tab-separated line per indicator:
// target, key, score, comma-separated reasons, locked.
func plainIndicators(list []indicator) string {
	var b strings.Builder
	b.WriteString("# target\tkey\tscore\treasons\tlocked\n")
	for _, in := range list {
		fmt.Fprintf(&b, "%s\t%s\t%.2f\t%s\t%t\n", in.Target, sanitize(in.Key), in.Score, strings.Join(in.Reasons, ","), in.Locked)
	}
	return b.String()
}

// sanitize keeps a client-chosen account name on one TSV field.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// stixNamespace makes indicator ids deterministic (UUIDv5-style over the
// key), so repeated exports update the same STIX object.
var stixNamespace = []byte("aldap.indicator.v1")

func stixID(prefix, name string) string {
	h := sha256.Sum256(append(append([]byte{}, stixNamespace...), name...))
	u := h[:16]
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s--%x-%x-%x-%x-%x", prefix, u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// stixPattern escapes a value for a STIX 2.1 pattern string literal.
func stixPattern(target, key string) string {
	esc := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(key)
	if target == ratelimit.TargetIP {
		if a, err := netip.ParseAddr(key); err == nil && a.Is6() && !a.Is4In6() {
			return fmt.Sprintf("[ipv6-addr:value = '%s']", esc)
		}
		return fmt.Sprintf("[ipv4-addr:value = '%s']", esc)
	}
	return fmt.Sprintf("[user-account:account_login = '%s']", esc)
}

// stixBundle renders the indicators as a reduced STIX 2.1 bundle
// ("stix-lite": indicator objects only, no relationships or sightings).
func stixBundle(list []indicator, now time.Time) map[string]any {
	ts := now.UTC().Format("2006-01-02T15:04:05.000Z")
	objs := make([]map[string]any, 0, len(list))
	for _, in := range list {
		conf := int(math.Min(100, math.Round(in.Score)))
		objs = append(objs, map[string]any{
			"type": "indicator", "spec_version": "2.1", "id": stixID("indicator", in.Target+":"+in.Key),
			"created": in.FirstSeen.Format("2006-01-02T15:04:05.000Z"), "modified": ts,
			"name": fmt.Sprintf("aldap %s %s", in.Target, in.Key), "indicator_types": []string{"malicious-activity"},
			"pattern": stixPattern(in.Target, in.Key), "pattern_type": "stix",
			"valid_from": in.FirstSeen.Format("2006-01-02T15:04:05.000Z"), "confidence": conf, "labels": in.Reasons,
			"x_aldap_score": in.Score, "x_aldap_last_seen": in.LastSeen.Format("2006-01-02T15:04:05.000Z"), "x_aldap_locked": in.Locked,
		})
	}
	return map[string]any{"type": "bundle", "id": stixID("bundle", ts), "objects": objs}
}
