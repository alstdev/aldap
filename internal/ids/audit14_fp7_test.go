package ids

import (
	"fmt"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
)

// FP-7b (final pass, Medium): with the indicator table full, every bind from
// a new address evicted ONE indicator after a scan of the whole table with a
// decay computation per entry — 23 ms per bind at 100 000 entries, under the
// engine lock that every bind of every client passes. An attacker with many
// source addresses (IPv6 rotation) could hold the lock ~45 binds per second.
func TestAudit14_FP7_FullIndicatorTableIsAmortized(t *testing.T) {
	const limit = 30000
	cfg := config.Default().Intrusion
	now := time.Unix(1_800_000_000, 0)
	e := New(cfg, Options{Now: func() time.Time { return now }, MaxSources: limit})
	for i := 0; i < limit; i++ {
		e.Bind(BindObs{Profile: "p", IP: fmt.Sprintf("2001:db8::%x", i+1), Account: "a", OK: false})
	}
	const extra = 300
	start := time.Now()
	for i := 0; i < extra; i++ {
		e.Bind(BindObs{Profile: "p", IP: fmt.Sprintf("2001:db8:1::%x", i+1), Account: "a", OK: false})
	}
	if per := time.Since(start) / extra; per > 2*time.Millisecond {
		t.Fatalf("each bind from a new address costs %s with a full table (one scan per key)", per)
	}
	e.mu.Lock()
	n := len(e.ind)
	e.mu.Unlock()
	if n > limit {
		t.Errorf("indicator table holds %d entries, max %d", n, limit)
	}
}

// What eviction keeps: the sources worth keeping (a honeytoken hit scores
// 100) survive a flood of fresh addresses that score 1 each.
func TestAudit14_FP7_EvictionKeepsHighScores(t *testing.T) {
	cfg := config.Default().Intrusion
	now := time.Unix(1_800_000_000, 0)
	e := New(cfg, Options{Now: func() time.Time { return now }, MaxSources: 1000})
	e.score(keyIP("203.0.113.9"), 100, now)
	for i := 0; i < 5000; i++ {
		e.Bind(BindObs{Profile: "p", IP: fmt.Sprintf("2001:db8::%x", i+1), Account: "a", OK: false})
	}
	found := false
	for _, in := range e.Indicators(50) {
		found = found || (in.Type == "ip" && in.Key == "203.0.113.9")
	}
	if !found {
		t.Error("the high-score indicator was evicted by a flood of fresh addresses")
	}
	e.mu.Lock()
	n := len(e.ind)
	e.mu.Unlock()
	if n > 1000 {
		t.Errorf("indicator table holds %d entries, max 1000", n)
	}
}
