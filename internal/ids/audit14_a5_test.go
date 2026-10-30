package ids

// Audit 14, area A.5 (IDS correctness). Adversarial tests; see
// ratelimit/audit14_a5_test.go for the limiter.

import (
	"fmt"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
)

// Check 9: the per-source table evicts the least recently seen source
// when MaxSources is reached. An attacker who can present MaxSources other
// addresses (IPv6 /64 rotation, or a trusted PROXY header) between two
// batches wipes the history of his attack address and stays below every
// per-source threshold. In production MaxSources = 100000.
func TestAudit14_A5_SourceEvictionClearsAttackHistory(t *testing.T) {
	e, ev, cl, _ := newTest(t, nil) // MaxSources = 100, spray.min_accounts = 5
	for i := 0; i < 4; i++ {
		bind(e, "2001:db8::bad", fmt.Sprintf("user%d", i), "Spring2026!", false)
	}
	cl.add(time.Second)
	for i := 0; i < 100; i++ { // the flood evicts 2001:db8::bad (oldest)
		bind(e, fmt.Sprintf("2001:db8::%x", i+1), "nobody", "x", false)
	}
	cl.add(time.Second)
	for i := 4; i < 8; i++ {
		bind(e, "2001:db8::bad", fmt.Sprintf("user%d", i), "Spring2026!", false)
	}
	if n := len(ev.find(events.AttackStart, func(e events.Event) bool { return e.Data["kind"] == KindSpray })); n == 0 {
		t.Error("INFO: 8 accounts sprayed with one password from one address within the window, no spray detected (history evicted by 100 other sources)")
	}
}

// Check 9: the enumeration streak resets on any successful bind from the
// source, so an attacker who owns one valid credential (or binds as a
// honeypot-free service account he knows) interleaves a success every
// min_accounts-1 attempts; with <= (min_pairs+1)/2 - 1 distinct passwords
// and < spray.min_accounts accounts per password he passes under every bind
// detector at any speed above slow_brute.max_rate_per_min.
func TestAudit14_A5_DetectorEvasionWithOneValidCredential(t *testing.T) {
	e, ev, cl, _ := newTest(t, func(c *config.Intrusion) {
		c.SlowBrute.Enabled = false // the attack runs faster than 2/min anyway
	})
	// 8 passwords x 4 accounts = 32 guesses on 32 accounts, a success every 8
	// (the success's own hash counts as a distinct password: 8+1 < 10).
	n := 0
	for pw := 0; pw < 8; pw++ {
		for a := 0; a < 4; a++ {
			bind(e, "10.0.0.1", fmt.Sprintf("victim%d", n), fmt.Sprintf("pw%d", pw), false)
			n++
			if n%8 == 0 {
				bind(e, "10.0.0.1", "attacker.own", "his-own", true)
			}
			cl.add(2 * time.Second)
		}
	}
	if starts := ev.find(events.AttackStart, nil); len(starts) == 0 {
		t.Logf("INFO: 32 guesses on 32 accounts with 8 passwords from one source, no attack_start (streak reset by a valid credential; spray best-per-hash 4 < 5; stuffing hashes 9 < 10)")
	} else {
		t.Logf("detected: %+v", starts[0].Data)
	}
}

// Check 9: blocked binds (no upstream) still feed the detectors and raise
// the level: a source that is already IP-locked reaches level high
// (accounts >= 3*min_accounts) with 15 refused binds, which with
// lockdown.auto enters lockdown. Expected to pass; evidence for the
// weaponization finding in cmd/aldap.
func TestAudit14_A5_BlockedBindsEscalateLevel(t *testing.T) {
	e, ev, _, started := newTest(t, nil)
	for i := 0; i < 15; i++ {
		e.Bind(BindObs{Profile: "p", IP: "10.0.0.7", Account: fmt.Sprintf("u%d", i), PwHash: "h:Winter2026!", OK: false, Reason: "ip_locked"})
	}
	if len(*started) == 0 {
		t.Fatal("no attack")
	}
	hi := false
	for _, a := range e.Attacks() {
		if a.Level == events.LevelHigh {
			hi = true
		}
	}
	if !hi {
		t.Errorf("level not high: %+v", e.Attacks())
	}
	_ = ev
}

// Check 9: indicator eviction drops the lowest decayed score, so an
// attacker cannot evict his own entry by flooding. Expected to pass.
func TestAudit14_A5_IndicatorEvictionKeepsHighScores(t *testing.T) {
	e, _, cl, _ := newTest(t, nil) // MaxSources = 100 bounds e.ind too
	e.score(keyIP("10.0.0.1"), weightHoneytoken, cl.now())
	for i := 0; i < 300; i++ {
		e.score(keyIP(fmt.Sprintf("10.1.%d.%d", i/256, i%256)), weightBindFail, cl.now())
	}
	found := false
	for _, in := range e.Indicators(50) {
		if in.Key == "10.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Error("high-score indicator evicted by a flood")
	}
}
