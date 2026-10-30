package ratelimit

// Audit 14, area A.1: negative cache and account-key handling of the guard.

import (
	"log/slog"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
)

func auditPolicy(t *testing.T, mod func(*config.Ratelimit)) (*Limiter, *Policy) {
	t.Helper()
	cfg := config.Default().Ratelimit
	if mod != nil {
		mod(&cfg)
	}
	l := New(Options{Logger: slog.New(slog.DiscardHandler)})
	p, err := l.Policy("audit", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l, p
}

// Check 5: the negative-cache password hash is salted with a per-process
// random salt (two limiters never agree), and the salt is used (hash of a
// password differs from plain sha256).
func TestAudit14_A1_NegativeCacheSaltPerProcess(t *testing.T) {
	a := New(Options{Logger: slog.New(slog.DiscardHandler)})
	b := New(Options{Logger: slog.New(slog.DiscardHandler)})
	if a.HashPassword([]byte("pw")) == b.HashPassword([]byte("pw")) {
		t.Error("two limiters hash the same password identically: the salt is not per process")
	}
	if len(a.salt) < 16 {
		t.Errorf("salt is %d bytes", len(a.salt))
	}
	if a.HashPassword([]byte("pw")) == a.HashPassword([]byte("pw\x00")) || a.HashPassword([]byte("")) == a.HashPassword([]byte("\x00")) {
		t.Error("distinct passwords collide")
	}
}

// Check 5: the negative cache remembers failures only, keys the account the
// same way the lock does, and a success for the pair is never recorded.
func TestAudit14_A1_NegativeCacheOnlyFailures(t *testing.T) {
	_, p := auditPolicy(t, nil)
	h := p.HashPassword([]byte("right"))
	if v := p.PreBind("10.0.0.1", "Alice", h); !v.Allowed {
		t.Fatalf("first: %+v", v)
	}
	p.PostBind("10.0.0.1", "Alice", h, true, "", time.Millisecond)
	if v := p.PreBind("10.0.0.1", "alice", h); !v.Allowed {
		t.Errorf("a successful pair was cached: %+v", v)
	}
	wrong := p.HashPassword([]byte("wrong"))
	p.PostBind("10.0.0.1", "ALICE ", wrong, false, "invalid_password", time.Millisecond)
	if v := p.PreBind("10.0.0.1", "alice", wrong); v.Allowed || v.Reason != ReasonNegativeCache {
		t.Errorf("failed pair not served from the negative cache across case/space forms: %+v", v)
	}
	// Non-credential failures (upstream_error, anonymous) are never cached.
	p.PostBind("10.0.0.1", "bob", wrong, false, "upstream_error", time.Millisecond)
	if v := p.PreBind("10.0.0.1", "bob", wrong); !v.Allowed {
		t.Errorf("upstream_error was cached: %+v", v)
	}
	// An empty account (anonymous) never enters the account tables.
	p.PostBind("10.0.0.1", "", wrong, false, "anonymous", time.Millisecond)
	if _, n := p.Failures("10.0.0.1", ""); n != 0 {
		t.Errorf("anonymous failures counted under the empty account key: %d", n)
	}
}

// Check 4 (guard side, passes): the lock, the failure window, allow_accounts
// and the API lock all normalize with normAccount (trim + lower) so the key
// the directory passes is matched consistently within this package. The
// stripping of @realm / DOMAIN\ happens in vdir.guardAccount only; see the
// vdir findings for the forms this package never sees.
func TestAudit14_A1_AccountKeyNormalizedConsistently(t *testing.T) {
	l, p := auditPolicy(t, nil)
	for i := 0; i < 3; i++ {
		p.PostBind("10.0.0.2", []string{"Alice", "ALICE", " alice "}[i], p.HashPassword([]byte{byte(i)}), false, "invalid_password", time.Millisecond)
	}
	if _, ok := l.AccountLocked("alice", l.now()); !ok {
		t.Fatal("3 failures across case/space forms did not lock")
	}
	if !l.Unlock(TargetAccount, " ALICE", SourceAPI) {
		t.Error("API unlock with another spelling missed the lock")
	}
	l.LockAccount("Bob ", l.now().Add(time.Hour), SourceAPI)
	if v := p.PreBind("10.0.0.2", "bob", ""); v.Allowed || v.Reason != ReasonAccountLocked {
		t.Errorf("API lock not applied to the bind key: %+v", v)
	}
}
