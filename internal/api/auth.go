package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/secret"
)

// MinTokenBytes is the shortest accepted token (SPEC §3.4).
const MinTokenBytes = 32

// maxBuckets bounds the per-client rate-limit table.
const maxBuckets = 10000

// authState is the token and limit configuration; Configure swaps it.
type authState struct {
	tokens         []token
	metricsEnabled bool
	metricsPublic  bool
	buckets        *buckets
}

type token struct {
	name   string
	sum    [sha256.Size]byte
	scopes map[string]bool
	nets   []netip.Prefix
}

// SecretResolver resolves a token source (secret.Resolver implements it).
type SecretResolver interface {
	Resolve(secret.Source) (secret.Value, []secret.Warning, error)
}

// Configure installs the tokens, scopes, allow_cidrs, rate limit and
// metrics settings of [api]; the previous state stays on error.
func (s *Server) Configure(a config.API, res SecretResolver) error {
	st := &authState{metricsEnabled: a.Metrics.Enabled, metricsPublic: a.Metrics.Public, buckets: newBuckets(a.RateLimitRPS)}
	for i := range a.Tokens {
		tc := &a.Tokens[i]
		v, _, err := res.Resolve(tc.TokenSource())
		if err != nil {
			return fmt.Errorf("api.token[%d].token: %w", i, err)
		}
		if len(v.Reveal()) < MinTokenBytes {
			return fmt.Errorf("api.token[%d].token: must be at least %d bytes", i, MinTokenBytes)
		}
		t := token{name: tc.Name, sum: sha256.Sum256(v.Bytes()), scopes: map[string]bool{}}
		v.Wipe()
		for _, sc := range tc.Scopes {
			t.scopes[sc] = true
		}
		for _, c := range tc.AllowCIDRs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return fmt.Errorf("api.token[%d].allow_cidrs: %w", i, err)
			}
			t.nets = append(t.nets, p.Masked())
		}
		st.tokens = append(st.tokens, t)
	}
	s.auth.Store(st)
	return nil
}

// bearer extracts the token of an Authorization: Bearer header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// match finds the token in constant time: the presented value is hashed
// and compared with every configured token without an early exit, so
// neither the length nor the position of a match leaks through timing.
func (st *authState) match(presented string) *token {
	if presented == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(presented))
	found := -1
	for i := range st.tokens {
		if subtle.ConstantTimeCompare(sum[:], st.tokens[i].sum[:]) == 1 {
			found = i
		}
	}
	if found < 0 {
		return nil
	}
	return &st.tokens[found]
}

func (t *token) has(scope string) bool { return t.scopes[ScopeAdmin] || t.scopes[scope] }

// allowedFrom applies allow_cidrs (empty = any source).
func (t *token) allowedFrom(ip string) bool {
	if len(t.nets) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, n := range t.nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// buckets is a token bucket per client address (rate_limit_rps).
type buckets struct {
	rps int
	mu  sync.Mutex
	m   map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newBuckets(rps int) *buckets { return &buckets{rps: rps, m: map[string]*bucket{}} }

// take spends one request of ip; rps <= 0 disables the limit.
func (b *buckets) take(ip string, now time.Time) bool {
	if b.rps <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.m[ip]
	if !ok {
		if len(b.m) >= maxBuckets {
			b.prune(now)
		}
		k = &bucket{tokens: float64(b.rps), last: now}
		b.m[ip] = k
	}
	k.tokens += now.Sub(k.last).Seconds() * float64(b.rps)
	if k.tokens > float64(b.rps) {
		k.tokens = float64(b.rps)
	}
	k.last = now
	if k.tokens < 1 {
		return false
	}
	k.tokens--
	return true
}

// prune drops the buckets that refilled completely; if none did, the table
// is cleared so it stays bounded. The caller holds mu.
func (b *buckets) prune(now time.Time) {
	for ip, k := range b.m {
		if now.Sub(k.last) > time.Second {
			delete(b.m, ip)
		}
	}
	if len(b.m) >= maxBuckets {
		b.m = map[string]*bucket{}
	}
}
