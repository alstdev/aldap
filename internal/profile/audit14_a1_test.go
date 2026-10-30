package profile

// Audit 14, area A.1: client_bind password hashing.

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func phc(params string) string {
	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	hash := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	return "$argon2id$v=19$" + params + "$" + salt + "$" + hash
}

// Check 3: the generated hash uses the SPEC §9 parameters and verification
// is constant time with respect to the password (argon2 is recomputed on
// every call, see TestAudit14_A1_ArgonCostPerVerify).
func TestAudit14_A1_DefaultArgon2Params(t *testing.T) {
	if DefaultArgon2.Time != 3 || DefaultArgon2.Memory != 64*1024 || DefaultArgon2.Threads != 4 {
		t.Errorf("DefaultArgon2 = %+v, SPEC §9 wants t=3, m=64MiB, p=4", DefaultArgon2)
	}
	h, err := HashPassword([]byte("pw"), Argon2Params{Time: 1, Memory: 1024, Threads: 1, KeyLen: 16, SaltLen: 8})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pw string
		ok bool
	}{{"pw", true}, {"pw\x00", false}, {"p", false}, {"", false}, {"PW", false}} {
		if h.Verify([]byte(tc.pw)) != tc.ok {
			t.Errorf("Verify(%q) = %v", tc.pw, !tc.ok)
		}
	}
}

// Check 3 (design evidence, passes): every Verify call recomputes argon2id;
// nothing is precomputed, so each client-bind attempt costs the full
// t/m/p work. With production parameters that is ~64 MiB and tens to
// hundreds of ms of CPU per attempt. Combined with FINDING A1-2 (lock-key
// evasion) this is a CPU/memory amplification vector bounded only by the
// per-IP limits (and unbounded from ratelimit.allow_cidrs sources).
func TestAudit14_A1_ArgonCostPerVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 production cost")
	}
	h, err := HashPassword([]byte("pw"), DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	const n = 3
	for i := 0; i < n; i++ {
		h.Verify([]byte("wrong"))
	}
	per := time.Since(start) / n
	t.Logf("argon2id(t=3,m=64MiB,p=4) per wrong client bind: %s", per)
	if per < 5*time.Millisecond {
		t.Errorf("Verify took %s: not the SPEC cost, or precomputed", per)
	}
}

// FINDING A1-5 (Low): client_bind.password_hash parameters are unbounded.
// `aldap check` only checks the "$argon2id$" prefix (config/validate.go:656)
// and ParsePasswordHash accepts any non-zero m/t/p: m=4294967295 KiB (4 TiB)
// allocates 4 TiB on the first client bind (OOM-kill of the proxy), t huge
// burns CPU forever per bind, and m=8,t=1 silently weakens the hash far
// below SPEC §9.
func TestAudit14_A1_PasswordHashParamBounds(t *testing.T) {
	cases := []struct {
		name   string
		params string
	}{
		{"memory_4TiB", "m=4294967295,t=1,p=1"},
		{"time_2^32", "m=65536,t=4294967295,p=1"},
		{"threads_255", "m=65536,t=3,p=255"},
		{"weak_m8_t1", "m=8,t=1,p=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParsePasswordHash(phc(tc.params))
			if err == nil {
				t.Errorf("FINDING: ParsePasswordHash accepted %q (params %+v); a bind would run argon2id with these costs", tc.params, h.Params())
			}
		})
	}
	// Sanity: the SPEC parameters parse.
	if _, err := ParsePasswordHash(phc("m=65536,t=3,p=4")); err != nil {
		t.Errorf("SPEC params rejected: %v", err)
	}
	if !strings.HasPrefix(phc("m=65536,t=3,p=4"), "$argon2id$v=19$") {
		t.Fatal("phc helper broken")
	}
}
