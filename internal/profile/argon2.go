package profile

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters (SPEC §9: t=3, m=64MiB, p=4).
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	KeyLen  uint32
	SaltLen int
}

// DefaultArgon2 are the SPEC §9 parameters.
var DefaultArgon2 = Argon2Params{Time: 3, Memory: 64 * 1024, Threads: 4, KeyLen: 32, SaltLen: 16}

// maxHashLen bounds the decoded hash length of a PHC string.
const maxHashLen = 1 << 16

// ErrBadHash reports a malformed PHC string.
var ErrBadHash = errors.New("invalid argon2id hash")

// PasswordHash is a parsed argon2id PHC string, compared in constant time.
type PasswordHash struct {
	p    Argon2Params
	salt []byte
	hash []byte
}

// HashPassword derives an argon2id hash of password with a random salt.
func HashPassword(password []byte, p Argon2Params) (*PasswordHash, error) {
	if p.Time == 0 || p.Memory == 0 || p.Threads == 0 || p.KeyLen == 0 || p.SaltLen <= 0 {
		return nil, errors.New("argon2: invalid parameters")
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("argon2 salt: %w", err)
	}
	return &PasswordHash{p: p, salt: salt, hash: argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)}, nil
}

// ParsePasswordHash parses "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>".
func ParsePasswordHash(s string) (*PasswordHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, fmt.Errorf("%w: expected $argon2id$v=19$m=..,t=..,p=..$salt$hash", ErrBadHash)
	}
	if parts[2] != "v=19" {
		return nil, fmt.Errorf("%w: unsupported version %q", ErrBadHash, parts[2])
	}
	p, err := parseArgon2Params(parts[3])
	if err != nil {
		return nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return nil, fmt.Errorf("%w: salt", ErrBadHash)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) < 16 {
		return nil, fmt.Errorf("%w: hash", ErrBadHash)
	}
	if len(hash) > maxHashLen {
		return nil, fmt.Errorf("%w: hash too long", ErrBadHash)
	}
	p.KeyLen = uint32(len(hash)) //nolint:gosec // bounded by maxHashLen above
	p.SaltLen = len(salt)
	return &PasswordHash{p: p, salt: salt, hash: hash}, nil
}

// String renders the PHC form.
func (h *PasswordHash) String() string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", h.p.Memory, h.p.Time, h.p.Threads,
		base64.RawStdEncoding.EncodeToString(h.salt), base64.RawStdEncoding.EncodeToString(h.hash))
}

// Verify reports whether password matches; the comparison is constant time
// and always computes the hash, so a wrong password costs the same as a
// right one.
func (h *PasswordHash) Verify(password []byte) bool {
	got := argon2.IDKey(password, h.salt, h.p.Time, h.p.Memory, h.p.Threads, h.p.KeyLen)
	return subtle.ConstantTimeCompare(got, h.hash) == 1
}

// Params returns the cost parameters.
func (h *PasswordHash) Params() Argon2Params { return h.p }

// parseArgon2Params parses "m=65536,t=3,p=4".
func parseArgon2Params(s string) (Argon2Params, error) {
	var p Argon2Params
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return p, fmt.Errorf("%w: parameter %q", ErrBadHash, kv)
		}
		var n uint64
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n == 0 {
			return p, fmt.Errorf("%w: parameter %q", ErrBadHash, kv)
		}
		switch {
		case k == "m" && n <= 1<<32-1:
			p.Memory = uint32(n) //nolint:gosec // range checked in the case guard
		case k == "t" && n <= 1<<32-1:
			p.Time = uint32(n) //nolint:gosec // range checked in the case guard
		case k == "p" && n <= 255:
			p.Threads = uint8(n) //nolint:gosec // range checked in the case guard
		case k == "m" || k == "t" || k == "p":
			return p, fmt.Errorf("%w: parameter %q too large", ErrBadHash, k)
		default:
			return p, fmt.Errorf("%w: unknown parameter %q", ErrBadHash, k)
		}
	}
	if p.Memory == 0 || p.Time == 0 || p.Threads == 0 {
		return p, fmt.Errorf("%w: m, t and p are required", ErrBadHash)
	}
	return p, nil
}
