package events

import (
	"crypto/rand"
	"io"
	"math/big"
	"time"
)

// crockford is the ULID alphabet (Crockford base32, no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID for t: 48 bits of Unix milliseconds followed by
// 80 random bits, encoded as 26 Crockford base32 characters. rnd defaults
// to crypto/rand.
func NewULID(t time.Time, rnd io.Reader) (string, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	var b [16]byte
	ms := uint64(t.UnixMilli())
	// 48-bit timestamp: the truncation of the upper 16 bits is the ULID layout.
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms) //nolint:gosec // see above
	if _, err := io.ReadFull(rnd, b[6:]); err != nil {
		return "", err
	}
	n := new(big.Int).SetBytes(b[:])
	mask := big.NewInt(31)
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = crockford[new(big.Int).And(n, mask).Int64()]
		n.Rsh(n, 5)
	}
	return string(out[:]), nil
}
