package listener

import (
	"bufio"
	"bytes"
	"errors"
	"math/rand"
	"runtime"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// FP-2 (final pass, High): an unauthenticated 1 MiB request (within
// max_request_bytes) of 520k empty attribute names made the decoder allocate
// 192 MiB (×194) and ~1.6 s of CPU; 32 connections per IP made that ~6 GiB.

func fp2SearchPacket(nAttrs int) []byte {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "m")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "id"))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "s")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "ou=virola,dc=aldap", "base"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "size"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "time"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "types"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "present"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs")
	for i := 0; i < nAttrs; i++ {
		attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "a"))
	}
	op.AppendChild(attrs)
	msg.AppendChild(op)
	return msg.Bytes()
}

func TestAudit14_FP2_ParseMemoryBounded(t *testing.T) {
	raw := fp2SearchPacket(520000)
	if len(raw) >= defaultMaxRequestBytes {
		t.Fatalf("test packet %d bytes is over the 1 MiB limit", len(raw))
	}
	got, err := readMessage(bufio.NewReader(bytes.NewReader(raw)), defaultMaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = parseMessage(got)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if alloc > uint64(len(raw)) {
		t.Errorf("a %d byte request allocated %d KiB before being refused", len(raw), alloc>>10)
	}
}

// The element cap sits just above what a legitimate request needs: exactly
// maxBERElements elements pass, one more is refused.
func TestAudit14_FP2_ElementCapBoundary(t *testing.T) {
	// Fixed elements of the packet above: envelope 1 + id 1 + op 1 + 6
	// search fields + the filter 1 + the attribute list 1 = 11.
	const fixed = 11
	for _, tc := range []struct {
		attrs int
		ok    bool
	}{{maxBERElements - fixed, true}, {maxBERElements - fixed + 1, false}} {
		_, err := parseMessage(fp2SearchPacket(tc.attrs))
		if (err == nil) != tc.ok {
			t.Errorf("%d attribute names: err = %v, want ok=%v", tc.attrs, err, tc.ok)
		}
	}
}

// The pre-scan and the decoder agree on the depth limit, so the scan is not
// a second, different limit: depths 60..70 are accepted or refused alike.
func TestAudit14_FP2_ScanAgreesWithDecoder(t *testing.T) {
	for depth := 60; depth <= 70; depth++ {
		cur := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "leaf")
		for i := 1; i < depth; i++ {
			n := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "n")
			n.AppendChild(cur) // inside out: the child is complete before it is appended
			cur = n
		}
		raw := cur.Bytes()
		_, libErr := ber.DecodePacketErr(raw)
		if scanErr := scanBER(raw); (scanErr != nil) != (libErr != nil) {
			t.Errorf("depth %d: scan err = %v, decoder err = %v", depth, scanErr, libErr)
		}
	}
	// 200 levels, built the same way, are refused by the whole path.
	cur := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "leaf")
	for i := 0; i < 200; i++ {
		n := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "n")
		n.AppendChild(cur)
		cur = n
	}
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "m")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "id"))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "b")
	op.AppendChild(cur)
	msg.AppendChild(op)
	if _, err := parseMessage(msg.Bytes()); !errors.Is(err, ErrMalformed) {
		t.Errorf("200-level nesting: err = %v, want ErrMalformed", err)
	}
}

// Whatever bytes arrive, the scan neither panics nor reads out of range.
func TestAudit14_FP2_ScanGarbage(_ *testing.T) {
	rng := rand.New(rand.NewSource(1))
	valid := fp2SearchPacket(20)
	for i := 0; i < 20000; i++ {
		var b []byte
		if i%2 == 0 {
			b = make([]byte, rng.Intn(64))
			rng.Read(b)
		} else {
			b = append([]byte(nil), valid...)
			for j := 0; j < 1+rng.Intn(4); j++ {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			b = b[:1+rng.Intn(len(b))]
		}
		_ = scanBER(b)
	}
}
