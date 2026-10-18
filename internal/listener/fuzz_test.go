package listener

import (
	"bufio"
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// FuzzParseMessage feeds arbitrary bytes through the bounded reader and the
// LDAPMessage decoder (TESTING.md: fuzz of the listener's BER input).
func FuzzParseMessage(f *testing.F) {
	f.Add(bindPacket(1, 3, "cn=x", "pw"))
	f.Add(extendedPacket(2, oidStartTLS))
	filter, _ := ldap.CompileFilter("(&(objectClass=user)(cn=a*))")
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "Search")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=x", "base"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "size"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "time"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	op.AppendChild(filter)
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs")
	attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "attr"))
	op.AppendChild(attrs)
	f.Add(envelope(3, op, []ldap.Control{ldap.NewControlPaging(100)}).Bytes())
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff})
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Fuzz(func(_ *testing.T, data []byte) {
		raw, err := readMessage(bufio.NewReader(bytes.NewReader(data)), 1<<16)
		if err != nil {
			return
		}
		m, err := parseMessage(raw)
		if err != nil {
			return
		}
		switch m.Op {
		case ldap.ApplicationBindRequest:
			_, _ = parseBind(m.Body)
		case ldap.ApplicationSearchRequest:
			if req, err := parseSearch(m.Body); err == nil {
				_ = encodeResult(m.ID, ldap.ApplicationSearchResultDone, Result{Code: 0, Controls: req.Controls})
			}
		case ldap.ApplicationExtendedRequest:
			_, _ = extendedName(m.Body)
		default:
		}
	})
}
