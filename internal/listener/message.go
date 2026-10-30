// Package listener accepts LDAP client connections (ldap, ldaps, StartTLS),
// enforces the transport limits of SPEC §9 and dispatches Bind and Search
// to a Handler. Every write operation, Compare and unknown extended
// operation is refused here with op_denied (SPEC §4.2, prohibition 1).
//
// The wire protocol is decoded with go-asn1-ber; filters are turned into
// their RFC 4515 text with go-ldap's DecompileFilter so that the same
// ldapfilter parser serves configuration and wire input
// (docs/DECISIONS.md).
package listener

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// maxBERDepth is the nesting the BER decoder accepts (SPEC §9: refuse
// nesting deeper than 64); go-asn1-ber's default of 1000 is far more than
// any LDAPMessage needs and gives recursive consumers less margin.
const maxBERDepth = 64

func init() {
	ber.MaxNestingDepth = maxBERDepth
}

// Protocol constants (RFC 4511).
const (
	ldapVersion3 = 3

	// OIDs.
	oidStartTLS              = "1.3.6.1.4.1.1466.20037"
	oidNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
	oidPagedResults          = "1.2.840.113556.1.4.319"

	// Maximum number of length octets accepted in a BER header (4 → 2 GiB).
	maxLengthOctets = 4
	// Minimum size of a syntactically valid LDAPMessage (SEQUENCE { INTEGER, op }).
	minMessageLen = 5
)

// Errors of the reader.
var (
	// ErrTooLarge reports a request longer than max_request_bytes.
	ErrTooLarge = errors.New("request exceeds max_request_bytes")
	// ErrNotLDAP reports input that is not a BER SEQUENCE (for example a
	// TLS ClientHello on a plain port).
	ErrNotLDAP = errors.New("not an LDAP message")
	// ErrMalformed reports a message that is BER but not a valid LDAPMessage.
	ErrMalformed = errors.New("malformed LDAP message")
)

// readMessage reads one complete BER-encoded LDAPMessage of at most max
// bytes. It parses the header itself so that an oversized length is
// rejected before any content is buffered.
func readMessage(r *bufio.Reader, maxBytes int64) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != 0x30 { // UNIVERSAL CONSTRUCTED SEQUENCE
		return nil, fmt.Errorf("%w: tag 0x%02x", ErrNotLDAP, tag)
	}
	first, err := r.ReadByte()
	if err != nil {
		return nil, unexpected(err)
	}
	hdr := []byte{tag, first}
	var length int64
	switch {
	case first < 0x80:
		length = int64(first)
	case first == 0x80:
		return nil, fmt.Errorf("%w: indefinite length", ErrMalformed)
	default:
		n := int(first & 0x7f)
		if n > maxLengthOctets {
			return nil, fmt.Errorf("%w: %d length octets", ErrTooLarge, n)
		}
		for i := 0; i < n; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return nil, unexpected(err)
			}
			hdr = append(hdr, b)
			length = length<<8 | int64(b)
		}
	}
	if maxBytes > 0 && length+int64(len(hdr)) > maxBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, length+int64(len(hdr)))
	}
	if length < minMessageLen {
		return nil, fmt.Errorf("%w: length %d", ErrMalformed, length)
	}
	buf := make([]byte, len(hdr)+int(length))
	copy(buf, hdr)
	if _, err := io.ReadFull(r, buf[len(hdr):]); err != nil {
		return nil, unexpected(err)
	}
	return buf, nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// message is one decoded LDAPMessage.
type message struct {
	ID       int64
	Op       ber.Tag
	Body     *ber.Packet
	Controls []ldap.Control
}

// maxBERElements bounds the TLV elements of one message. The decoder
// allocates a packet tree of ~370 bytes per element, so a 1 MiB request of
// 2-byte attribute names would cost ~190 MiB before any limit is checked;
// no LDAP request an application sends needs more than a few hundred.
const maxBERElements = 10000

// scanBER walks the TLV structure of one message without allocating and
// refuses what the decoder must never see: indefinite or truncated lengths,
// nesting of maxBERDepth or more (as ber.MaxNestingDepth), and more than
// maxBERElements elements.
func scanBER(b []byte) error {
	n := 0
	return scanTLV(b, 0, &n)
}

func scanTLV(b []byte, depth int, n *int) error {
	for len(b) > 0 {
		if depth >= maxBERDepth { // an element at this depth, as in ber.readPacket
			return fmt.Errorf("nesting depth %d exceeds maximum %d", depth, maxBERDepth)
		}
		if *n++; *n > maxBERElements {
			return fmt.Errorf("more than %d BER elements", maxBERElements)
		}
		constructed := b[0]&0x20 != 0
		i := 1
		if b[0]&0x1f == 0x1f { // high tag number: base-128 digits
			for {
				if i >= len(b) || i > 5 {
					return errors.New("bad tag")
				}
				more := b[i]&0x80 != 0
				i++
				if !more {
					break
				}
			}
		}
		if i >= len(b) {
			return errors.New("truncated length")
		}
		l := int(b[i])
		i++
		switch {
		case l == 0x80:
			return errors.New("indefinite length")
		case l > 0x80:
			octets := l & 0x7f
			if octets > 4 || i+octets > len(b) {
				return errors.New("bad length")
			}
			l = 0
			for _, c := range b[i : i+octets] {
				l = l<<8 | int(c)
			}
			i += octets
		}
		if l < 0 || l > len(b)-i {
			return errors.New("length exceeds the message")
		}
		if constructed {
			if err := scanTLV(b[i:i+l], depth+1, n); err != nil {
				return err
			}
		}
		b = b[i+l:]
	}
	return nil
}

// parseMessage decodes the envelope: messageID, protocolOp and controls.
func parseMessage(raw []byte) (*message, error) {
	if err := scanBER(raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	p, err := ber.DecodePacketErr(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if p.ClassType != ber.ClassUniversal || p.Tag != ber.TagSequence || len(p.Children) < 2 || len(p.Children) > 3 {
		return nil, fmt.Errorf("%w: envelope", ErrMalformed)
	}
	id, ok := p.Children[0].Value.(int64)
	if !ok || p.Children[0].ClassType != ber.ClassUniversal || p.Children[0].Tag != ber.TagInteger || id < 0 {
		return nil, fmt.Errorf("%w: messageID", ErrMalformed)
	}
	op := p.Children[1]
	if op.ClassType != ber.ClassApplication {
		return nil, fmt.Errorf("%w: protocolOp class %d", ErrMalformed, op.ClassType)
	}
	m := &message{ID: id, Op: op.Tag, Body: op}
	if len(p.Children) == 3 {
		ctl := p.Children[2]
		if ctl.ClassType != ber.ClassContext || ctl.Tag != 0 {
			return nil, fmt.Errorf("%w: controls", ErrMalformed)
		}
		for _, c := range ctl.Children {
			dc, err := ldap.DecodeControl(c)
			if err != nil {
				return nil, fmt.Errorf("%w: control: %w", ErrMalformed, err)
			}
			m.Controls = append(m.Controls, dc)
		}
	}
	return m, nil
}

// bindRequest is a decoded simple BindRequest.
type bindRequest struct {
	Version  int64
	Name     string
	Password []byte
	// SASL is set for SASL binds (refused with authMethodNotSupported).
	SASL bool
}

func parseBind(body *ber.Packet) (*bindRequest, error) {
	if len(body.Children) != 3 {
		return nil, fmt.Errorf("%w: bind request", ErrMalformed)
	}
	ver, ok := body.Children[0].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("%w: bind version", ErrMalformed)
	}
	name, ok := body.Children[1].Value.(string)
	if !ok {
		return nil, fmt.Errorf("%w: bind name", ErrMalformed)
	}
	auth := body.Children[2]
	if auth.ClassType != ber.ClassContext {
		return nil, fmt.Errorf("%w: bind authentication", ErrMalformed)
	}
	req := &bindRequest{Version: ver, Name: name}
	switch auth.Tag {
	case 0: // simple
		req.Password = append([]byte(nil), auth.Data.Bytes()...)
	case 3: // sasl
		req.SASL = true
	default:
		return nil, fmt.Errorf("%w: bind authentication choice %d", ErrMalformed, auth.Tag)
	}
	return req, nil
}

// Scope of a search.
type Scope int

// Search scopes (RFC 4511 §4.5.1.2).
const (
	ScopeBase Scope = 0
	ScopeOne  Scope = 1
	ScopeSub  Scope = 2
)

// String returns base, one or sub.
func (s Scope) String() string {
	switch s {
	case ScopeBase:
		return "base"
	case ScopeOne:
		return "one"
	case ScopeSub:
		return "sub"
	default:
		return fmt.Sprintf("scope(%d)", int(s))
	}
}

// SearchRequest is a decoded SearchRequest. Filter is the RFC 4515 text of
// the wire filter.
type SearchRequest struct {
	Base         string
	Scope        Scope
	DerefAliases int
	SizeLimit    int
	TimeLimit    time.Duration
	TypesOnly    bool
	Filter       string
	Attrs        []string
	Controls     []ldap.Control
}

func parseSearch(body *ber.Packet) (*SearchRequest, error) {
	if len(body.Children) != 8 {
		return nil, fmt.Errorf("%w: search request with %d fields", ErrMalformed, len(body.Children))
	}
	c := body.Children
	base, ok1 := c[0].Value.(string)
	scope, ok2 := c[1].Value.(int64)
	deref, ok3 := c[2].Value.(int64)
	size, ok4 := c[3].Value.(int64)
	tlim, ok5 := c[4].Value.(int64)
	typesOnly, ok6 := c[5].Value.(bool)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return nil, fmt.Errorf("%w: search request fields", ErrMalformed)
	}
	if scope < 0 || scope > 2 || size < 0 || tlim < 0 {
		return nil, fmt.Errorf("%w: search request values", ErrMalformed)
	}
	filter, err := ldap.DecompileFilter(c[6])
	if err != nil {
		return nil, fmt.Errorf("%w: filter: %w", ErrMalformed, err)
	}
	req := &SearchRequest{Base: base, Scope: Scope(scope), DerefAliases: int(deref), SizeLimit: int(size),
		TimeLimit: time.Duration(tlim) * time.Second, TypesOnly: typesOnly, Filter: filter}
	for _, a := range c[7].Children {
		s, ok := a.Value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: attribute name", ErrMalformed)
		}
		req.Attrs = append(req.Attrs, s)
	}
	return req, nil
}

// extendedName returns the requestName of an ExtendedRequest.
func extendedName(body *ber.Packet) (string, error) {
	if len(body.Children) == 0 || body.Children[0].ClassType != ber.ClassContext || body.Children[0].Tag != 0 {
		return "", fmt.Errorf("%w: extended request", ErrMalformed)
	}
	return body.Children[0].Data.String(), nil
}

// Result is the LDAPResult a handler returns for Bind and Search.
type Result struct {
	// Code is an LDAP result code (ldap.LDAPResult*).
	Code int
	// MatchedDN and Diagnostic are returned verbatim; keep them free of
	// anything that reveals the real directory.
	MatchedDN  string
	Diagnostic string
	// Controls are attached to the response (paged results cookie).
	Controls []ldap.Control
}

// Success is a Result with resultCode success.
var Success = Result{Code: ldap.LDAPResultSuccess}

// Entry is one SearchResultEntry.
type Entry struct {
	DN    string
	Attrs []Attribute
}

// Attribute is one attribute of an Entry.
type Attribute struct {
	Name   string
	Values []string
}

// Encoding helpers.

func envelope(id int64, op *ber.Packet, controls []ldap.Control) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	p.AppendChild(op)
	if len(controls) > 0 {
		ctl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		for _, c := range controls {
			ctl.AppendChild(c.Encode())
		}
		p.AppendChild(ctl)
	}
	return p
}

func ldapResult(app ber.Tag, res Result, extra ...*ber.Packet) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "LDAPResult")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, res.Code, "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.MatchedDN, "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.Diagnostic, "diagnosticMessage"))
	for _, e := range extra {
		op.AppendChild(e)
	}
	return op
}

// encodeResult builds a plain LDAPResult response of the given application tag.
func encodeResult(id int64, app ber.Tag, res Result) []byte {
	return envelope(id, ldapResult(app, res), res.Controls).Bytes()
}

// encodeExtended builds an ExtendedResponse with an optional responseName.
func encodeExtended(id int64, res Result, name string) []byte {
	var extra []*ber.Packet
	if name != "" {
		extra = append(extra, ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, name, "responseName"))
	}
	return envelope(id, ldapResult(ldap.ApplicationExtendedResponse, res, extra...), res.Controls).Bytes()
}

// encodeNotice builds the Notice of Disconnection (RFC 4511 §4.4.1).
func encodeNotice(code int, diag string) []byte {
	return encodeExtended(0, Result{Code: code, Diagnostic: diag}, oidNoticeOfDisconnection)
}

// encodeEntry builds a SearchResultEntry; with typesOnly the values are omitted.
func encodeEntry(id int64, e Entry, typesOnly bool) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SearchResultEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range e.Attrs {
		seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		if !typesOnly {
			for _, v := range a.Values {
				vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
			}
		}
		seq.AppendChild(vals)
		attrs.AppendChild(seq)
	}
	op.AppendChild(attrs)
	return envelope(id, op, nil).Bytes()
}

// responseTag maps a request application tag to its response tag; ok is
// false for requests without a response (Unbind, Abandon) and unknown tags.
func responseTag(req ber.Tag) (ber.Tag, bool) {
	switch req {
	case ldap.ApplicationBindRequest:
		return ldap.ApplicationBindResponse, true
	case ldap.ApplicationSearchRequest:
		return ldap.ApplicationSearchResultDone, true
	case ldap.ApplicationModifyRequest:
		return ldap.ApplicationModifyResponse, true
	case ldap.ApplicationAddRequest:
		return ldap.ApplicationAddResponse, true
	case ldap.ApplicationDelRequest:
		return ldap.ApplicationDelResponse, true
	case ldap.ApplicationModifyDNRequest:
		return ldap.ApplicationModifyDNResponse, true
	case ldap.ApplicationCompareRequest:
		return ldap.ApplicationCompareResponse, true
	case ldap.ApplicationExtendedRequest:
		return ldap.ApplicationExtendedResponse, true
	default:
		return 0, false
	}
}

// deniedOp maps a write/compare request tag to the op_denied op name.
func deniedOp(req ber.Tag) string {
	switch req {
	case ldap.ApplicationModifyRequest:
		return "modify"
	case ldap.ApplicationAddRequest:
		return "add"
	case ldap.ApplicationDelRequest:
		return "delete"
	case ldap.ApplicationModifyDNRequest:
		return "modrdn"
	case ldap.ApplicationCompareRequest:
		return "compare"
	case ldap.ApplicationExtendedRequest:
		return "extended"
	default:
		return ""
	}
}
