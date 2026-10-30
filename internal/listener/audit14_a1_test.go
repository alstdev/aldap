package listener

// Audit 14, area A.1: BindRequest decoding and connection auth state.

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Check 2: the listener hands the handler the exact password bytes (NUL in
// the middle, spaces only, non-UTF-8, 512 KiB) and the exact name; nothing
// is truncated or re-encoded, and an empty password reaches the handler as
// an empty slice (the handler, not the listener, decides it is
// unauthenticated).
func TestAudit14_A1_BindBytesReachHandlerIntact(t *testing.T) {
	ts := start(t, Config{Profile: "p", MaxRequestBytes: 1 << 20})
	ts.h.bindCode = ldap.LDAPResultInvalidCredentials
	cases := []struct {
		name, user, pw string
	}{
		{"nul_mid", "alice", "ab\x00cd"},
		{"nul_only", "alice", "\x00\x00"},
		{"spaces_only", "alice", "   "},
		{"non_utf8", "alice", "p\xff\xfe\x80q"},
		{"empty_pw", "alice", ""},
		{"long_pw_512k", "alice", strings.Repeat("Q", 512<<10)},
		{"non_utf8_name", "al\xffice@x", "pw"},
		{"spaces_name", "  alice  ", "pw"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, rd := rawConn(t, ts.addr)
			_, _ = raw.Write(bindPacket(int64(i+1), 3, tc.user, tc.pw))
			m := readRaw(t, rd)
			if m.ID != int64(i+1) || resultCode(t, m) != ldap.LDAPResultInvalidCredentials {
				t.Fatalf("response id=%d code=%d", m.ID, resultCode(t, m))
			}
			ts.h.mu.Lock()
			name, pw := ts.h.binds[len(ts.h.binds)-1], ts.h.pws[len(ts.h.pws)-1]
			ts.h.mu.Unlock()
			if name != tc.user || pw != tc.pw {
				t.Errorf("handler saw name=%q pw(len %d)=%q..., want name=%q pw len %d", name, len(pw), pw[:min(len(pw), 16)], tc.user, len(tc.pw))
			}
		})
	}
}

// Check 1: a bind that the handler refuses resets the authorization state
// of the connection (RFC 4511 §4.2.1): a connection bound as a user that
// then sends a bind with an empty password ends up anonymous, never keeps
// its earlier rights.
func TestAudit14_A1_FailedBindResetsAuthState(t *testing.T) {
	ts := start(t, Config{Profile: "p"})
	ts.h.bindCode = ldap.LDAPResultInvalidCredentials
	raw, rd := rawConn(t, ts.addr)
	_, _ = raw.Write(bindPacket(1, 3, "ok", "pw"))
	if m := readRaw(t, rd); resultCode(t, m) != 0 {
		t.Fatalf("first bind: %d", resultCode(t, m))
	}
	_, _ = raw.Write(bindPacket(2, 3, "ok2", ""))
	if m := readRaw(t, rd); resultCode(t, m) != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("empty-password bind: %d", resultCode(t, m))
	}
	ts.mu.Lock()
	conns := make([]*Conn, 0, len(ts.conns))
	for c := range ts.conns {
		conns = append(conns, c)
	}
	ts.mu.Unlock()
	if len(conns) != 1 {
		t.Fatalf("conns = %d", len(conns))
	}
	if b := conns[0].Bound(); b.Kind != BindAnonymous || b.Name != "" {
		t.Errorf("after a failed rebind the connection is still bound: %+v", b)
	}
}
