package notify

// Audit 14 / A.2 — hostile event fields in notification channels.

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
)

const a2Hostile = "*[evil](https://x.example) _u_ `c` ~s~ >q #h +p -m =e |t {b} .d !x \\bs ) ( \n\n*bold*"

// unescapedMD returns the first MarkdownV2 special rune not preceded by a
// backslash, or "" when the text is fully escaped.
func unescapedMD(s string) string {
	esc := false
	for _, r := range s {
		if esc {
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		if strings.ContainsRune(markdownV2Special, r) {
			return string(r)
		}
	}
	return ""
}

func TestAudit14_A2_TelegramMarkdownV2Escaped(t *testing.T) {
	tg := newMockHTTP(t, `{"ok":true,"result":{}}`, false)
	e := newEnv(t, nil)
	c := tgChannel(tg.srv.URL)
	c.Events = append(c.Events, events.BindFail)
	e.configure(t, c)
	ev := bindFail("10.0.0.5", a2Hostile)
	ev.Reason = "x_[y](z)"
	ev.Data["upstream_error"] = "LDAP Result Code 49 \"Invalid Credentials\": *80090308* _data 52e_"
	e.n.Handle(e.record(ev))
	waitFor(t, func() bool { return tg.n() == 1 })
	text := tg.field(t, 0, "text")
	if mode := tg.field(t, 0, "parse_mode"); mode != "MarkdownV2" {
		t.Fatalf("parse_mode = %q", mode)
	}
	if bad := unescapedMD(text); bad != "" {
		t.Errorf("unescaped MarkdownV2 special %q in:\n%s", bad, text)
	}
	if !strings.Contains(text, escapeMarkdownV2(a2Hostile)) {
		t.Errorf("hostile account not rendered literally:\n%s", text)
	}
}

func TestAudit14_A2_TelegramHTMLEscaped(t *testing.T) {
	tg := newMockHTTP(t, `{"ok":true,"result":{}}`, false)
	e := newEnv(t, nil)
	c := tgChannel(tg.srv.URL)
	c.ParseMode = "HTML"
	c.Events = append(c.Events, events.BindFail)
	e.configure(t, c)
	e.n.Handle(e.record(bindFail("10.0.0.5", `<a href="https://evil">click</a>&amp;<b>`)))
	waitFor(t, func() bool { return tg.n() == 1 })
	text := tg.field(t, 0, "text")
	if strings.ContainsAny(text, "<>") {
		t.Errorf("raw markup in HTML-mode text:\n%s", text)
	}
}

// Telegram rejects texts over 4096 characters; escaping after truncation
// can double the length. Informational: records the rendered size.
func TestAudit14_A2_TelegramLengthAfterEscape(t *testing.T) {
	tg := newMockHTTP(t, `{"ok":true,"result":{}}`, false)
	e := newEnv(t, nil)
	c := tgChannel(tg.srv.URL)
	e.configure(t, c)
	e.n.Handle(e.record(lockAccount(strings.Repeat(".", 3500))))
	waitFor(t, func() bool { return tg.n() == 1 })
	text := tg.field(t, 0, "text")
	t.Logf("INFO: telegram text after escaping: %d runes (raw limit 4096; Telegram counts after entity parsing)", utf8.RuneCountInString(text))
}

func TestAudit14_A2_EmailHeaderInjection(t *testing.T) {
	srvTLS, roots := testCert(t)
	smtp := newSMTPMock(t, srvTLS, false)
	e := newEnv(t, roots)
	c := emailChannel(smtp.port(), "starttls")
	c.Events = append(c.Events, events.BindFail)
	c.SubjectTemplate = "{{.Account}}"
	e.configure(t, c)
	e.n.Handle(e.record(bindFail("10.0.0.5", "x\r\nBcc: attacker@evil.example\r\nX-Inj: 1\r\n\r\nbody\n.\nRSET\nMARKER-AFTER-DOT")))
	waitFor(t, func() bool { return smtp.n() == 1 })
	msg := smtp.msg(0)
	if !strings.Contains(msg, "MARKER-AFTER-DOT") {
		t.Errorf("DATA terminated early by a lone dot line (no dot-stuffing):\n%s", msg)
	}
	head, _, _ := strings.Cut(msg, "\n\n")
	for _, line := range strings.Split(head, "\n") {
		l := strings.ToLower(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(l, "bcc:") || strings.HasPrefix(l, "x-inj:") {
			t.Errorf("injected header %q in:\n%s", line, head)
		}
	}
	// compose() directly, bypassing the subject folding.
	em := &email{from: "a@b.example", to: []string{"c@d.example"}, helo: "h"}
	raw := string(em.compose(message{subject: "s\r\nBcc: attacker@evil.example", text: "t\r\n.\r\nQUIT\r\n"}))
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	if strings.Contains(strings.ToLower(head), "\r\nbcc:") {
		t.Errorf("compose: injected header in:\n%s", head)
	}
	if strings.Contains(body, "\r\n.\r\n") {
		t.Logf("INFO: compose emits a lone dot line; safe only because smtp.Client.Data dot-stuffs (verified above)")
	}
}

func TestAudit14_A2_WebhookBodyTemplate(t *testing.T) {
	wh := newMockHTTP(t, `{}`, false)
	e := newEnv(t, nil)
	naive := webhookChannel(wh.srv.URL)
	naive.Name = "naive"
	naive.Events = append(naive.Events, events.BindFail)
	naive.BodyTemplate = `{"account":"{{.Account}}","reason":"{{.Reason}}"}`
	safe := webhookChannel(wh.srv.URL)
	safe.Name = "safe"
	safe.Events = append(safe.Events, events.BindFail)
	safe.BodyTemplate = `{"account":{{json .Account}},"reason":{{json .Reason}}}`
	e.configure(t, naive, safe)
	acct := `a"b\c` + "\n" + `","admin":true,"x":"`
	e.n.Handle(e.record(bindFail("10.0.0.5", acct)))
	waitFor(t, func() bool { return wh.n() >= 1 })
	time.Sleep(50 * time.Millisecond)
	for i := range wh.n() {
		var m map[string]any
		if err := json.Unmarshal(wh.body(i), &m); err != nil {
			t.Errorf("body %d is not JSON: %v: %s", i, err, wh.body(i))
			continue
		}
		if _, injected := m["admin"]; injected {
			t.Errorf("body %d: injected key: %s", i, wh.body(i))
		}
		if got, _ := m["account"].(string); got != acct {
			t.Errorf("body %d: account %q, want %q", i, got, acct)
		}
	}
	t.Logf("INFO: naive template: delivered=%v errors=%v (documented: invalid JSON output drops the message)",
		wh.n(), e.count("naive", ResultError))
	// Default body (no template) must be the record itself, intact.
	wh2 := newMockHTTP(t, `{}`, false)
	e2 := newEnv(t, nil)
	def := webhookChannel(wh2.srv.URL)
	def.Events = append(def.Events, events.BindFail)
	e2.configure(t, def)
	e2.n.Handle(e2.record(bindFail("10.0.0.5", acct)))
	waitFor(t, func() bool { return wh2.n() == 1 })
	var r events.Record
	if err := json.Unmarshal(wh2.body(0), &r); err != nil || r.Account != acct {
		t.Errorf("default body: %v %q", err, wh2.body(0))
	}
}

func TestAudit14_A2_VirolaJSON(t *testing.T) {
	vir := newMockHTTP(t, `{}`, true)
	pool := x509.NewCertPool()
	pool.AddCert(vir.srv.Certificate())
	e := newEnv(t, pool)
	c := virolaChannel(vir.srv.URL)
	c.Events = append(c.Events, events.BindFail)
	e.configure(t, c)
	e.n.Handle(e.record(bindFail("10.0.0.5", a2Hostile+`","admin":true`)))
	waitFor(t, func() bool { return vir.n() == 1 })
	var m map[string]any
	if err := json.Unmarshal(vir.body(0), &m); err != nil {
		t.Fatalf("virola body: %v: %s", err, vir.body(0))
	}
	if len(m) != 1 {
		t.Errorf("virola body has extra keys: %s", vir.body(0))
	}
	if s, _ := m["content"].(string); !strings.Contains(s, a2Hostile) {
		t.Errorf("content lacks literal account: %q", s)
	}
}

// Custom template_dir text is sent unescaped (documented); confirms the
// behavior so the report can state it.
func TestAudit14_A2_TelegramCustomTemplateUnescaped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bind_fail.tmpl"), []byte("Account: {{.Account}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := newMockHTTP(t, `{"ok":true,"result":{}}`, false)
	e := newEnv(t, nil)
	c := tgChannel(tg.srv.URL)
	c.TemplateDir = dir
	c.Events = append(c.Events, events.BindFail)
	cfg := config.Notify{Cooldown: config.Duration(time.Minute), DigestInterval: config.Duration(time.Minute), Channels: []config.Channel{c}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := e.n.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	e.n.Handle(e.record(bindFail("10.0.0.5", "*bold* [x](https://evil)")))
	waitFor(t, func() bool { return tg.n() == 1 })
	t.Logf("INFO: custom template text sent to Telegram verbatim: %q", tg.field(t, 0, "text"))
}
