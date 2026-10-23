package notify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/secret"
)

const (
	tgToken  = "S3CR3T-tg-123456:AAH0123456789abcdef"
	virToken = "S3CR3T-virola-0123456789abcdef"
	smtpPW   = "S3CR3T-smtp-0123456789"
	hookKey  = "S3CR3T-hmac-0123456789"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

// env is a notifier with a fake clock, metrics and captured logs.
type env struct {
	n     *Notifier
	clk   *clock
	m     *metrics.Metrics
	logs  *syncBuffer
	bus   *events.Bus
	sleep []time.Duration
	mu    sync.Mutex
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newEnv(t *testing.T, roots *x509.CertPool) *env {
	t.Helper()
	e := &env{clk: newClock(), m: metrics.New("test", "none", "now"), logs: &syncBuffer{}}
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.bus = events.NewBus(events.Options{Host: "aldap-test", Now: e.clk.now, Logger: log})
	e.n = New(Options{Hostname: "aldap-test", Version: "1.2.3", Logger: log, Metrics: e.m, Now: e.clk.now, RootCAs: roots,
		Sleep: func(_ context.Context, d time.Duration) {
			e.mu.Lock()
			e.sleep = append(e.sleep, d)
			e.mu.Unlock()
		}})
	t.Cleanup(e.n.Close)
	return e
}

func (e *env) configure(t *testing.T, chans ...config.Channel) {
	t.Helper()
	cfg := config.Notify{Cooldown: config.Duration(10 * time.Minute), DigestInterval: config.Duration(15 * time.Minute), Channels: chans}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := e.n.Configure(cfg); err != nil {
		t.Fatalf("configure: %v", err)
	}
}

// record wraps an event the way the bus does.
func (e *env) record(ev events.Event) events.Record { return e.bus.Wrap(ev) }

func (e *env) count(ch, result string) float64 {
	var m dto.Metric
	if err := e.m.NotifyTotal.WithLabelValues(ch, result).Write(&m); err != nil {
		return -1
	}
	return m.GetCounter().GetValue()
}

func tgChannel(url string) config.Channel {
	c := config.DefaultChannel()
	c.Name, c.Type, c.APIBase, c.ChatID, c.BotToken = "tg", "telegram", url, "-1001", secret.Inline(tgToken)
	return c
}

func virolaChannel(url string) config.Channel {
	c := config.DefaultChannel()
	c.Name, c.Type, c.BaseURL, c.RoomID, c.Token = "virola", "virola", url, 42, secret.Inline(virToken)
	return c
}

func emailChannel(port int, mode string) config.Channel {
	c := config.DefaultChannel()
	c.Name, c.Type, c.SMTPHost, c.SMTPPort, c.TLSMode = "mail", "email", "127.0.0.1", port, mode
	c.Username, c.Password, c.From, c.To = "aldap", secret.Inline(smtpPW), "ALDAP <aldap@example.test>", []string{"sec@example.test", "ops@example.test"}
	return c
}

func webhookChannel(url string) config.Channel {
	c := config.DefaultChannel()
	c.Name, c.Type, c.URL, c.HMACSecret = "hook", "webhook", url, secret.Inline(hookKey)
	return c
}

func attack(kind, id string, ev, level string) events.Event {
	return events.Event{Event: ev, Level: level, Data: map[string]any{"kind": kind, "attack_id": id, "ips": []string{"10.0.0.5", "10.0.0.6"},
		"accounts_count": 12, "failures": 40, "rate_per_min": 25.5, "first_seen": "2026-10-23T10:00:00Z", "last_seen": "2026-10-23T10:01:00Z"}}
}

func bindFail(ip, account string) events.Event {
	return events.Event{Event: events.BindFail, Level: events.LevelLow, Profile: "virola", ClientIP: ip, Account: account, Reason: "invalid_password", Data: map[string]any{"reason": "invalid_password"}}
}

func lockAccount(account string) events.Event {
	return events.Event{Event: events.Lock, Level: events.LevelMedium, Profile: "virola",
		Data: map[string]any{"target": "account", "key": account, "until": "2026-10-23T10:15:00Z", "source": "ratelimit", "failures": 3}}
}

// TESTING.md 39: attack_start reaches telegram, virola and email exactly
// once; a repeat within the cooldown is not sent; during the attack the
// other events go into one digest per interval.
func TestScenario39_CooldownAndDigest(t *testing.T) {
	srvTLS, roots := testCert(t)
	tg := newMockHTTP(t, `{"ok":true,"result":{}}`, false)
	vir := newMockHTTP(t, `{}`, true)
	smtp := newSMTPMock(t, srvTLS, false)
	e := newEnv(t, x509PoolWith(roots, vir.srv.Certificate()))
	tgc, vc, mc := tgChannel(tg.srv.URL), virolaChannel(vir.srv.URL), emailChannel(smtp.port(), "starttls")
	for _, c := range []*config.Channel{&tgc, &vc, &mc} {
		c.Events = append(c.Events, events.BindFail)
	}
	e.configure(t, tgc, vc, mc)

	start := attack("spray", "a1", events.AttackStart, events.LevelHigh)
	e.n.Handle(e.record(start))
	e.clk.add(time.Minute)
	e.n.Handle(e.record(start)) // repeat within cooldown
	for i := range 5 {
		e.clk.add(10 * time.Second)
		e.n.Handle(e.record(bindFail("10.0.0.5", "user"+itoa(i))))
	}
	e.n.Handle(e.record(lockAccount("user1")))
	e.n.Handle(e.record(attack("spray", "a1", events.AttackSummary, events.LevelHigh)))
	e.n.Tick(e.clk.add(time.Minute)) // before the interval: nothing
	waitFor(t, func() bool { return tg.n() == 1 && vir.n() == 1 && smtp.n() == 1 })
	time.Sleep(50 * time.Millisecond)
	if tg.n() != 1 || vir.n() != 1 || smtp.n() != 1 {
		t.Fatalf("before the digest interval: tg=%d virola=%d email=%d, want 1 each", tg.n(), vir.n(), smtp.n())
	}
	e.n.Tick(e.clk.add(15 * time.Minute)) // interval elapsed → one digest per channel
	waitFor(t, func() bool { return tg.n() == 2 && vir.n() == 2 && smtp.n() == 2 })
	e.n.Tick(e.clk.add(time.Second)) // empty digest is not sent
	e.n.Tick(e.clk.add(15 * time.Minute))
	time.Sleep(50 * time.Millisecond)
	if tg.n() != 2 {
		t.Fatalf("empty digest sent: tg=%d", tg.n())
	}
	digest := tg.field(t, 1, "text")
	for _, want := range []string{`digest of 7 events`, `bind\_fail: 5`, `lock: 1`, `attack\_summary: 1`, `10\.0\.0\.5 \(5\)`, `Accounts involved: 5`} {
		if !strings.Contains(digest, want) {
			t.Errorf("telegram digest lacks %q:\n%s", want, digest)
		}
	}
	if c := vir.field(t, 1, "content"); !strings.Contains(c, "digest of 7 events") || !strings.Contains(c, "Attack spray (high)") {
		t.Errorf("virola digest:\n%s", c)
	}
	if !strings.Contains(smtp.msg(1), "digest") {
		t.Errorf("email digest:\n%s", smtp.msg(1))
	}
	// A bind_fail after the attack ended is a single message again.
	e.n.Handle(e.record(bindFail("10.0.0.9", "late")))
	e.n.Handle(e.record(attack("spray", "a1", events.AttackEnd, events.LevelHigh)))
	e.n.Handle(e.record(bindFail("10.0.0.9", "late")))
	waitFor(t, func() bool { return tg.n() == 5 })
	if got := tg.field(t, 2, "text"); !strings.Contains(got, "digest of 1 events") {
		t.Errorf("final digest before attack_end: %s", got)
	}
	if got := tg.field(t, 3, "text"); !strings.Contains(got, "attack ended") {
		t.Errorf("attack_end: %s", got)
	}
	if got := tg.field(t, 4, "text"); !strings.Contains(got, "bind\\_fail") {
		t.Errorf("single bind_fail after the attack: %s", got)
	}
	if got := e.count("tg", ResultCooldown); got != 1 {
		t.Errorf("cooldown count = %v, want 1", got)
	}
	if got := e.count("tg", ResultDigested); got != 8 {
		t.Errorf("digested count = %v, want 8", got)
	}
	e.n.Close()
	if got := e.count("tg", ResultOK); got != 5 {
		t.Errorf("ok count = %v, want 5", got)
	}
	// attack_start body.
	if txt := tg.field(t, 0, "text"); !strings.Contains(txt, "attack started — spray \\(high\\)") || !strings.Contains(txt, "10\\.0\\.0\\.5, 10\\.0\\.0\\.6") {
		t.Errorf("attack_start text:\n%s", txt)
	}
	if tg.paths[0] != "/bot"+tgToken+"/sendMessage" || tg.field(t, 0, "parse_mode") != "MarkdownV2" || tg.field(t, 0, "chat_id") != "-1001" {
		t.Errorf("telegram request: %s %s", tg.paths[0], tg.body(0))
	}
	if vir.paths[0] != "/api/v1/rooms/42/messages" || vir.hdrs[0].Get("Authorization") != "Bearer "+virToken {
		t.Errorf("virola request: %s %v", vir.paths[0], vir.hdrs[0])
	}
	msg := smtp.msg(0)
	for _, want := range []string{"Subject: [ALDAP] high attack_start on aldap-test", "To: sec@example.test, ops@example.test", "Content-Transfer-Encoding: quoted-printable"} {
		if !strings.Contains(msg, want) {
			t.Errorf("email lacks %q:\n%s", want, msg)
		}
	}
	if len(smtp.auths) == 0 || !strings.Contains(smtp.auths[0], "aldap\x00"+smtpPW) {
		t.Errorf("SMTP AUTH PLAIN after STARTTLS missing: %q", smtp.auths)
	}
}

func x509PoolWith(p *x509.CertPool, certs ...*x509.Certificate) *x509.CertPool {
	p = p.Clone()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout")
}

func TestCooldown_PerKeyAndExpiry(t *testing.T) {
	hook := newMockHTTP(t, `{}`, false)
	e := newEnv(t, nil)
	c := webhookChannel(hook.srv.URL)
	c.Events = []string{"lock_account", events.UpstreamDown}
	e.configure(t, c)
	e.n.Handle(e.record(lockAccount("alice")))
	e.n.Handle(e.record(lockAccount("alice")))                                                                                                 // same key → cooldown
	e.n.Handle(e.record(lockAccount("bob")))                                                                                                   // other key → sent
	e.n.Handle(e.record(events.Event{Event: events.Lock, Level: events.LevelMedium, Data: map[string]any{"target": "ip", "key": "10.0.0.1"}})) // not selected
	e.clk.add(10 * time.Minute)
	e.n.Tick(e.clk.add(time.Minute))           // prunes
	e.n.Handle(e.record(lockAccount("alice"))) // cooldown over
	waitFor(t, func() bool { return hook.n() == 3 })
	if got := e.count("hook", ResultCooldown); got != 1 {
		t.Errorf("cooldown = %v", got)
	}
	var r events.Record
	if err := json.Unmarshal(hook.body(0), &r); err != nil || r.Event != events.Lock || r.Schema != events.SchemaID {
		t.Fatalf("default webhook body is the record: %v %s", err, hook.body(0))
	}
	if !events.VerifySignature([]byte(hookKey), hook.body(0), hook.hdrs[0].Get(events.SignatureHeader)) {
		t.Error("HMAC signature invalid")
	}
}

func TestMatches_LevelsAndAliases(t *testing.T) {
	cases := []struct {
		name   string
		events []string
		min    string
		ev     events.Event
		want   bool
	}{
		{"listed", []string{"honeytoken"}, "low", events.Event{Event: events.Honeytoken, Level: events.LevelHigh}, true},
		{"not listed", []string{"honeytoken"}, "low", events.Event{Event: events.BindFail, Level: events.LevelHigh}, false},
		{"below min level", []string{"bind_fail"}, "medium", events.Event{Event: events.BindFail, Level: events.LevelLow}, false},
		{"at min level", []string{"bind_fail"}, "medium", events.Event{Event: events.BindFail, Level: events.LevelMedium}, true},
		{"lock_account", []string{"lock_account"}, "low", lockAccount("a"), true},
		{"lock_account ip", []string{"lock_account"}, "low", events.Event{Event: events.Lock, Data: map[string]any{"target": "ip"}}, false},
		{"lock_ip", []string{"lock_ip"}, "low", events.Event{Event: events.Lock, Data: map[string]any{"target": "ip"}}, true},
		{"lock all", []string{"lock"}, "low", events.Event{Event: events.Lock, Data: map[string]any{"target": "ip"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			c := webhookChannel("https://127.0.0.1:1/")
			c.Events, c.MinLevel = tc.events, tc.min
			ch, err := e.n.build(c)
			if err != nil {
				t.Fatal(err)
			}
			if got := ch.matches(e.record(tc.ev)); got != tc.want {
				t.Errorf("matches = %v, want %v", got, tc.want)
			}
		})
	}
}

// Every event type renders on every channel type with the built-in
// templates, without "<no value>" artifacts.
func TestTemplates_EveryEventType(t *testing.T) {
	e := newEnv(t, nil)
	chans := []config.Channel{tgChannel("https://127.0.0.1:1"), virolaChannel("https://127.0.0.1:1"), emailChannel(25, "tls"), webhookChannel("https://127.0.0.1:1")}
	for _, c := range chans {
		ch, err := e.n.build(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range config.EventKinds {
			ev := events.Event{Event: kind, Level: events.LevelMedium, Profile: "p", ClientIP: "10.1.1.1", Account: "acc", Reason: "r", Upstream: "ad",
				Data: map[string]any{"kind": "spray", "attack_id": "x", "ips": []string{"10.1.1.1"}, "target": "account", "key": "acc", "state": "on",
					"server": "ldaps://dc:636", "subject": "CN=aldap", "days_left": 5, "account": "trap", "op": "bind"}}
			m, err := ch.render(e.n.data(e.record(ev), nil))
			if err != nil {
				t.Fatalf("%s/%s: %v", c.Type, kind, err)
			}
			out := m.text + m.subject + string(m.body)
			if strings.TrimSpace(out) == "" || strings.Contains(out, "<no value>") {
				t.Errorf("%s/%s rendered %q", c.Type, kind, out)
			}
			if c.Type == "webhook" && !json.Valid(m.body) {
				t.Errorf("webhook/%s: invalid JSON", kind)
			}
		}
		// A digest renders on every channel too.
		g := newDigest()
		g.add(e.record(bindFail("10.0.0.1", "a")), e.clk.now())
		g.add(e.record(attack("spray", "a1", events.AttackSummary, events.LevelHigh)), e.clk.now())
		dg, level := g.take(e.clk.now())
		m, err := ch.render(e.n.data(events.Record{Event: tmplDigest, Level: level}, dg))
		if err != nil || strings.Contains(m.text+string(m.body), "<no value>") {
			t.Errorf("%s digest: %v %q", c.Type, err, m.text+string(m.body))
		}
	}
}

func TestTemplateFuncsInSync(t *testing.T) {
	names := make([]string, 0, len(funcs))
	for k := range funcs {
		names = append(names, k)
	}
	slices.Sort(names)
	want := slices.Clone(config.NotifyTemplateFuncs)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("template funcs %v, config.NotifyTemplateFuncs %v", names, want)
	}
}

func TestTemplateDir_OverrideNotEscaped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lock.tmpl"), []byte(`*locked* {{md (get .Data "key")}} on {{.Hostname}} v{{.Version}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := newMockHTTP(t, `{"ok":true}`, false)
	e := newEnv(t, nil)
	c := tgChannel(tg.srv.URL)
	c.TemplateDir = dir
	e.configure(t, c)
	e.n.Handle(e.record(lockAccount("j.doe")))
	e.n.Handle(e.record(events.Event{Event: events.Honeytoken, Level: events.LevelHigh, Data: map[string]any{"account": "trap.user", "op": "bind"}}))
	waitFor(t, func() bool { return tg.n() == 2 })
	if got := tg.field(t, 0, "text"); got != `*locked* j\.doe on aldap-test v1.2.3` {
		t.Errorf("custom template: %q", got)
	}
	if got := tg.field(t, 1, "text"); !strings.Contains(got, `trap\.user`) {
		t.Errorf("built-in template is escaped: %q", got)
	}
	for _, bad := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, "lock.tmpl")} {
		c.TemplateDir = bad
		if _, err := e.n.build(c); err == nil {
			t.Errorf("template_dir %s: want error", bad)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "unlock.tmpl"), []byte(`{{.Nope`), 0o600); err != nil {
		t.Fatal(err)
	}
	c.TemplateDir = dir
	if _, err := e.n.build(c); err == nil {
		t.Error("broken template: want error")
	}
}

func TestTelegram_ParseModes(t *testing.T) {
	tg := newMockHTTP(t, `{"ok":true}`, false)
	e := newEnv(t, nil)
	h, n := tgChannel(tg.srv.URL), tgChannel(tg.srv.URL)
	h.Name, h.ParseMode = "html", "HTML"
	n.Name, n.ParseMode = "plain", "none"
	e.configure(t, h, n)
	e.n.Handle(e.record(events.Event{Event: events.Honeytoken, Level: events.LevelHigh, Data: map[string]any{"account": "<b>x</b>", "op": "bind"}}))
	waitFor(t, func() bool { return tg.n() == 2 })
	var html, plain string
	for i := range 2 {
		var m map[string]any
		_ = json.Unmarshal(tg.body(i), &m)
		if m["parse_mode"] == "HTML" {
			html, _ = m["text"].(string)
		} else if _, ok := m["parse_mode"]; !ok {
			plain, _ = m["text"].(string)
		}
	}
	if !strings.Contains(html, "&lt;b&gt;x&lt;/b&gt;") || !strings.Contains(plain, "<b>x</b>") {
		t.Errorf("html=%q plain=%q", html, plain)
	}
}

func TestRetry_TransientAndPermanent(t *testing.T) {
	tg := newMockHTTP(t, `{"ok":true}`, false)
	tg.failWith(500, 429)
	hook := newMockHTTP(t, `{}`, false)
	hook.failWith(400)
	e := newEnv(t, nil)
	tc, hc := tgChannel(tg.srv.URL), webhookChannel(hook.srv.URL)
	tc.Retry = config.Retry{Max: 3, Backoff: config.Duration(time.Second), MaxBackoff: config.Duration(30 * time.Second)}
	e.configure(t, tc, hc)
	e.n.Handle(e.record(lockAccount("x")))
	e.n.Close()
	if tg.n() != 3 || e.count("tg", ResultOK) != 1 || e.count("tg", ResultError) != 0 {
		t.Errorf("telegram: requests=%d ok=%v error=%v", tg.n(), e.count("tg", ResultOK), e.count("tg", ResultError))
	}
	if hook.n() != 1 || e.count("hook", ResultError) != 1 {
		t.Errorf("webhook 400 is permanent: requests=%d error=%v", hook.n(), e.count("hook", ResultError))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// 1s backoff after the 500, then the mock's error body has no
	// retry_after, so 2s.
	if !slices.Equal(e.sleep, []time.Duration{time.Second, 2 * time.Second}) {
		t.Errorf("backoff = %v", e.sleep)
	}
	if !strings.Contains(e.logs.String(), "notify: delivery failed") || !strings.Contains(e.logs.String(), "status 400") {
		t.Errorf("failure not logged:\n%s", e.logs.String())
	}
}

func TestTelegram_RetryAfterAndExhausted(t *testing.T) {
	srv := newMockHTTP(t, `{"ok":true}`, false)
	srv.failWith(429, 429, 429)
	srv.failBody = `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":7}}`
	e := newEnv(t, nil)
	c := tgChannel(srv.srv.URL)
	c.Retry = config.Retry{Max: 2, Backoff: config.Duration(time.Second), MaxBackoff: config.Duration(5 * time.Second)}
	e.configure(t, c)
	e.n.Handle(e.record(lockAccount("x")))
	e.n.Close()
	if srv.n() != 3 || e.count("tg", ResultError) != 1 {
		t.Errorf("calls=%d error=%v", srv.n(), e.count("tg", ResultError))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !slices.Equal(e.sleep, []time.Duration{5 * time.Second, 5 * time.Second}) {
		t.Errorf("retry_after capped by max_backoff: %v", e.sleep)
	}
}

// A hanging channel neither blocks Handle (the bus consumer) nor the
// other channels; its full queue drops with a metric.
func TestChannelFailure_DoesNotBlock(t *testing.T) {
	slow := newMockHTTP(t, `{}`, false)
	slow.hold = make(chan struct{})
	fast := newMockHTTP(t, `{"ok":true}`, false)
	e := newEnv(t, nil)
	e.n.o.QueueSize = 2
	sc, fc := webhookChannel(slow.srv.URL), tgChannel(fast.srv.URL)
	sc.Events, fc.Events = []string{events.BindFail}, []string{events.BindFail}
	e.configure(t, sc, fc)
	for i := range 10 {
		done := make(chan struct{})
		go func() {
			e.n.Handle(e.record(bindFail("10.9.9."+itoa(i), "u")))
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Handle blocked on a hanging channel")
		}
		waitFor(t, func() bool { return fast.n() == i+1 }) // the other channel keeps delivering
	}
	if got := e.count("hook", ResultDropped); got < 7 {
		t.Errorf("dropped = %v, want ≥ 7", got)
	}
	close(slow.hold)
}

// The notifier consumes a bus subscription: Emit never waits for it.
func TestStart_BusNotBlocked(t *testing.T) {
	hook := newMockHTTP(t, `{}`, false)
	hook.hold = make(chan struct{})
	e := newEnv(t, nil)
	c := webhookChannel(hook.srv.URL)
	c.Events = []string{events.BindFail}
	e.configure(t, c)
	e.n.Start(e.bus.Subscribe(4))
	begin := time.Now()
	for i := range 2000 {
		e.bus.Emit(bindFail("10.0.0.1", "u"+itoa(i)))
	}
	if d := time.Since(begin); d > 2*time.Second {
		t.Fatalf("Emit took %s", d)
	}
	close(hook.hold)
	waitFor(t, func() bool { return hook.n() >= 1 })
	if e.n.Tick(e.clk.now()); e.bus.Seq() != 2000 {
		t.Errorf("seq = %d", e.bus.Seq())
	}
}

func TestEmail_Modes(t *testing.T) {
	srvTLS, roots := testCert(t)
	t.Run("tls", func(t *testing.T) {
		s := newSMTPMock(t, srvTLS, true)
		e := newEnv(t, roots)
		e.configure(t, emailChannel(s.port(), "tls"))
		e.n.Handle(e.record(attack("spray", "a", events.AttackStart, events.LevelHigh)))
		waitFor(t, func() bool { return s.n() == 1 })
	})
	t.Run("starttls not offered", func(t *testing.T) {
		s := newSMTPMock(t, srvTLS, false)
		s.noTLS = true
		e := newEnv(t, roots)
		e.configure(t, emailChannel(s.port(), "starttls"))
		e.n.Handle(e.record(attack("spray", "a", events.AttackStart, events.LevelHigh)))
		e.n.Close()
		if s.n() != 0 || e.count("mail", ResultError) != 1 || !strings.Contains(e.logs.String(), "does not offer STARTTLS") {
			t.Errorf("sent=%d logs=%s", s.n(), e.logs.String())
		}
	})
	t.Run("none, rcpt 550", func(t *testing.T) {
		s := newSMTPMock(t, nil, false)
		s.failRcpt = []int{550}
		e := newEnv(t, nil)
		c := emailChannel(s.port(), "none")
		c.Username = ""
		c.SubjectTemplate = `ALDAP {{upper .Event}}`
		e.configure(t, c)
		e.n.Handle(e.record(attack("spray", "a", events.AttackStart, events.LevelHigh)))
		e.n.Handle(e.record(attack("spray", "b", events.AttackStart, events.LevelHigh)))
		e.n.Close()
		if s.n() != 1 || e.count("mail", ResultError) != 1 || !strings.Contains(s.msg(0), "Subject: ALDAP ATTACK_START") {
			t.Errorf("sent=%d errors=%v", s.n(), e.count("mail", ResultError))
		}
	})
}

func TestWebhook_BodyTemplate(t *testing.T) {
	hook := newMockHTTP(t, `{}`, false)
	e := newEnv(t, nil)
	good, bad := webhookChannel(hook.srv.URL), webhookChannel(hook.srv.URL)
	good.Name, good.HMACSecret = "good", ""
	good.BodyTemplate = `{"text": {{json (printf "%s on %s" .Event .Hostname)}}, "ips": {{json (get .Data "ips")}}}`
	good.Headers = map[string]string{"X-Team": "sec"}
	good.Method = "PUT"
	bad.Name, bad.BodyTemplate = "bad", `not json {{.Event}}`
	e.configure(t, good, bad)
	e.n.Handle(e.record(attack("spray", "a", events.AttackStart, events.LevelHigh)))
	e.n.Close()
	if hook.n() != 1 || string(hook.body(0)) != `{"text": "attack_start on aldap-test", "ips": ["10.0.0.5","10.0.0.6"]}` {
		t.Fatalf("body: %d %s", hook.n(), hook.body(0))
	}
	if hook.hdrs[0].Get("X-Team") != "sec" || hook.hdrs[0].Get(events.SignatureHeader) != "" {
		t.Errorf("headers: %v", hook.hdrs[0])
	}
	if e.count("bad", ResultError) != 1 || !strings.Contains(e.logs.String(), "not valid JSON") {
		t.Errorf("invalid JSON body not refused: %s", e.logs.String())
	}
}

func TestConfigure_KeepsDigestAndRejects(t *testing.T) {
	tg := newMockHTTP(t, `{"ok":true}`, false)
	e := newEnv(t, nil)
	c := tgChannel(tg.srv.URL)
	c.Events = append(c.Events, events.BindFail)
	e.configure(t, c)
	e.n.Handle(e.record(attack("spray", "a1", events.AttackStart, events.LevelHigh)))
	e.n.Handle(e.record(bindFail("10.0.0.1", "x")))
	e.configure(t, c) // reload: the digest moves to the new channel
	broken := c
	broken.TemplateDir = "/nonexistent"
	if err := e.n.Configure(config.Notify{Cooldown: config.Duration(time.Minute), DigestInterval: config.Duration(time.Minute), Channels: []config.Channel{broken}}); err == nil {
		t.Fatal("broken channel accepted")
	}
	e.n.Tick(e.clk.add(16 * time.Minute))
	waitFor(t, func() bool { return tg.n() == 2 })
	if !strings.Contains(tg.field(t, 0, "text")+tg.field(t, 1, "text"), "digest of 1 events") {
		t.Errorf("digest after reload missing: %s / %s", tg.body(0), tg.body(1))
	}
	// An attack whose end is lost expires after max(1h, 4×interval).
	e.n.Tick(e.clk.add(2 * time.Hour))
	e.n.Handle(e.record(bindFail("10.0.0.2", "y")))
	waitFor(t, func() bool { return tg.n() == 3 })
	e.n.Close()
	if err := e.n.Configure(config.Notify{Cooldown: config.Duration(time.Minute), DigestInterval: config.Duration(time.Minute)}); err == nil {
		t.Error("Configure after Close accepted")
	}
}

// TestNoSecretsInOutput_Notify: tokens and passwords of every channel
// never reach logs, errors, metrics or message bodies, also when the
// destination fails (the Telegram URL holds the bot token).
func TestNoSecretsInOutput_Notify(t *testing.T) {
	srvTLS, roots := testCert(t)
	dead := "http://127.0.0.1:1"
	fail := newMockHTTP(t, `{}`, false)
	fail.failWith(401, 401, 401, 401, 401, 401, 401, 401)
	smtp := newSMTPMock(t, srvTLS, false)
	smtp.failRcpt = []int{550}
	e := newEnv(t, roots)
	tg1, tg2 := tgChannel(dead), tgChannel(fail.srv.URL)
	tg1.Name, tg2.Name = "tg-dead", "tg-401"
	v1, v2 := virolaChannel(dead), virolaChannel(fail.srv.URL)
	v1.Name, v2.Name = "virola-dead", "virola-401"
	w1 := webhookChannel(dead)
	m1, m2 := emailChannel(1, "starttls"), emailChannel(smtp.port(), "starttls")
	m1.Name, m2.Name = "mail-dead", "mail-550"
	chans := []config.Channel{tg1, tg2, v1, v2, w1, m1, m2}
	for i := range chans {
		chans[i].Retry = config.Retry{Max: 1, Backoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)}
	}
	e.configure(t, chans...)
	e.n.Handle(e.record(attack("spray", "a", events.AttackStart, events.LevelHigh)))
	e.n.Close()
	var out bytes.Buffer
	out.WriteString(e.logs.String())
	fams, _ := e.m.Gather()
	for _, f := range fams {
		out.WriteString(f.String())
	}
	if !strings.Contains(out.String(), "notify: delivery failed") {
		t.Fatalf("no delivery failure logged:\n%s", out.String())
	}
	for _, secretValue := range []string{tgToken, virToken, smtpPW, hookKey, "S3CR3T"} {
		if strings.Contains(out.String(), secretValue) {
			t.Fatalf("secret %q in output:\n%s", secretValue, out.String())
		}
	}
	for i := range fail.n() {
		if strings.Contains(string(fail.body(i)), "S3CR3T") {
			t.Fatalf("secret in a message body: %s", fail.body(i))
		}
	}
	if got := e.count("tg-dead", ResultError); got != 1 {
		t.Errorf("tg-dead errors = %v", got)
	}
}
