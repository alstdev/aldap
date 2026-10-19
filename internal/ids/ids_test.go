package ids

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/events/schematest"
	"github.com/alstdev/aldap/internal/ldapfilter"
)

type sink struct {
	mu sync.Mutex
	ev []events.Event
}

func (s *sink) Emit(e events.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
}

func (s *sink) find(kind string, match func(events.Event) bool) []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []events.Event
	for _, e := range s.ev {
		if e.Event == kind && (match == nil || match(e)) {
			out = append(out, e)
		}
	}
	return out
}

func (s *sink) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	schematest.CheckEvents(t, s.ev...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTest(t *testing.T, mod func(*config.Intrusion)) (*Engine, *sink, *clock, *[]Attack) {
	t.Helper()
	cl := &clock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	ev := &sink{}
	cfg := config.Default().Intrusion
	cfg.Anomaly.LearnFor = config.Duration(10 * time.Second)
	if mod != nil {
		mod(&cfg)
	}
	var started []Attack
	var mu sync.Mutex
	e := New(cfg, Options{Events: ev, Logger: slog.New(slog.DiscardHandler), Now: cl.now, MaxSources: 100,
		OnAttack: func(a Attack) { mu.Lock(); started = append(started, a); mu.Unlock() }})
	return e, ev, cl, &started
}

func bind(e *Engine, ip, account, pw string, ok bool) {
	e.Bind(BindObs{Profile: "p", IP: ip, ConnID: "c-1", Account: account, PwHash: "h:" + pw, OK: ok, Reason: "invalid_password"})
}

func TestEngine_Spray(t *testing.T) {
	e, ev, cl, started := newTest(t, nil)
	// 1 password × 6 accounts within a minute (TESTING.md 27).
	for i := 0; i < 6; i++ {
		bind(e, "10.0.0.1", fmt.Sprintf("user%d", i), "Spring2026!", false)
		cl.add(10 * time.Second)
	}
	starts := ev.find(events.AttackStart, func(e events.Event) bool { return e.Data["kind"] == KindSpray })
	if len(starts) != 1 || starts[0].Data["accounts_count"] != 5 && starts[0].Data["accounts_count"] != 6 {
		t.Fatalf("attack_start: %+v", starts)
	}
	if len(*started) != 1 || (*started)[0].Kind != KindSpray || (*started)[0].IPs[0] != "10.0.0.1" {
		t.Errorf("OnAttack: %+v", *started)
	}
	// Different passwords per account are not a spray (same_password_hash).
	for i := 0; i < 6; i++ {
		bind(e, "10.0.0.2", fmt.Sprintf("other%d", i), fmt.Sprintf("pw%d", i), false)
	}
	if n := len(ev.find(events.AttackStart, nil)); n != 1 {
		t.Errorf("attack_start count = %d", n)
	}
	// Summary between, end after quiet_period.
	cl.add(5*time.Minute + time.Second)
	e.Tick()
	if len(ev.find(events.AttackSummary, nil)) != 1 {
		t.Error("attack_summary missing")
	}
	if a := e.Attacks(); len(a) != 1 || a[0].Kind != KindSpray {
		t.Errorf("attacks = %+v", a)
	}
	cl.add(15 * time.Minute)
	e.Tick()
	ends := ev.find(events.AttackEnd, nil)
	if len(ends) != 1 || ends[0].Data["attack_id"] != starts[0].Data["attack_id"] {
		t.Errorf("attack_end: %+v", ends)
	}
	if len(e.Attacks()) != 0 {
		t.Error("attack still active")
	}
	// A new spray afterwards is a new attack.
	for i := 0; i < 6; i++ {
		bind(e, "10.0.0.1", fmt.Sprintf("user%d", i), "Summer2026!", false)
	}
	if n := len(ev.find(events.AttackStart, nil)); n != 2 {
		t.Errorf("second attack_start count = %d", n)
	}
	ev.check(t)
}

func TestEngine_Enumeration(t *testing.T) {
	e, ev, _, _ := newTest(t, func(c *config.Intrusion) { c.Spray.Enabled = false })
	// 12 different accounts, different passwords, no success (TESTING.md 28).
	for i := 0; i < 12; i++ {
		bind(e, "10.0.0.3", fmt.Sprintf("acct%d", i), fmt.Sprintf("pw%d", i), false)
	}
	starts := ev.find(events.AttackStart, func(e events.Event) bool { return e.Data["kind"] == KindEnumeration })
	if len(starts) != 1 || starts[0].Level != events.LevelMedium {
		t.Fatalf("enumeration: %+v", starts)
	}
	// A success resets the streak: 9 more distinct accounts after it stay quiet... but the attack is still open, so no new start.
	bind(e, "10.0.0.4", "alice", "right", true)
	for i := 0; i < 9; i++ {
		bind(e, "10.0.0.4", fmt.Sprintf("x%d", i), fmt.Sprintf("pw%d", i), false)
	}
	if len(ev.find(events.AttackStart, nil)) != 1 {
		t.Error("streak not reset by success")
	}
	// A third source joins the active attack and raises the level to high.
	for i := 0; i < 10; i++ {
		bind(e, "10.0.0.5", fmt.Sprintf("y%d", i), "pw", false)
	}
	for i := 0; i < 10; i++ {
		bind(e, "10.0.0.6", fmt.Sprintf("z%d", i), "pw", false)
	}
	if a := e.Attacks(); len(a) != 1 || a[0].Level != events.LevelHigh || len(a[0].IPs) != 3 {
		t.Errorf("joined attack: %+v", a)
	}
	ev.check(t)
}

func TestEngine_StuffingAndSlowBrute(t *testing.T) {
	e, ev, cl, _ := newTest(t, func(c *config.Intrusion) { c.Spray.Enabled, c.Enumeration.Enabled = false, false })
	for i := 0; i < 20; i++ {
		bind(e, "10.0.1.1", fmt.Sprintf("leak%d", i), fmt.Sprintf("leaked-pw-%d", i), false)
	}
	if n := len(ev.find(events.AttackStart, func(e events.Event) bool { return e.Data["kind"] == KindStuffing })); n != 1 {
		t.Errorf("stuffing: %d", n)
	}
	// Slow brute: 30 failures spread over 5 hours (0.1/min) on one account.
	e2, ev2, cl2, _ := newTest(t, func(c *config.Intrusion) {
		c.Spray.Enabled, c.Enumeration.Enabled, c.Stuffing.Enabled = false, false, false
	})
	for i := 0; i < 30; i++ {
		bind(e2, "10.0.1.2", "admin", fmt.Sprintf("guess%d", i), false)
		cl2.add(10 * time.Minute)
	}
	if n := len(ev2.find(events.AttackStart, func(e events.Event) bool { return e.Data["kind"] == KindSlowBrute })); n != 1 {
		t.Errorf("slow_brute: %d", n)
	}
	// Fast failures are not "slow".
	e3, ev3, _, _ := newTest(t, func(c *config.Intrusion) {
		c.Spray.Enabled, c.Enumeration.Enabled, c.Stuffing.Enabled = false, false, false
	})
	for i := 0; i < 30; i++ {
		bind(e3, "10.0.1.3", "admin", fmt.Sprintf("guess%d", i), false)
	}
	if n := len(ev3.find(events.AttackStart, nil)); n != 0 {
		t.Errorf("fast brute reported as slow: %d", n)
	}
	// Disabled detectors never fire; empty IP is ignored.
	e4, ev4, _, _ := newTest(t, func(c *config.Intrusion) {
		c.Spray.Enabled, c.Enumeration.Enabled, c.Stuffing.Enabled, c.SlowBrute.Enabled = false, false, false, false
	})
	for i := 0; i < 40; i++ {
		bind(e4, "10.0.1.4", fmt.Sprintf("u%d", i), "pw", false)
		bind(e4, "", fmt.Sprintf("u%d", i), "pw", false)
	}
	if n := len(ev4.find(events.AttackStart, nil)); n != 0 {
		t.Errorf("disabled detectors fired: %d", n)
	}
	_ = cl
	ev.check(t)
	ev2.check(t)
}

func filter(t *testing.T, s string) *ldapfilter.Filter {
	t.Helper()
	f, err := ldapfilter.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestEngine_Recon(t *testing.T) {
	e, ev, cl, _ := newTest(t, nil)
	obs := SearchObs{Profile: "p", IP: "10.0.2.1", ConnID: "c-2", Account: "cn=app", Base: "ou=virola,dc=aldap", BaseKind: "virtual", Scope: "sub",
		FilterNorm: "(objectClass=*)", Filter: filter(t, "(objectClass=*)"), Attrs: []string{"nTSecurityDescriptor", "cn"}}
	e.Search(obs)
	sigs := map[string]bool{}
	for _, r := range ev.find(events.Recon, nil) {
		sigs[r.Data["signature"].(string)] = true
		if r.Data["base"] != obs.Base || r.ClientIP != "10.0.2.1" {
			t.Errorf("recon event %+v", r)
		}
	}
	if !sigs[SigSDDump] || !sigs[SigRootDump] || len(sigs) != 2 {
		t.Errorf("signatures = %v", sigs)
	}
	// Repeats within a minute are suppressed, later ones reported again.
	e.Search(obs)
	if n := len(ev.find(events.Recon, nil)); n != 2 {
		t.Errorf("repeat suppressed: %d", n)
	}
	cl.add(2 * time.Minute)
	e.Search(obs)
	if n := len(ev.find(events.Recon, nil)); n != 4 {
		t.Errorf("after a minute: %d", n)
	}
	cases := []struct {
		obs  SearchObs
		want []string
	}{
		{SearchObs{BaseKind: "users", Scope: "sub", Filter: filter(t, "(sIDHistory=*)")}, []string{SigSIDHistory}},
		{SearchObs{BaseKind: "users", Scope: "sub", Filter: filter(t, "(cn=a)"), Attrs: []string{"trustPartner"}}, []string{SigTrusts}},
		{SearchObs{BaseKind: "users", Scope: "sub", Filter: filter(t, "(msDS-AllowedToDelegateTo=*)"), Attrs: []string{"adminCount"}}, []string{SigMSDS, SigAdminCount}},
		{SearchObs{BaseKind: "users", Scope: "sub", Filter: filter(t, "(servicePrincipalName=*)"), Attrs: []string{"servicePrincipalName"}}, []string{SigSPNSweep}},
		{SearchObs{BaseKind: "users", Scope: "sub", Filter: filter(t, "(cn=exact)"), Attrs: []string{"servicePrincipalName"}}, nil},
		{SearchObs{BaseKind: "users", Scope: "sub", Attrs: []string{"servicePrincipalName;binary"}}, []string{SigSPNSweep}},
		{SearchObs{BaseKind: "outside", Scope: "base", FilterNorm: "(objectclass=*)"}, []string{SigBaseOutside}},
		{SearchObs{BaseKind: "rootdse", Scope: "base", FilterNorm: "(objectclass=*)"}, nil},
		{SearchObs{BaseKind: "rootdse", Scope: "sub", FilterNorm: "(objectclass=*)"}, []string{SigRootDump}},
		{SearchObs{BaseKind: "users", Scope: "sub", Filter: filter(t, "(uid=a)"), Attrs: []string{"uid", "mail"}}, nil},
	}
	for i, c := range cases {
		got := Signatures(c.obs)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("case %d: signatures %v, want %v", i, got, c.want)
		}
	}
	// Recon disabled: nothing.
	e2, ev2, _, _ := newTest(t, func(c *config.Intrusion) { c.Recon.Enabled = false })
	e2.Search(obs)
	if len(ev2.find(events.Recon, nil)) != 0 {
		t.Error("recon disabled")
	}
	// Scores: recon hits raise the IP indicator.
	ind := e.Indicators(0)
	if len(ind) != 1 || ind[0].Type != "ip" || ind[0].Key != "10.0.2.1" || ind[0].Hits["recon"] != 4 || ind[0].Score < 60 {
		t.Errorf("indicators = %+v", ind)
	}
	ev.check(t)
}

func TestEngine_Baseline(t *testing.T) {
	e, ev, cl, _ := newTest(t, nil)
	if !e.Learning() {
		t.Fatal("not learning")
	}
	learn := SearchObs{Profile: "p", IP: "10.0.3.1", Base: "ou=users,ou=v,dc=x", BaseKind: "users", Scope: "sub", FilterNorm: "(uid=alice)", Filter: filter(t, "(uid=alice)"), Attrs: []string{"uid", "mail"}}
	for i := 0; i < 5; i++ {
		e.Search(learn)
		bind(e, "10.0.3.1", "alice", "ok", true)
		cl.add(time.Second)
	}
	if len(ev.find(events.Anomaly, nil)) != 0 {
		t.Fatal("anomaly during learning")
	}
	cl.add(10 * time.Second)
	if e.Learning() {
		t.Fatal("still learning")
	}
	// Known pattern with another value: no anomaly.
	known := learn
	known.FilterNorm, known.Filter = "(uid=bob)", filter(t, "(uid=bob)")
	e.Search(known)
	if len(ev.find(events.Anomaly, nil)) != 0 {
		t.Errorf("new value reported: %+v", ev.find(events.Anomaly, nil))
	}
	// Bind from a new IP → new_ip (TESTING.md 31); reported once.
	bind(e, "10.9.9.9", "alice", "ok", true)
	bind(e, "10.9.9.9", "alice", "ok", true)
	if a := ev.find(events.Anomaly, func(e events.Event) bool { return e.Reason == AnomalyNewIP }); len(a) != 1 || a[0].Data["observed"] != "10.9.9.9" || a[0].Data["baseline"] != 1 {
		t.Errorf("new_ip: %+v", a)
	}
	// New filter shape, base and attribute set.
	novel := SearchObs{Profile: "p", IP: "10.0.3.1", Base: "ou=groups,ou=v,dc=x", BaseKind: "groups", Scope: "sub", FilterNorm: "(&(objectClass=group)(member=*))", Filter: filter(t, "(&(objectClass=group)(member=*))"), Attrs: []string{"member"}}
	e.Search(novel)
	reasons := map[string]bool{}
	for _, a := range ev.find(events.Anomaly, nil) {
		reasons[a.Reason] = true
	}
	if !reasons[AnomalyNewFilter] || !reasons[AnomalyNewBase] || !reasons[AnomalyNewAttrs] {
		t.Errorf("reasons = %v", reasons)
	}
	// RPS spike: 11 searches in one second after a baseline of 1/s.
	cl.add(time.Second)
	for i := 0; i < 12; i++ {
		e.Search(learn)
	}
	if a := ev.find(events.Anomaly, func(e events.Event) bool { return e.Reason == AnomalyRPSSpike }); len(a) != 1 {
		t.Errorf("rps_spike: %+v", a)
	}
	// Learn again: new values are absorbed, not reported.
	e.Learn(time.Minute)
	other := learn
	other.IP = "10.7.7.7"
	e.Search(other)
	cl.add(2 * time.Minute)
	e.Search(other)
	if a := ev.find(events.Anomaly, func(e events.Event) bool { return e.Data["observed"] == "10.7.7.7" }); len(a) != 0 {
		t.Errorf("relearned ip reported: %+v", a)
	}
	// Fingerprints: off by default, on → unknown fingerprint after learning.
	e.Fingerprint("p", "10.0.3.1", "c-1", "fp-a")
	e.Reconfigure(func() config.Intrusion { c := config.Default().Intrusion; c.Fingerprint.Enabled = true; return c }())
	e.Learn(time.Second)
	e.Fingerprint("p", "10.0.3.1", "c-1", "fp-a")
	cl.add(2 * time.Second)
	e.Fingerprint("p", "10.0.3.1", "c-1", "fp-a")
	e.Fingerprint("p", "10.0.3.2", "c-3", "fp-b")
	e.Fingerprint("p", "10.0.3.2", "c-3", "fp-b")
	e.Fingerprint("p", "10.0.3.2", "c-3", "")
	if a := ev.find(events.Anomaly, func(e events.Event) bool { return e.Reason == AnomalyFingerprint }); len(a) != 1 || a[0].Data["observed"] != "fp-b" {
		t.Errorf("fingerprint: %+v", a)
	}
	// Anomaly detector off: silent.
	e2, ev2, cl2, _ := newTest(t, func(c *config.Intrusion) { c.Anomaly.Enabled = false })
	cl2.add(time.Hour)
	e2.Search(novel)
	if len(ev2.find(events.Anomaly, nil)) != 0 {
		t.Error("anomaly disabled")
	}
	if FilterShape("(&(uid=a)(cn=b*c*d)(x>=1)(y~=2)(z:dn:=3)(!(w=*)))") != "(&(uid=?)(cn=?*)(x>=?)(y~=?)(z:dn:=?)(!(w=*)))" || FilterShape("junk") != "junk" {
		t.Errorf("FilterShape = %s", FilterShape("(&(uid=a)(cn=b*c*d)(x>=1)(y~=2)(z:dn:=3)(!(w=*)))"))
	}
	ev.check(t)
}

func TestEngine_IndicatorsAndNote(t *testing.T) {
	e, _, cl, _ := newTest(t, nil)
	e.Note(events.Event{Event: events.Honeytoken, ClientIP: "10.0.4.1", Account: "trap"})
	e.Note(events.Event{Event: events.Lock, ClientIP: "10.0.4.1", Data: map[string]any{"target": "ip", "source": "ratelimit"}})
	e.Note(events.Event{Event: events.Lock, Account: "bob", Data: map[string]any{"target": "account", "source": "ids"}})
	e.Note(events.Event{Event: events.Lock, ClientIP: "10.0.4.1", Data: map[string]any{"target": "ip", "source": "honeytoken"}}) // already scored via honeytoken
	e.Emit(events.Event{Event: events.OpDenied, ClientIP: "10.0.4.2"})
	e.Note(events.Event{Event: events.Search, ClientIP: "10.0.4.2"})
	ind := e.Indicators(0)
	if len(ind) != 4 || ind[0].Key != "10.0.4.1" || ind[0].Score != 130 || ind[0].Hits["honeytoken"] != 1 || ind[0].Hits["lock"] != 1 {
		t.Fatalf("indicators = %+v", ind)
	}
	if ind[1].Type != "account" || ind[1].Key != "trap" || ind[1].Score != 100 {
		t.Errorf("account indicator %+v", ind[1])
	}
	// Decay: half after one hour; minScore filters; tiny scores are forgotten.
	cl.add(time.Hour)
	if got := e.Indicators(40); len(got) != 2 || got[0].Score != 65 || got[1].Score != 50 {
		t.Errorf("decayed = %+v", got)
	}
	cl.add(24 * time.Hour)
	if got := e.Indicators(0); len(got) != 0 {
		t.Errorf("not forgotten: %+v", got)
	}
	// Bounded: MaxSources indicators, lowest evicted; sources evicted by age.
	e2, _, cl2, _ := newTest(t, nil)
	e2.o.MaxSources = 3
	for i := 0; i < 5; i++ {
		bind(e2, fmt.Sprintf("10.0.5.%d", i), "u", "pw", false)
		cl2.add(time.Second)
	}
	e2.mu.Lock()
	ns, ni := len(e2.sources), len(e2.ind)
	_, oldest := e2.sources["10.0.5.0"]
	e2.mu.Unlock()
	if ns != 3 || ni > 3 || oldest {
		t.Errorf("bounds: sources %d indicators %d oldest kept %v", ns, ni, oldest)
	}
	// Run ticks until the context ends.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e2.Run(ctx, time.Millisecond); close(done) }()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
	// Long source histories are capped.
	s := &source{}
	for i := 0; i < 20001; i++ {
		s.attempts = append(s.attempts, attempt{t: cl.now()})
	}
	s.prune(cl.now(), time.Hour)
	if len(s.attempts) != 10000 {
		t.Errorf("history cap: %d", len(s.attempts))
	}
	if percentile(nil, 95) != 0 || percentile([]int{1, 2, 3}, 50) != 2 {
		t.Error("percentile")
	}
}
