package notify

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/metrics"
	"github.com/alstdev/aldap/internal/secret"
)

// Result labels of aldap_notify_total{channel,result}.
const (
	ResultOK       = "ok"       // message delivered
	ResultError    = "error"    // delivery failed after the retries
	ResultCooldown = "cooldown" // suppressed: same (channel, event, key) within cooldown
	ResultDigested = "digested" // folded into the attack digest
	ResultDropped  = "dropped"  // channel queue full
)

const (
	// tickInterval drives digests, attack expiry and cooldown pruning.
	tickInterval = time.Second
	// closeTimeout bounds the delivery of queued messages at shutdown.
	closeTimeout = 10 * time.Second
	// minAttackExpiry: an attack without start/summary records for
	// max(minAttackExpiry, 4×digest_interval) is considered over (a lost
	// attack_end must not keep the channels in digest mode forever).
	minAttackExpiry = time.Hour
	topIPs          = 10
)

// Options supply what the notifier needs from the process.
type Options struct {
	// Hostname and Version are passed to the templates.
	Hostname, Version string
	// Secrets resolves tokens and passwords (default secret.Default).
	Secrets   secret.Resolver
	Logger    *slog.Logger
	Metrics   *metrics.Metrics
	UserAgent string
	// QueueSize bounds the pending messages per channel (default 256).
	QueueSize int
	// Now is the clock (tests).
	Now func() time.Time
	// RootCAs replaces the system roots for HTTPS and SMTP TLS (tests).
	RootCAs *x509.CertPool
	// Sleep waits between delivery attempts (tests).
	Sleep func(context.Context, time.Duration)
}

// Notifier turns bus records into human notifications ([notify]). It is
// process-wide: cooldowns and the attack digest survive Configure.
// Delivery runs in one goroutine per channel behind a bounded queue, so a
// slow or failing channel never blocks the bus or the other channels.
type Notifier struct {
	o   Options
	log *slog.Logger

	ctx    context.Context // delivery context, canceled by Close
	cancel context.CancelFunc
	wg     sync.WaitGroup // channel workers

	mu          sync.Mutex
	cooldown    time.Duration
	interval    time.Duration
	channels    []*channel
	last        map[string]time.Time // cooldown key → last delivery
	attacks     map[string]time.Time // active attack id → last record
	nextDigest  time.Time
	lastPrune   time.Time
	subDropped  uint64
	runDone     chan struct{}
	stopRun     context.CancelFunc
	closeCalled bool
}

// New creates a notifier without channels; Configure installs them.
func New(o Options) *Notifier {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 256
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.UserAgent == "" {
		o.UserAgent = "aldap"
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Notifier{o: o, log: o.Logger, ctx: ctx, cancel: cancel, last: map[string]time.Time{}, attacks: map[string]time.Time{}}
}

// Configure builds the channels of cfg and replaces the current ones. On
// an error nothing changes. Replaced channels deliver what they already
// queued; a pending digest moves to the new channel of the same name.
func (n *Notifier) Configure(cfg config.Notify) error {
	built := make([]*channel, 0, len(cfg.Channels))
	for i := range cfg.Channels {
		ch, err := n.build(cfg.Channels[i])
		if err != nil {
			for _, b := range built {
				b.snd.close()
			}
			return fmt.Errorf("notify.channel[%d] %q: %w", i, cfg.Channels[i].Name, err)
		}
		built = append(built, ch)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closeCalled {
		for _, b := range built {
			b.snd.close()
		}
		return errors.New("notify: closed")
	}
	old := map[string]*channel{}
	for _, ch := range n.channels {
		old[ch.name] = ch
	}
	for _, ch := range built {
		if prev := old[ch.name]; prev != nil {
			ch.digest = prev.digest
		}
		n.wg.Add(1)
		go ch.loop(n)
	}
	for _, ch := range n.channels {
		close(ch.queue)
	}
	n.channels = built
	n.cooldown = cfg.Cooldown.D()
	n.interval = cfg.DigestInterval.D()
	return nil
}

// Start reads records from sub until Close. The subscription drops (and
// counts) records when the notifier lags; the bus never waits for it.
func (n *Notifier) Start(sub *events.Subscription) {
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	n.mu.Lock()
	n.stopRun, n.runDone = stop, done
	n.mu.Unlock()
	go func() {
		defer close(done)
		defer sub.Close()
		t := time.NewTicker(tickInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				for { // records already queued by the bus (shutdown)
					select {
					case r := <-sub.C:
						n.Handle(r)
					default:
						return
					}
				}
			case r := <-sub.C:
				n.Handle(r)
			case <-t.C:
				n.Tick(n.o.Now())
				n.noteDropped(sub.Dropped())
			}
		}
	}()
}

func (n *Notifier) noteDropped(total uint64) {
	n.mu.Lock()
	d := total - n.subDropped
	n.subDropped = total
	n.mu.Unlock()
	if d > 0 {
		n.o.Metrics.Dropped("notify", float64(d))
		n.log.Warn("notify: lagging behind the event bus, records dropped", "dropped", d)
	}
}

// Close stops reading the bus, lets the channels deliver their queues for
// up to closeTimeout and then aborts the remaining deliveries.
func (n *Notifier) Close() {
	n.mu.Lock()
	if n.closeCalled {
		n.mu.Unlock()
		return
	}
	n.closeCalled = true
	stop, done := n.stopRun, n.runDone
	n.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}
	n.mu.Lock()
	for _, ch := range n.channels {
		close(ch.queue)
	}
	n.channels = nil
	n.mu.Unlock()
	finished := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(closeTimeout):
		n.log.Warn("notify: shutdown timeout, pending notifications dropped")
	}
	n.cancel()
	<-finished
}

// Handle processes one record: channel match, attack/digest state,
// cooldown, rendering and queueing. It never blocks on delivery.
func (n *Notifier) Handle(r events.Record) {
	now := n.o.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	id := attackID(r)
	switch r.Event {
	case events.AttackStart, events.AttackSummary:
		if len(n.attacks) == 0 {
			n.nextDigest = now.Add(n.interval)
		}
		n.attacks[id] = now
	case events.AttackEnd:
		if _, ok := n.attacks[id]; ok {
			delete(n.attacks, id)
			if len(n.attacks) == 0 {
				n.flushDigests(now)
			}
		}
	}
	for _, ch := range n.channels {
		if !ch.matches(r) {
			continue
		}
		if len(n.attacks) > 0 && r.Event != events.AttackStart && r.Event != events.AttackEnd {
			ch.digest.add(r, now)
			n.o.Metrics.Notify(ch.name, ResultDigested)
			continue
		}
		key := ch.name + "\x00" + r.Event + "\x00" + cooldownKey(r)
		if t, ok := n.last[key]; ok && now.Sub(t) < n.cooldown {
			n.o.Metrics.Notify(ch.name, ResultCooldown)
			continue
		}
		n.last[key] = now
		n.enqueue(ch, n.data(r, nil))
	}
}

// Tick sends due digests, expires attacks whose end was never seen and
// prunes old cooldown entries.
func (n *Notifier) Tick(now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.attacks) > 0 {
		expiry := max(minAttackExpiry, 4*n.interval)
		for id, seen := range n.attacks {
			if now.Sub(seen) > expiry {
				n.log.Info("notify: attack without attack_end expired, digest mode ends", "attack_id", id)
				delete(n.attacks, id)
			}
		}
		if len(n.attacks) == 0 {
			n.flushDigests(now)
		} else if !now.Before(n.nextDigest) {
			n.flushDigests(now)
			n.nextDigest = now.Add(n.interval)
		}
	}
	if now.Sub(n.lastPrune) >= time.Minute {
		n.lastPrune = now
		for k, t := range n.last {
			if now.Sub(t) >= n.cooldown {
				delete(n.last, k)
			}
		}
	}
}

// flushDigests queues the non-empty digests of every channel; mu is held.
func (n *Notifier) flushDigests(now time.Time) {
	for _, ch := range n.channels {
		if dg, level := ch.digest.take(now); dg != nil {
			d := n.data(events.Record{Schema: events.SchemaID, Event: tmplDigest, Level: level, TS: now.UTC().Format(time.RFC3339Nano), Time: now}, dg)
			n.enqueue(ch, d)
		}
	}
}

func (n *Notifier) data(r events.Record, dg *Digest) Data {
	host := n.o.Hostname
	if host == "" {
		host = r.Host
	}
	if r.Host == "" {
		r.Host = host
	}
	return Data{Record: r, Hostname: host, Version: n.o.Version, Digest: dg}
}

// enqueue renders d for ch and queues it without blocking; mu is held.
func (n *Notifier) enqueue(ch *channel, d Data) {
	m, err := ch.render(d)
	if err != nil {
		n.o.Metrics.Notify(ch.name, ResultError)
		n.log.Warn("notify: template failed", "channel", ch.name, "event", d.Event, "err", err)
		return
	}
	select {
	case ch.queue <- m:
	default:
		n.o.Metrics.Notify(ch.name, ResultDropped)
		n.log.Warn("notify: channel queue full, notification dropped", "channel", ch.name, "event", d.Event)
	}
}

// attackID is data.attack_id of attack records (the kind when missing).
func attackID(r events.Record) string {
	if v, ok := r.Data["attack_id"]; ok {
		return fmt.Sprint(v)
	}
	if v, ok := r.Data["kind"]; ok {
		return fmt.Sprint(v)
	}
	return r.Event
}

// cooldownKey is the "key" of SPEC §3.4 cooldown (channel, event type, key):
// what makes two records of one type the same incident.
func cooldownKey(r events.Record) string {
	get := func(k string) string {
		if v, ok := r.Data[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	switch r.Event {
	case events.AttackStart, events.AttackSummary, events.AttackEnd:
		return attackID(r)
	case events.Lock, events.Unlock:
		return get("target") + ":" + get("key")
	case events.UpstreamDown, events.UpstreamUp:
		return r.Upstream + " " + get("server")
	case events.CertExpiring, events.CertRenewed:
		return r.Profile + " " + get("subject")
	case events.Honeytoken:
		return get("account") + " " + r.ClientIP
	case events.Lockdown:
		return get("state")
	}
	return r.Profile + " " + r.ClientIP + " " + r.Account + r.AccountHash + " " + r.Reason + " " + r.Upstream
}

// levelRank orders low < medium < high.
func levelRank(l string) int {
	switch l {
	case events.LevelHigh:
		return 2
	case events.LevelMedium:
		return 1
	}
	return 0
}

// channel is one [[notify.channel]] with its queue and worker.
type channel struct {
	name     string
	typ      string
	kinds    map[string]bool
	lockTo   map[string]bool // lock targets selected by lock_account / lock_ip
	minLevel int
	tpl      *templates
	snd      sender
	retry    config.Retry
	queue    chan message
	digest   *digest
}

func (n *Notifier) build(c config.Channel) (*channel, error) {
	tpl, err := loadTemplates(c.TemplateDir, c.SubjectTemplate, c.BodyTemplate)
	if err != nil {
		return nil, err
	}
	ch := &channel{name: c.Name, typ: c.Type, kinds: map[string]bool{}, lockTo: map[string]bool{}, minLevel: levelRank(c.MinLevel),
		tpl: tpl, retry: c.Retry, queue: make(chan message, n.o.QueueSize), digest: newDigest()}
	for _, e := range c.Events {
		if t := config.NotifyLockAliases[e]; t != "" {
			ch.lockTo[t] = true
			continue
		}
		ch.kinds[e] = true
	}
	resolve := func(s secret.Source) (secret.Value, error) {
		v, warns, err := n.o.Secrets.Resolve(s)
		for _, w := range warns {
			n.log.Warn("notify: secret", "channel", c.Name, "warning", w.Msg)
		}
		return v, err
	}
	switch c.Type {
	case "telegram":
		tok, err := resolve(c.BotTokenSource())
		if err != nil {
			return nil, fmt.Errorf("bot_token: %w", err)
		}
		ch.snd, err = newTelegram(c, tok, n.o)
		if err != nil {
			return nil, err
		}
	case "virola":
		tok, err := resolve(c.TokenSource())
		if err != nil {
			return nil, fmt.Errorf("token: %w", err)
		}
		ch.snd, err = newVirola(c, tok, n.o)
		if err != nil {
			return nil, err
		}
	case "email":
		var pw secret.Value
		if c.Username != "" {
			if pw, err = resolve(c.PasswordSource()); err != nil {
				return nil, fmt.Errorf("password: %w", err)
			}
		}
		ch.snd, err = newEmail(c, pw, n.o)
		if err != nil {
			return nil, err
		}
	case "webhook":
		if ch.snd, err = n.buildWebhook(c, resolve); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown type %q", c.Type)
	}
	return ch, nil
}

// buildWebhook resolves the HMAC key and the headers (inline and
// headers_file) of a webhook channel.
func (n *Notifier) buildWebhook(c config.Channel, resolve func(secret.Source) (secret.Value, error)) (*webhook, error) {
	var key secret.Value
	if c.HMACSecretSource().IsSet() {
		var err error
		if key, err = resolve(c.HMACSecretSource()); err != nil {
			return nil, fmt.Errorf("hmac_secret: %w", err)
		}
	}
	headers, warns, err := config.LoadHeaders(n.o.Secrets, c.Headers, c.HeadersFile)
	for _, w := range warns {
		n.log.Warn("notify: headers_file", "channel", c.Name, "warning", w.Msg)
	}
	if err != nil {
		key.Wipe()
		return nil, err
	}
	return newWebhook(c, key, headers, n.o)
}

// matches applies events and min_level.
func (ch *channel) matches(r events.Record) bool {
	if levelRank(r.Level) < ch.minLevel {
		return false
	}
	if ch.kinds[r.Event] {
		return true
	}
	if r.Event == events.Lock && len(ch.lockTo) > 0 {
		return ch.lockTo[fmt.Sprint(r.Data["target"])]
	}
	return false
}

// render builds the message of d for the channel type.
func (ch *channel) render(d Data) (message, error) {
	m := message{event: d.Event}
	switch ch.typ {
	case "webhook":
		b, err := ch.tpl.renderBody(d)
		if err != nil {
			return m, err
		}
		m.body = b
		return m, nil
	case "email":
		s, err := ch.tpl.renderSubject(d)
		if err != nil {
			return m, err
		}
		m.subject = s
	}
	text, custom, err := ch.tpl.render(d)
	if err != nil {
		return m, err
	}
	switch s := ch.snd.(type) {
	case *telegram:
		text = s.format(text, custom)
	case *virola:
		text = truncate(text, maxChatRunes)
	}
	m.text = text
	return m, nil
}

// loop delivers the queue until it is closed (Configure, Close).
func (ch *channel) loop(n *Notifier) {
	defer n.wg.Done()
	defer ch.snd.close()
	for m := range ch.queue {
		if err := ch.deliver(n, m); err != nil {
			n.o.Metrics.Notify(ch.name, ResultError)
			n.log.Warn("notify: delivery failed", "channel", ch.name, "type", ch.typ, "event", m.event, "err", err)
			continue
		}
		n.o.Metrics.Notify(ch.name, ResultOK)
	}
}

// deliver sends m, retrying transient failures retry.max times with
// exponential backoff (a server-requested delay wins, capped by
// retry.max_backoff).
func (ch *channel) deliver(n *Notifier, m message) error {
	backoff := ch.retry.Backoff.D()
	for attempt := 0; ; attempt++ {
		err := ch.snd.send(n.ctx, m)
		if err == nil {
			return nil
		}
		var te *transientError
		if !errors.As(err, &te) || attempt >= ch.retry.Max || n.ctx.Err() != nil {
			return err
		}
		wait := max(backoff, te.after)
		if mb := ch.retry.MaxBackoff.D(); mb > 0 && wait > mb {
			wait = mb
		}
		n.o.Sleep(n.ctx, wait)
		backoff *= 2
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// digest collects the events of one channel during an attack.
type digest struct {
	from     time.Time
	total    int
	level    int
	counts   map[string]int
	ips      map[string]int
	accounts map[string]bool
	attacks  map[string]events.Record
}

func newDigest() *digest { return &digest{} }

func (g *digest) add(r events.Record, now time.Time) {
	if g.total == 0 {
		g.from = now
		g.counts, g.ips, g.accounts, g.attacks = map[string]int{}, map[string]int{}, map[string]bool{}, map[string]events.Record{}
	}
	g.total++
	g.level = max(g.level, levelRank(r.Level))
	g.counts[r.Event]++
	if r.ClientIP != "" {
		g.ips[r.ClientIP]++
	}
	if a := r.Account + r.AccountHash; a != "" {
		g.accounts[a] = true
	}
	if r.Event == events.AttackSummary || r.Event == events.AttackStart {
		g.attacks[attackID(r)] = r
		if ips, ok := r.Data["ips"].([]string); ok {
			for _, ip := range ips {
				if _, seen := g.ips[ip]; !seen {
					g.ips[ip] = 0
				}
			}
		}
	}
}

// take returns the collected digest and resets it (nil when empty).
func (g *digest) take(now time.Time) (*Digest, string) {
	if g.total == 0 {
		return nil, ""
	}
	dg := &Digest{From: g.from, To: now, Total: g.total, Counts: topCounts(g.counts, 0), IPs: topCounts(g.ips, topIPs), Accounts: len(g.accounts)}
	ids := make([]string, 0, len(g.attacks))
	for id := range g.attacks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		dg.Attacks = append(dg.Attacks, g.attacks[id])
	}
	level := []string{events.LevelLow, events.LevelMedium, events.LevelHigh}[g.level]
	*g = digest{}
	return dg, level
}
