// Package events defines the ALDAP event record (SPEC §6, aldap.event.v1)
// and the sink interface producers emit to. The bus, the envelope fields
// (ts, id, seq, host) and the sinks arrive with Stage 6; until then the
// daemon logs events through slog.
package events

import (
	"context"
	"log/slog"
	"time"
)

// Event kinds emitted by the daemon (SPEC §6). The list mirrors the enum of
// docs/events.schema.json.
const (
	BindOK         = "bind_ok"
	BindFail       = "bind_fail"
	BindBlocked    = "bind_blocked"
	Lock           = "lock"
	Honeytoken     = "honeytoken"
	Search         = "search"
	OpDenied       = "op_denied"
	RateLimited    = "rate_limited"
	UpstreamDown   = "upstream_down"
	UpstreamUp     = "upstream_up"
	CertExpiring   = "cert_expiring"
	CertRenewed    = "cert_renewed"
	ConfigReload   = "config_reload"
	InsecureConfig = "insecure_config"
	Startup        = "startup"
	Shutdown       = "shutdown"
)

// Levels.
const (
	LevelLow    = "low"
	LevelMedium = "medium"
	LevelHigh   = "high"
)

// Event is one audit event before it is wrapped into the aldap.event.v1
// envelope. Zero-valued optional fields are omitted from the output.
type Event struct {
	// Event is the kind (bind_fail, search, ...).
	Event string
	// Level is low, medium or high.
	Level string
	// Profile is the [profile.<name>] name.
	Profile string
	// ConnID identifies the client connection ("c-7f3a").
	ConnID string
	// ClientIP and ClientPort describe the peer.
	ClientIP   string
	ClientPort int
	// TLS reports whether the client connection was encrypted (nil = unknown).
	TLS *bool
	// Account is the bind name as presented by the client (never a password).
	Account string
	// Reason is the event-specific reason (bind_fail, bind_blocked, rate_limited).
	Reason string
	// Upstream and UpstreamServer name the directory that served the request.
	Upstream       string
	UpstreamServer string
	// Duration is the request duration.
	Duration time.Duration
	// Data holds the event-specific fields of SPEC §6.
	Data map[string]any
}

// Sink receives events. Emit must not block for long and must never panic.
type Sink interface {
	Emit(Event)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Event)

// Emit calls f.
func (f SinkFunc) Emit(e Event) { f(e) }

// Discard drops every event.
var Discard Sink = SinkFunc(func(Event) {})

// Attrs renders the event as slog attributes (for the interim slog sink and
// for tests). Passwords never reach an Event, so every field is loggable.
func (e Event) Attrs() []slog.Attr {
	out := []slog.Attr{slog.String("event", e.Event), slog.String("level", e.Level)}
	add := func(k, v string) {
		if v != "" {
			out = append(out, slog.String(k, v))
		}
	}
	add("profile", e.Profile)
	add("conn_id", e.ConnID)
	add("client_ip", e.ClientIP)
	if e.ClientPort != 0 {
		out = append(out, slog.Int("client_port", e.ClientPort))
	}
	if e.TLS != nil {
		out = append(out, slog.Bool("tls", *e.TLS))
	}
	add("account", e.Account)
	add("reason", e.Reason)
	add("upstream", e.Upstream)
	add("upstream_server", e.UpstreamServer)
	if e.Duration != 0 {
		out = append(out, slog.Float64("duration_ms", float64(e.Duration)/float64(time.Millisecond)))
	}
	if len(e.Data) > 0 {
		out = append(out, slog.Any("data", e.Data))
	}
	return out
}

// Logger is a Sink that writes every event as one slog record.
type Logger struct {
	Log *slog.Logger
}

// Emit logs the event at info level (high level events at warn).
func (l Logger) Emit(e Event) {
	log := l.Log
	if log == nil {
		log = slog.Default()
	}
	lvl := slog.LevelInfo
	if e.Level == LevelHigh {
		lvl = slog.LevelWarn
	}
	log.LogAttrs(context.Background(), lvl, "event", e.Attrs()...)
}

// Bool returns a pointer for Event.TLS.
func Bool(b bool) *bool { return &b }
