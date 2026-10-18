package upstream

// Event kinds emitted by this package (SPEC §6).
const (
	EventUpstreamDown   = "upstream_down"
	EventUpstreamUp     = "upstream_up"
	EventInsecureConfig = "insecure_config"
)

// Event is a package-local event; the events bus (Stage 6) wraps it into the
// aldap.event.v1 envelope.
type Event struct {
	// Kind is the event name: upstream_down, upstream_up or insecure_config.
	Kind string
	// Level is low, medium or high.
	Level string
	// Upstream is the [upstream.<name>] name.
	Upstream string
	// Server is the server URL the event is about ("" for upstream-wide events).
	Server string
	// Data holds the event-specific fields (server, reason, consecutive, what).
	Data map[string]any
}

// EventSink receives events. Emit must not block for long.
type EventSink interface {
	Emit(Event)
}

// EventFunc adapts a function to EventSink.
type EventFunc func(Event)

// Emit calls f.
func (f EventFunc) Emit(e Event) { f(e) }
