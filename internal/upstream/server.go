package upstream

import (
	"sort"
	"sync"
	"time"

	"github.com/alstdev/aldap/internal/config"
)

// State of one server (SPEC §5.2).
type State uint8

// Server states.
const (
	StateUnknown State = iota
	StateUp
	StateDown
)

// String returns unknown, up or down.
func (s State) String() string {
	switch s {
	case StateUp:
		return "up"
	case StateDown:
		return "down"
	default:
		return "unknown"
	}
}

// MarshalText renders the state for JSON/TOML.
func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

const latencyWindow = 128

// server holds the runtime state of one upstream server.
type server struct {
	url   ServerURL
	index int

	mu         sync.Mutex
	state      State
	okStreak   int
	failStreak int
	lastErr    string
	lastErrAt  time.Time
	lastCheck  time.Time
	lastChange time.Time
	lat        [latencyWindow]time.Duration
	latN       int
	latPos     int

	svc  *pool // service-bound connections for searches
	bind *pool // bind-only connections for user binds
	kick chan struct{}
}

// ServerStatus is a snapshot for /v1/upstreams and aldapctl.
type ServerStatus struct {
	URL             string        `json:"url"`
	State           State         `json:"state"`
	ConsecutiveOK   int           `json:"consecutive_ok"`
	ConsecutiveFail int           `json:"consecutive_fail"`
	LastError       string        `json:"last_error,omitempty"`
	LastErrorAt     time.Time     `json:"last_error_at,omitempty"`
	LastCheck       time.Time     `json:"last_check,omitempty"`
	LastChange      time.Time     `json:"last_change,omitempty"`
	P50             time.Duration `json:"p50"`
	P95             time.Duration `json:"p95"`
	IdleConns       int           `json:"idle_conns"`
	ActiveConns     int           `json:"active_conns"`
}

// transition describes a state change produced by record.
type transition struct {
	from, to    State
	consecutive int
	reason      string
}

// record applies one observation and returns the transition, if any.
// Unknown becomes up on the first success and down after fail_threshold
// failures; down becomes up after recover_threshold successes; up becomes
// down after fail_threshold failures.
func (s *server) record(ok bool, err error, d time.Duration, f config.Failover, now time.Time) (transition, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheck = now
	if d > 0 {
		s.lat[s.latPos] = d
		s.latPos = (s.latPos + 1) % latencyWindow
		if s.latN < latencyWindow {
			s.latN++
		}
	}
	from := s.state
	if ok {
		s.okStreak++
		s.failStreak = 0
		if s.state == StateUp {
			return transition{}, false
		}
		if s.state == StateUnknown || s.okStreak >= f.RecoverThreshold {
			s.state = StateUp
			s.lastChange = now
			return transition{from: from, to: StateUp, consecutive: s.okStreak}, true
		}
		return transition{}, false
	}
	s.failStreak++
	s.okStreak = 0
	if err != nil {
		s.lastErr = err.Error()
		s.lastErrAt = now
	}
	if s.state != StateDown && s.failStreak >= f.FailThreshold {
		s.state = StateDown
		s.lastChange = now
		return transition{from: from, to: StateDown, consecutive: s.failStreak, reason: s.lastErr}, true
	}
	return transition{}, false
}

func (s *server) getState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// percentiles returns p50 and p95 of the latency window.
func (s *server) percentiles() (p50, p95 time.Duration) {
	if s.latN == 0 {
		return 0, 0
	}
	vals := make([]time.Duration, s.latN)
	copy(vals, s.lat[:s.latN])
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	idx := func(p float64) int {
		i := int(float64(len(vals)-1) * p)
		return i
	}
	return vals[idx(0.5)], vals[idx(0.95)]
}

func (s *server) status() ServerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	p50, p95 := s.percentiles()
	st := ServerStatus{
		URL: s.url.String(), State: s.state, ConsecutiveOK: s.okStreak, ConsecutiveFail: s.failStreak,
		LastError: s.lastErr, LastErrorAt: s.lastErrAt, LastCheck: s.lastCheck, LastChange: s.lastChange, P50: p50, P95: p95,
	}
	if s.svc != nil {
		i, a := s.svc.stats()
		st.IdleConns, st.ActiveConns = i, a
	}
	if s.bind != nil {
		i, a := s.bind.stats()
		st.IdleConns += i
		st.ActiveConns += a
	}
	return st
}

// requestCheck asks the health loop to re-check the server now.
func (s *server) requestCheck() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}
