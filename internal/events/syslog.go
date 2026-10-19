package events

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// facilities maps [events.syslog].facility names to RFC 5424 codes.
var facilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// Facility returns the code of a facility name.
func Facility(name string) (int, bool) {
	f, ok := facilities[strings.ToLower(name)]
	return f, ok
}

// SyslogSink sends records as RFC 5424 messages over udp, tcp or unix
// (newline framing on stream sockets). The connection is re-established
// after a write failure.
type SyslogSink struct {
	Network  string
	Address  string
	Facility int
	AppName  string
	Timeout  time.Duration
	// Dial overrides net.DialTimeout (tests).
	Dial func(network, address string, timeout time.Duration) (net.Conn, error)

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslogSink validates the parameters; the connection is opened lazily.
func NewSyslogSink(network, address, facility string) (*SyslogSink, error) {
	switch network {
	case "udp", "tcp", "unix", "unixgram":
	default:
		return nil, fmt.Errorf("events: syslog network %q not supported", network)
	}
	f, ok := Facility(facility)
	if !ok {
		return nil, fmt.Errorf("events: syslog facility %q unknown", facility)
	}
	if address == "" {
		return nil, fmt.Errorf("events: syslog address required")
	}
	return &SyslogSink{Network: network, Address: address, Facility: f, AppName: "aldap", Timeout: 5 * time.Second}, nil
}

func severity(level string) int {
	switch level {
	case LevelHigh:
		return 4 // warning
	case LevelMedium:
		return 5 // notice
	default:
		return 6 // informational
	}
}

// Message renders one RFC 5424 line for r.
func (s *SyslogSink) Message(r Record) []byte {
	host := r.Host
	if host == "" {
		host = "-"
	}
	msgid := r.Event
	if msgid == "" {
		msgid = "-"
	}
	pri := s.Facility*8 + severity(r.Level)
	return []byte(fmt.Sprintf("<%d>1 %s %s %s %d %s - %s\n", pri, r.TS, host, s.AppName, os.Getpid(), msgid, r.JSON()))
}

func (s *SyslogSink) connect() error {
	dial := s.Dial
	if dial == nil {
		dial = net.DialTimeout
	}
	c, err := dial(s.Network, s.Address, s.Timeout)
	if err != nil {
		return fmt.Errorf("events: syslog connect: %w", err)
	}
	s.conn = c
	return nil
}

// Write implements RecordSink.
func (s *SyslogSink) Write(_ context.Context, batch []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range batch {
		msg := s.Message(r)
		if s.conn == nil {
			if err := s.connect(); err != nil {
				return err
			}
		}
		if err := s.send(msg); err != nil {
			// One reconnect per record; a second failure drops the batch.
			if err := s.connect(); err != nil {
				return err
			}
			if err := s.send(msg); err != nil {
				return fmt.Errorf("events: syslog write: %w", err)
			}
		}
	}
	return nil
}

// send writes one message on the current connection; on failure the
// connection is dropped so the next call reconnects.
func (s *SyslogSink) send(msg []byte) error {
	if s.Timeout > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(s.Timeout)); err != nil {
			closeQuietly(s.conn)
			s.conn = nil
			return err
		}
	}
	if _, err := s.conn.Write(msg); err != nil {
		closeQuietly(s.conn)
		s.conn = nil
		return err
	}
	return nil
}

// Close implements RecordSink.
func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}
