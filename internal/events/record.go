package events

import (
	"encoding/json"
	"time"
)

// SchemaID is the fixed value of the schema field (SPEC §6).
const SchemaID = "aldap.event.v1"

// tsLayout renders ts with millisecond precision in UTC, as in SPEC §6.
const tsLayout = "2006-01-02T15:04:05.000Z07:00"

// Record is one event in the aldap.event.v1 envelope, as written to the
// sinks and returned by the API. Optional fields are omitted when unset.
type Record struct {
	Schema         string         `json:"schema"`
	TS             string         `json:"ts"`
	ID             string         `json:"id"`
	Seq            uint64         `json:"seq"`
	Event          string         `json:"event"`
	Level          string         `json:"level"`
	Host           string         `json:"host"`
	Profile        string         `json:"profile,omitempty"`
	ConnID         string         `json:"conn_id,omitempty"`
	ClientIP       string         `json:"client_ip,omitempty"`
	ClientPort     int            `json:"client_port,omitempty"`
	TLS            *bool          `json:"tls,omitempty"`
	Account        string         `json:"account,omitempty"`
	AccountHash    string         `json:"account_hash,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Failures       *int           `json:"failures,omitempty"`
	Upstream       string         `json:"upstream,omitempty"`
	UpstreamServer string         `json:"upstream_server,omitempty"`
	DurationMS     *float64       `json:"duration_ms,omitempty"`
	Data           map[string]any `json:"data"`

	// Time is the parsed ts (not serialized).
	Time time.Time `json:"-"`

	// flush marks a barrier record used by Bus.Flush (never serialized).
	flush chan struct{}
}

// JSON renders the record as one JSON object without a trailing newline.
func (r Record) JSON() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		// Only unmarshalable Data values can fail; fall back to the envelope alone.
		r.Data = map[string]any{"error": "unserializable data: " + err.Error()}
		if b, err = json.Marshal(r); err != nil {
			// Unreachable: the envelope holds only strings, numbers and booleans.
			return []byte(`{"schema":"aldap.event.v1","error":"unserializable record"}`)
		}
	}
	return b
}

// newRecord wraps e into the envelope. Data is copied so later changes by
// the producer do not leak into the stored record.
func newRecord(e Event, ts time.Time, id string, seq uint64, host string) Record {
	r := Record{Schema: SchemaID, TS: ts.UTC().Format(tsLayout), Time: ts.UTC(), ID: id, Seq: seq, Event: e.Event, Level: e.Level, Host: host,
		Profile: e.Profile, ConnID: e.ConnID, ClientIP: e.ClientIP, ClientPort: e.ClientPort, TLS: e.TLS, Account: e.Account,
		Reason: e.Reason, Upstream: e.Upstream, UpstreamServer: e.UpstreamServer, Data: map[string]any{}}
	if r.Level == "" {
		r.Level = LevelLow
	}
	if e.Failures != 0 {
		f := e.Failures
		r.Failures = &f
	}
	if e.Duration != 0 {
		ms := float64(e.Duration) / float64(time.Millisecond)
		r.DurationMS = &ms
	}
	for k, v := range e.Data {
		r.Data[k] = v
	}
	return r
}
