package events

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/config"
)

// schemaEnum reads the event enum of docs/events.schema.json.
func schemaEnum(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../docs/events.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties struct {
			Event struct {
				Enum []string `json:"enum"`
			} `json:"event"`
			Level struct {
				Enum []string `json:"enum"`
			} `json:"level"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	out := map[string]bool{}
	for _, e := range schema.Properties.Event.Enum {
		out[e] = true
	}
	for _, l := range schema.Properties.Level.Enum {
		out["level:"+l] = true
	}
	return out
}

func TestEventKinds_InSchema(t *testing.T) {
	enum := schemaEnum(t)
	for _, k := range []string{BindOK, BindFail, BindBlocked, Search, OpDenied, RateLimited, UpstreamDown, UpstreamUp,
		CertExpiring, CertRenewed, ConfigReload, InsecureConfig, Startup, Shutdown} {
		if !enum[k] {
			t.Errorf("event kind %q is not in docs/events.schema.json", k)
		}
	}
	for _, l := range []string{LevelLow, LevelMedium, LevelHigh} {
		if !enum["level:"+l] {
			t.Errorf("level %q is not in docs/events.schema.json", l)
		}
	}
}

func TestLogger_Emit(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	Logger{Log: log}.Emit(Event{
		Event: BindFail, Level: LevelHigh, Profile: "p", ConnID: "c-1", ClientIP: "10.0.0.1", ClientPort: 4000,
		TLS: Bool(true), Account: "j.doe", Reason: "invalid_password", Upstream: "ad", UpstreamServer: "ldap://dc:389",
		Duration: 1500 * time.Microsecond, Data: map[string]any{"failures": 2},
	})
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("decode: %v (%s)", err, buf.String())
	}
	want := map[string]any{
		"event": "bind_fail", "level": "high", "profile": "p", "conn_id": "c-1", "client_ip": "10.0.0.1",
		"client_port": float64(4000), "tls": true, "account": "j.doe", "reason": "invalid_password",
		"upstream": "ad", "upstream_server": "ldap://dc:389", "duration_ms": 1.5,
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %v, want %v", k, rec[k], v)
		}
	}
	if rec["level"] != "high" || rec["LEVEL"] == "INFO" {
		t.Errorf("record = %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"WARN"`) {
		t.Errorf("high level event should be logged at warn: %s", buf.String())
	}
	if d, _ := rec["data"].(map[string]any); d["failures"] != float64(2) {
		t.Errorf("data = %v", rec["data"])
	}
	buf.Reset()
	Logger{}.Emit(Event{Event: Startup, Level: LevelLow})
	if buf.Len() != 0 {
		t.Errorf("nil logger must use slog.Default, not the test buffer")
	}
	SinkFunc(func(e Event) {
		if e.Event != Startup {
			t.Errorf("SinkFunc got %q", e.Event)
		}
	}).Emit(Event{Event: Startup})
	Discard.Emit(Event{})
}

func TestEventKindsInSync(t *testing.T) {
	enum := schemaEnum(t)
	seen := map[string]bool{}
	for _, k := range config.EventKinds {
		if !enum[k] {
			t.Errorf("config.EventKinds: %q is not in docs/events.schema.json", k)
		}
		seen[k] = true
	}
	for k := range enum {
		if !strings.HasPrefix(k, "level:") && !seen[k] {
			t.Errorf("docs/events.schema.json: %q is missing from config.EventKinds", k)
		}
	}
}
