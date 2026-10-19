package schematest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

func TestSchema_EveryKindValidates(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	kinds := s.EventKinds()
	if len(kinds) < 25 {
		t.Fatalf("enum too short: %v", kinds)
	}
	// Minimal valid data per kind with constraints.
	data := map[string]map[string]any{
		events.BindFail:      {"reason": "invalid_password"},
		events.BindBlocked:   {"reason": "ip_locked"},
		events.Lock:          {"target": "ip", "key": "10.0.0.1", "until": "2026-10-19T10:00:00Z", "source": "ratelimit", "failures": 3},
		events.AttackStart:   {"kind": "spray", "attack_id": "a1", "ips": []string{"10.0.0.1"}, "accounts_count": 6, "failures": 6, "rate_per_min": 1.5, "first_seen": "2026-10-19T10:00:00Z", "last_seen": "2026-10-19T10:01:00Z"},
		events.AttackSummary: {"kind": "enumeration", "attack_id": "a1"},
		events.AttackEnd:     {"kind": "slow_brute", "attack_id": "a1"},
		events.Search:        {"base": "ou=users,dc=x", "scope": "sub", "filter_norm": "(uid=a)", "results": 1, "attrs_requested": []string{"uid"}, "attrs_denied": []string{}, "denied_terms": []string{}, "upstream_queries": 1, "cache_hit": false},
		events.OpDenied:      {"op": "add"},
	}
	for _, kind := range kinds {
		e := events.Event{Event: kind, Level: events.LevelMedium, Profile: "p", ConnID: "c-1", ClientIP: "10.0.0.1", ClientPort: 1234,
			TLS: events.Bool(true), Account: "alice", Upstream: "ad", UpstreamServer: "ldaps://dc:636", Duration: time.Millisecond, Data: data[kind]}
		if kind == events.BindFail {
			e.Reason = "invalid_password"
			e.Failures = 2
		}
		if kind == events.BindBlocked {
			e.Reason = "lockdown"
		}
		CheckEvents(t, e)
	}
}

func TestSchema_RejectsInvalid(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing host":        `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"startup","level":"low","data":{}}`,
		"bad schema":          `{"schema":"x","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"startup","level":"low","host":"h","data":{}}`,
		"unknown kind":        `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"nope","level":"low","host":"h","data":{}}`,
		"bad ulid":            `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"not-a-ulid","seq":1,"event":"startup","level":"low","host":"h","data":{}}`,
		"bad ts":              `{"schema":"aldap.event.v1","ts":"yesterday","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"startup","level":"low","host":"h","data":{}}`,
		"negative seq":        `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":-1,"event":"startup","level":"low","host":"h","data":{}}`,
		"float seq":           `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1.5,"event":"startup","level":"low","host":"h","data":{}}`,
		"extra field":         `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"startup","level":"low","host":"h","data":{},"extra":1}`,
		"bind_fail reason":    `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"bind_fail","level":"low","host":"h","reason":"meh","data":{}}`,
		"bind_fail no reason": `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"bind_fail","level":"low","host":"h","data":{}}`,
		"lock data":           `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"lock","level":"medium","host":"h","data":{"target":"ip","key":"x","until":"soon","source":"ratelimit"}}`,
		"search scope":        `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"search","level":"low","host":"h","data":{"base":"","scope":"all","filter_norm":"","results":0}}`,
		"attrs items":         `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"search","level":"low","host":"h","data":{"base":"","scope":"sub","filter_norm":"","results":0,"attrs_requested":[1]}}`,
		"tls type":            `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"startup","level":"low","host":"h","tls":"yes","data":{}}`,
		"data not object":     `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"startup","level":"low","host":"h","data":[]}`,
	}
	for name, raw := range cases {
		var doc any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if errs := s.Validate(doc); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	valid := `{"schema":"aldap.event.v1","ts":"2026-10-19T10:00:00.000Z","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"event":"startup","level":"low","host":"h","profile":null,"tls":null,"data":{}}`
	var doc any
	_ = json.Unmarshal([]byte(valid), &doc)
	if errs := s.Validate(doc); len(errs) != 0 {
		t.Errorf("valid document rejected: %v", errs)
	}
	if errs := s.ValidateRecord(events.Record{Schema: "x"}); len(errs) == 0 || !strings.Contains(errs[0].Error(), "$") {
		t.Errorf("record validation: %v", errs)
	}
	if typeOf(int64(1)) != "int64" || typeOf(nil) != "null" {
		t.Error("typeOf")
	}
}
