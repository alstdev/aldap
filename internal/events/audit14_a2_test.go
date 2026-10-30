package events

// Audit 14 / A.2 — control characters in event fields must not split or
// forge JSONL, syslog or webhook-batch records.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const a2Forged = "bob\n{\"schema\":\"aldap.event.v1\",\"event\":\"lockdown\",\"level\":\"high\"}\r\x00\x1b[2K <80>1 forged"

func a2Record() Record {
	bus := NewBus(Options{Host: "audit-host"})
	return bus.Wrap(Event{Event: BindFail, Level: LevelLow, Profile: "p\n", ClientIP: "10.0.0.5", Account: a2Forged, Reason: "r\r\n",
		Upstream: "u\x1b", Data: map[string]any{"filter": "(cn=x)\n(objectClass=*)", "err": "boom\n\n", "ad_data": "52e\x00"}})
}

func a2RawControls(b []byte) int {
	n := 0
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			n++
		}
	}
	return n
}

func TestAudit14_A2_JSONLSingleRecord(t *testing.T) {
	rec := a2Record()
	var buf bytes.Buffer
	if err := (&WriterSink{W: &buf}).Write(context.Background(), []Record{rec}); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if bytes.Count(out, []byte("\n")) != 1 || out[len(out)-1] != '\n' {
		t.Errorf("JSONL record split into %d lines: %q", bytes.Count(out, []byte("\n")), out)
	}
	if a2RawControls(out) != 1 { // only the trailing newline
		t.Errorf("raw control bytes in JSONL line: %q", out)
	}
	var back Record
	if err := json.Unmarshal(out, &back); err != nil || back.Account != a2Forged || back.Event != BindFail {
		t.Errorf("round trip: %v account=%q event=%q", err, back.Account, back.Event)
	}
}

func TestAudit14_A2_SyslogSingleMessage(t *testing.T) {
	rec := a2Record()
	s := &SyslogSink{Facility: 1, AppName: "aldap"}
	msg := s.Message(rec)
	if bytes.Count(msg, []byte("\n")) != 1 || msg[len(msg)-1] != '\n' {
		t.Errorf("syslog message split: %q", msg)
	}
	if a2RawControls(msg) != 1 {
		t.Errorf("raw control bytes inside syslog message: %q", msg)
	}
	if !bytes.HasPrefix(msg, []byte("<14>1 ")) {
		t.Errorf("PRI/VERSION header: %q", msg[:16])
	}
	// The structured part after "- " must be the single JSON object.
	_, js, _ := bytes.Cut(msg, []byte(" - "))
	var back Record
	if err := json.Unmarshal(bytes.TrimSpace(js), &back); err != nil || back.Account != a2Forged {
		t.Errorf("syslog payload: %v %q", err, js)
	}
	// Over TCP the sink writes newline-framed messages; one Write call per record.
	var wire bytes.Buffer
	srv, cli := net.Pipe()
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&wire, srv); close(copied) }()
	s.conn = cli
	if err := s.Write(context.Background(), []Record{rec, rec}); err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	<-copied
	if n := bytes.Count(wire.Bytes(), []byte("\n")); n != 2 {
		t.Errorf("two records produced %d syslog frames", n)
	}
}

func TestAudit14_A2_WebhookBatchJSON(t *testing.T) {
	rec := a2Record()
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s, err := NewWebhookSink(WebhookOptions{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(context.Background(), []Record{rec, rec}); err != nil {
		t.Fatal(err)
	}
	var back []Record
	if err := json.Unmarshal(body, &back); err != nil || len(back) != 2 || back[0].Account != a2Forged {
		t.Errorf("webhook batch: %v len=%d body=%s", err, len(back), body)
	}
	if strings.Contains(string(body), "\n") {
		t.Errorf("raw newline in webhook body")
	}
}
