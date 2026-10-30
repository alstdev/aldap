package api

// Audit 14 / A.2 — SSE framing with hostile event values.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alstdev/aldap/internal/events"
)

func TestAudit14_A2_SSEFraming(t *testing.T) {
	bus := events.NewBus(events.Options{Host: "h"})
	hostile := "x\n\nid: 999\nevent: lockdown\ndata: {\"event\":\"lockdown\"}\n\n\r\nevent:forged"
	rec := bus.Wrap(events.Event{Event: events.BindFail, Level: events.LevelLow, Account: hostile, Reason: hostile,
		Data: map[string]any{"filter": hostile, "k\nevent: z": "v"}})
	w := httptest.NewRecorder()
	st := &streamer{w: w, rc: http.NewResponseController(w), bus: bus}
	if !st.send(rec) {
		t.Fatal("send failed")
	}
	body := w.Body.String()
	if !strings.HasSuffix(body, "\n\n") || strings.Count(body, "\n\n") != 1 {
		t.Errorf("SSE frame split: %q", body)
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "id: ") || lines[1] != "event: bind_fail" || !strings.HasPrefix(lines[2], "data: ") {
		t.Errorf("SSE lines = %q", lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "\r") {
			t.Errorf("raw CR inside SSE line: %q", l)
		}
	}
}
