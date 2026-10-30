package main

// Audit 14 / A.2 — terminal output of `aldapctl events` must not let an
// event field forge or overwrite lines.

import (
	"strings"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

func TestAudit14_A2_EventLineNoControlChars(t *testing.T) {
	forged := "\n2026-10-27T10:00:00Z #999 lockdown high state=on"
	base := events.Record{TS: "2026-10-27T09:59:59.000Z", Seq: 7, Event: "bind_fail", Level: "low", Profile: "virola"}
	cases := map[string]func(r *events.Record){
		"account newline":  func(r *events.Record) { r.Account = "bob" + forged },
		"account CR":       func(r *events.Record) { r.Account = "bob\rforged line" },
		"account ESC":      func(r *events.Record) { r.Account = "bob\x1b[2K\x1b[1;31mFORGED" },
		"reason newline":   func(r *events.Record) { r.Reason = "x" + forged },
		"upstream newline": func(r *events.Record) { r.Upstream = "u" + forged },
		"data CR":          func(r *events.Record) { r.Data = map[string]any{"k": "a\rb"} },
		"data ESC":         func(r *events.Record) { r.Data = map[string]any{"k": "a\x1b[31mb"} },
		"data newline":     func(r *events.Record) { r.Data = map[string]any{"k": "a" + forged} },
	}
	for name, mut := range cases {
		r := base
		mut(&r)
		line := eventLine(r, time.RFC3339)
		if strings.ContainsAny(line, "\r\n\x1b") {
			t.Errorf("%s: control characters reach the terminal: %q", name, line)
		}
	}
}
