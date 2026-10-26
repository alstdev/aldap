package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
)

// systemLogger is the system log of a service (the Windows Event Log
// through kardianos/service); the daemon sends it warnings and errors.
type systemLogger interface {
	Error(v ...any) error
	Warning(v ...any) error
}

// teeHandler sends every record to each handler that accepts its level.
type teeHandler []slog.Handler

func (t teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range t {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (t teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(teeHandler, len(t))
	for i, h := range t {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	out := make(teeHandler, len(t))
	for i, h := range t {
		out[i] = h.WithGroup(name)
	}
	return out
}

// sysLogWriter receives one text-formatted record per Write from a
// slog.TextHandler at warn level and forwards it to the system log.
type sysLogWriter struct {
	sys systemLogger
}

func (w sysLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(bytes.TrimRight(p, "\n")))
	var err error
	if strings.Contains(line, " level=ERROR ") {
		err = w.sys.Error(line)
	} else {
		err = w.sys.Warning(line)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// withSystemLog adds the system log (warnings and errors) to a handler.
func withSystemLog(h slog.Handler, sys systemLogger) slog.Handler {
	if sys == nil {
		return h
	}
	return teeHandler{h, slog.NewTextHandler(sysLogWriter{sys: sys}, &slog.HandlerOptions{Level: slog.LevelWarn})}
}
