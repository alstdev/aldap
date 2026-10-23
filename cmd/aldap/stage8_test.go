//go:build integration

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alstdev/aldap/internal/events"
)

const (
	s8TGToken  = "S3CR3T-tg-777:AAbbccddeeff00112233"
	s8VirToken = "S3CR3T-virola-44556677889900aabbcc"
	s8SMTPPW   = "S3CR3T-smtp-ffeeddccbbaa"
)

// chatSink records the "text"/"content" of JSON messages it receives.
type chatSink struct {
	mu    sync.Mutex
	texts []string
	auth  []string
}

func (s *chatSink) handler(field string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		s.mu.Lock()
		txt, _ := m[field].(string)
		s.texts = append(s.texts, txt)
		s.auth = append(s.auth, r.URL.Path+" "+r.Header.Get("Authorization"))
		s.mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}
}

func (s *chatSink) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.texts {
		if strings.Contains(t, sub) {
			n++
		}
	}
	return n
}

// smtpSink is a plain SMTP server (tls = "none", AUTH PLAIN on loopback).
type smtpSink struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
}

func newSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpSink{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *smtpSink) serve(c net.Conn) {
	defer c.Close()
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 sink")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		switch strings.ToUpper(strings.Fields(line + " x")[0]) {
		case "EHLO":
			_ = tp.PrintfLine("250-sink")
			_ = tp.PrintfLine("250 AUTH PLAIN")
		case "AUTH":
			_ = tp.PrintfLine("235 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go")
			b, _ := io.ReadAll(bufio.NewReader(tp.DotReader()))
			s.mu.Lock()
			s.msgs = append(s.msgs, string(b))
			s.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

func (s *smtpSink) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, m := range s.msgs {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}

// TESTING.md 39 end to end: a spray attack sends attack_start once to
// telegram, virola and email; the summaries during the attack arrive as
// digests, then attack_end. TestNoSecretsInOutput for the channel tokens.
func TestStage8_NotifyAttack(t *testing.T) {
	tg, vir := &chatSink{}, &chatSink{}
	tgSrv := httptest.NewServer(tg.handler("text"))
	t.Cleanup(tgSrv.Close)
	virSrv := httptest.NewTLSServer(vir.handler("content"))
	t.Cleanup(virSrv.Close)
	ca := filepath.Join(t.TempDir(), "virola-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: virSrv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	mail := newSMTPSink(t)
	t.Setenv("ALDAP_TEST_TG", s8TGToken)
	t.Setenv("ALDAP_TEST_VIROLA", s8VirToken)
	t.Setenv("ALDAP_TEST_SMTP", s8SMTPPW)
	notifyCfg := fmt.Sprintf(`
[notify]
cooldown = "10m"
digest_interval = "1s"

[[notify.channel]]
name = "tg"
type = "telegram"
api_base = %q
bot_token_env = "ALDAP_TEST_TG"
chat_id = "-100200"

[[notify.channel]]
name = "virola"
type = "virola"
base_url = %q
token_env = "ALDAP_TEST_VIROLA"
room_id = 7
tls_ca_file = %q

[[notify.channel]]
name = "mail"
type = "email"
smtp_host = "127.0.0.1"
smtp_port = %d
tls = "none"
username = "aldap"
password_env = "ALDAP_TEST_SMTP"
from = "aldap@example.test"
to = ["sec@example.test"]
`, tgSrv.URL, virSrv.URL, ca, mail.ln.Addr().(*net.TCPAddr).Port)
	r := startDaemon(t, stage6Config+notifyCfg)
	c := r.ldaps(t)
	for i := 0; i < 6; i++ {
		_ = c.Bind(fmt.Sprintf("spray%d", i), "Spring2026!")
	}
	start := waitEvents(t, r, "spray", events.AttackStart, nil)
	waitEvents(t, r, "end", events.AttackEnd, func(e events.Record) bool { return e.Data["attack_id"] == start.Data["attack_id"] })
	waitFor(t, func() bool {
		return tg.count("attack ended") == 1 && vir.count("attack ended") == 1 && mail.count("attack ended") == 1
	})
	for name, n := range map[string]int{"telegram": tg.count("attack started"), "virola": vir.count("attack started"), "email": mail.count("attack started")} {
		if n != 1 {
			t.Errorf("%s: attack_start delivered %d times, want 1", name, n)
		}
	}
	if tg.count("digest of") == 0 || vir.count("digest of") == 0 {
		t.Errorf("no digest during the attack: tg=%v virola=%v", tg.texts, vir.texts)
	}
	tg.mu.Lock()
	if !strings.HasPrefix(tg.auth[0], "/bot"+s8TGToken+"/sendMessage") {
		t.Errorf("telegram path %q", tg.auth[0])
	}
	tg.mu.Unlock()
	vir.mu.Lock()
	if vir.auth[0] != "/api/v1/rooms/7/messages Bearer "+s8VirToken {
		t.Errorf("virola request %q", vir.auth[0])
	}
	vir.mu.Unlock()
	r.d.stop()
	out := r.logs.String()
	for _, m := range []string{s8TGToken, s8VirToken, s8SMTPPW, "S3CR3T"} {
		if strings.Contains(out, m) {
			t.Fatalf("secret %q in output", m)
		}
	}
}
