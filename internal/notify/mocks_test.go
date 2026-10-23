package notify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// hits records the requests a mock received.
type hits struct {
	mu     sync.Mutex
	bodies [][]byte
	hdrs   []http.Header
	paths  []string
}

func (h *hits) add(r *http.Request, body []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bodies = append(h.bodies, body)
	h.hdrs = append(h.hdrs, r.Header.Clone())
	h.paths = append(h.paths, r.URL.Path)
}

func (h *hits) n() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bodies)
}

func (h *hits) body(i int) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bodies[i]
}

// field decodes the JSON body i and returns key.
func (h *hits) field(t *testing.T, i int, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(h.body(i), &m); err != nil {
		t.Fatalf("body %d: %v: %s", i, err, h.body(i))
	}
	s, _ := m[key].(string)
	return s
}

// mockHTTP answers with status (default 200) and resp; fail lists the
// statuses of the first requests.
type mockHTTP struct {
	hits
	srv  *httptest.Server
	mu2  sync.Mutex
	fail []int
	resp string
	// failBody replaces the default error body of failed requests.
	failBody string
	hold     chan struct{} // when set, requests wait for it
}

func newMockHTTP(t *testing.T, resp string, tlsSrv bool) *mockHTTP {
	t.Helper()
	m := &mockHTTP{resp: resp}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.hold != nil {
			<-m.hold
		}
		body, _ := io.ReadAll(r.Body)
		m.add(r, body)
		m.mu2.Lock()
		status := 200
		if len(m.fail) > 0 {
			status, m.fail = m.fail[0], m.fail[1:]
		}
		failBody := m.failBody
		m.mu2.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		switch {
		case status == 200:
			_, _ = io.WriteString(w, m.resp)
		case failBody != "":
			_, _ = io.WriteString(w, failBody)
		default:
			_, _ = io.WriteString(w, `{"ok":false,"error_code":`+itoa(status)+`,"description":"mock failure"}`)
		}
	})
	if tlsSrv {
		m.srv = httptest.NewTLSServer(h)
	} else {
		m.srv = httptest.NewServer(h)
	}
	t.Cleanup(func() {
		if m.hold != nil {
			select {
			case <-m.hold:
			default:
				close(m.hold)
			}
		}
		m.srv.Close()
	})
	return m
}

func (m *mockHTTP) failWith(statuses ...int) {
	m.mu2.Lock()
	defer m.mu2.Unlock()
	m.fail = append(m.fail, statuses...)
}

func itoa(n int) string { return strconv.Itoa(n) }

// smtpMock is a minimal ESMTP server: EHLO, STARTTLS, AUTH PLAIN, MAIL,
// RCPT, DATA, QUIT. Messages and AUTH credentials are recorded.
type smtpMock struct {
	ln       net.Listener
	tls      *tls.Config // STARTTLS offered when set (and implicit TLS when implicit)
	implicit bool
	noTLS    bool // do not offer STARTTLS even with a config

	mu       sync.Mutex
	msgs     []string
	auths    []string
	failRcpt []int
	wg       sync.WaitGroup
}

func newSMTPMock(t *testing.T, cfg *tls.Config, implicit bool) *smtpMock {
	t.Helper()
	var ln net.Listener
	var err error
	ln, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil && implicit {
		ln = tls.NewListener(ln, cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpMock{ln: ln, tls: cfg, implicit: implicit}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *smtpMock) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpMock) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

func (s *smtpMock) msg(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.msgs[i]
}

func (s *smtpMock) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.conn(c)
		}()
	}
}

func (s *smtpMock) conn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 mock ESMTP")
	secure := s.implicit
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.Fields(line + " x")[0])
		switch cmd {
		case "EHLO", "HELO":
			ext := []string{"250-mock", "250-8BITMIME"}
			if s.tls != nil && !secure && !s.noTLS {
				ext = append(ext, "250-STARTTLS")
			}
			ext = append(ext, "250 AUTH PLAIN")
			for _, e := range ext {
				_ = tp.PrintfLine("%s", e)
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(c, s.tls)
			if err := tc.HandshakeContext(context.Background()); err != nil {
				return
			}
			c = tc
			tp = textproto.NewConn(tc)
			secure = true
		case "AUTH":
			parts := strings.Fields(line)
			if len(parts) == 3 {
				raw, _ := base64.StdEncoding.DecodeString(parts[2])
				s.mu.Lock()
				s.auths = append(s.auths, string(raw))
				s.mu.Unlock()
			}
			_ = tp.PrintfLine("235 ok")
		case "MAIL":
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			s.mu.Lock()
			code := 250
			if len(s.failRcpt) > 0 {
				code, s.failRcpt = s.failRcpt[0], s.failRcpt[1:]
			}
			s.mu.Unlock()
			_ = tp.PrintfLine("%d rcpt", code)
		case "DATA":
			_ = tp.PrintfLine("354 go")
			var b bytes.Buffer
			r := bufio.NewReader(tp.DotReader())
			_, _ = io.Copy(&b, r)
			s.mu.Lock()
			s.msgs = append(s.msgs, b.String())
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

// testCert returns a server TLS config for 127.0.0.1 and a pool trusting it.
func testCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, pool
}
