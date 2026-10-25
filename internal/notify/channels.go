package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/secret"
)

// maxChatRunes bounds the text of chat messages (Telegram allows 4096
// characters per message).
const maxChatRunes = 4000

// message is one rendered notification ready for a sender.
type message struct {
	event   string
	subject string
	text    string
	body    []byte
}

// sender delivers messages of one channel type.
type sender interface {
	send(ctx context.Context, m message) error
	close()
}

// transientError marks a failure worth retrying; after is the delay the
// server asked for (Retry-After, Telegram retry_after), zero when none.
type transientError struct {
	err   error
	after time.Duration
}

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func transient(err error, after time.Duration) error { return &transientError{err: err, after: after} }

// httpClient builds the client of an HTTP channel: own transport, TLS 1.2+,
// no redirects (a token must never follow a redirect).
func httpClient(timeout time.Duration, caFile string, insecure bool, roots *x509.CertPool) (*http.Client, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not *http.Transport")
	}
	tr := base.Clone()
	tc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("tls_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls_ca_file %s: no certificates", caFile)
		}
		tc.RootCAs = pool
	}
	// Only virola exposes tls_insecure_skip_verify (SPEC §3.4, warned by
	// the validator); it is false by default.
	tc.InsecureSkipVerify = insecure
	tr.TLSClientConfig = tc
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// post sends one request. The error never carries the URL (a Telegram URL
// contains the bot token): what names the call instead.
func post(ctx context.Context, c *http.Client, method, u, what string, hdr http.Header, body []byte) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, nil, fmt.Errorf("%s: request: %w", what, err)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, nil, transient(fmt.Errorf("%s: %w", what, err), 0)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, nil, nil, transient(fmt.Errorf("%s: response: %w", what, err), 0)
	}
	return resp.StatusCode, raw, resp.Header, nil
}

// statusError classifies a non-2xx status: 429 and 5xx are transient.
func statusError(what string, status int, detail string, after time.Duration) error {
	err := fmt.Errorf("%s: status %d", what, status)
	if detail != "" {
		err = fmt.Errorf("%s: status %d: %s", what, status, detail)
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		return transient(err, after)
	}
	return err
}

func retryAfter(h http.Header) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return 0
}

// shortText trims a server-provided detail for an error message.
func shortText(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

// truncate cuts s to at most n runes.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// telegram posts to the Bot API sendMessage method.
type telegram struct {
	client    *http.Client
	base      string
	token     secret.Value
	chatID    string
	parseMode string
}

func newTelegram(c config.Channel, tok secret.Value, o Options) (*telegram, error) {
	cl, err := httpClient(c.Timeout.D(), "", false, o.RootCAs)
	if err != nil {
		return nil, err
	}
	return &telegram{client: cl, base: strings.TrimRight(c.APIBase, "/"), token: tok, chatID: c.ChatID, parseMode: c.ParseMode}, nil
}

// format escapes built-in text for the parse mode; custom templates are
// sent as rendered (they escape with md/html themselves).
func (t *telegram) format(text string, custom bool) string {
	if custom {
		return truncate(text, maxChatRunes)
	}
	text = truncate(text, maxChatRunes*3/4)
	switch t.parseMode {
	case "MarkdownV2":
		return escapeMarkdownV2(text)
	case "HTML":
		return html.EscapeString(text)
	}
	return text
}

func (t *telegram) send(ctx context.Context, m message) error {
	payload := map[string]any{"chat_id": t.chatID, "text": m.text}
	if t.parseMode != "none" {
		payload["parse_mode"] = t.parseMode
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	const what = "telegram sendMessage"
	status, raw, hdr, err := post(ctx, t.client, http.MethodPost, t.base+"/bot"+t.token.Reveal()+"/sendMessage", what,
		http.Header{"Content-Type": {"application/json"}}, body)
	if err != nil {
		return err
	}
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	_ = json.Unmarshal(raw, &r) //nolint:errcheck // a non-JSON body is reported through the status
	if status/100 == 2 && r.OK {
		return nil
	}
	after := retryAfter(hdr)
	if r.Parameters.RetryAfter > 0 {
		after = time.Duration(r.Parameters.RetryAfter) * time.Second
	}
	if status/100 == 2 {
		return fmt.Errorf("%s: ok=false: %s", what, shortText([]byte(r.Description)))
	}
	return statusError(what, status, shortText([]byte(r.Description)), after)
}

func (t *telegram) close() {
	t.client.CloseIdleConnections()
	t.token.Wipe()
}

// virola posts to the Virola Web API: POST /api/v1/rooms/{room_id}/messages
// or /api/v1/users/{user_id}/messages (path_template overrides the path),
// Authorization: Bearer, {"content"}.
type virola struct {
	client *http.Client
	url    string
	token  secret.Value
}

func newVirola(c config.Channel, tok secret.Value, o Options) (*virola, error) {
	cl, err := httpClient(c.Timeout.D(), c.TLSCAFile, c.TLSInsecureSkipVerify, o.RootCAs)
	if err != nil {
		return nil, err
	}
	u := strings.TrimRight(c.BaseURL, "/") + c.VirolaPath()
	return &virola{client: cl, url: u, token: tok}, nil
}

func (v *virola) send(ctx context.Context, m message) error {
	body, err := json.Marshal(map[string]string{"content": m.text})
	if err != nil {
		return fmt.Errorf("virola: %w", err)
	}
	const what = "virola message"
	status, raw, hdr, err := post(ctx, v.client, http.MethodPost, v.url, what,
		http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer " + v.token.Reveal()}}, body)
	if err != nil {
		return err
	}
	if status/100 == 2 {
		return nil
	}
	return statusError(what, status, shortText(raw), retryAfter(hdr))
}

func (v *virola) close() {
	v.client.CloseIdleConnections()
	v.token.Wipe()
}

// webhook sends the rendered body with optional HMAC signature
// (X-ALDAP-Signature, as the events webhook sink).
type webhook struct {
	client  *http.Client
	url     string
	method  string
	headers map[string]string
	key     secret.Value
	ua      string
}

func newWebhook(c config.Channel, key secret.Value, headers map[string]string, o Options) (*webhook, error) {
	cl, err := httpClient(c.Timeout.D(), "", false, o.RootCAs)
	if err != nil {
		return nil, err
	}
	return &webhook{client: cl, url: c.URL, method: c.Method, headers: headers, key: key, ua: o.UserAgent}, nil
}

func (w *webhook) send(ctx context.Context, m message) error {
	hdr := http.Header{"Content-Type": {"application/json"}, "User-Agent": {w.ua}}
	for k, v := range w.headers {
		hdr.Set(k, v)
	}
	if !w.key.IsZero() {
		key := w.key.Bytes()
		hdr.Set(events.SignatureHeader, events.Sign(key, m.body))
		clear(key)
	}
	const what = "webhook"
	status, raw, rh, err := post(ctx, w.client, w.method, w.url, what, hdr, m.body)
	if err != nil {
		return err
	}
	if status/100 == 2 {
		return nil
	}
	return statusError(what, status, shortText(raw), retryAfter(rh))
}

func (w *webhook) close() {
	w.client.CloseIdleConnections()
	w.key.Wipe()
}

// email sends one message per notification over SMTP: implicit TLS
// (tls), mandatory STARTTLS (starttls) or plain (none; net/smtp then
// refuses AUTH unless the server is localhost).
type email struct {
	host, port string
	mode       string
	user       string
	password   secret.Value
	from       string
	to         []string
	timeout    time.Duration
	helo       string
	roots      *x509.CertPool
}

func newEmail(c config.Channel, pw secret.Value, o Options) (*email, error) {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	to := make([]string, 0, len(c.To))
	for _, a := range c.To {
		addr, err := mail.ParseAddress(a)
		if err != nil {
			return nil, fmt.Errorf("to %q: %w", a, err)
		}
		to = append(to, addr.Address)
	}
	helo := o.Hostname
	if helo == "" || strings.ContainsAny(helo, " \r\n") {
		helo = "localhost"
	}
	return &email{host: c.SMTPHost, port: strconv.Itoa(c.SMTPPort), mode: c.TLSMode, user: c.Username, password: pw,
		from: from.Address, to: to, timeout: c.Timeout.D(), helo: helo, roots: o.RootCAs}, nil
}

// deadlineConn renews the deadline before every read and write, so the
// channel timeout applies per SMTP command.
type deadlineConn struct {
	net.Conn
	d time.Duration
}

func (c deadlineConn) Read(p []byte) (int, error) {
	_ = c.SetDeadline(time.Now().Add(c.d)) //nolint:errcheck // a failed deadline surfaces as an I/O error
	return c.Conn.Read(p)
}

func (c deadlineConn) Write(p []byte) (int, error) {
	_ = c.SetDeadline(time.Now().Add(c.d)) //nolint:errcheck // a failed deadline surfaces as an I/O error
	return c.Conn.Write(p)
}

func (e *email) send(ctx context.Context, m message) error {
	addr := net.JoinHostPort(e.host, e.port)
	tc := &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12, RootCAs: e.roots}
	raw, err := (&net.Dialer{Timeout: e.timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return transient(fmt.Errorf("smtp: %w", err), 0)
	}
	// The deadline wrapper sits under TLS: smtp.Client must see a
	// *tls.Conn to treat implicit TLS as encrypted (PLAIN auth).
	var conn net.Conn = deadlineConn{Conn: raw, d: e.timeout}
	if e.mode == "tls" {
		tconn := tls.Client(conn, tc)
		if err := tconn.HandshakeContext(ctx); err != nil {
			_ = raw.Close() //nolint:errcheck // failed handshake
			return transient(fmt.Errorf("smtp: tls: %w", err), 0)
		}
		conn = tconn
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		_ = conn.Close() //nolint:errcheck // failed greeting
		return transient(fmt.Errorf("smtp: %w", err), 0)
	}
	defer c.Close() //nolint:errcheck // after QUIT or on error
	if err := c.Hello(e.helo); err != nil {
		return smtpError("hello", err)
	}
	if e.mode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: server does not offer STARTTLS (tls = starttls)")
		}
		if err := c.StartTLS(tc); err != nil {
			return smtpError("starttls", err)
		}
	}
	if e.user != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("smtp: server does not offer AUTH")
		}
		if err := c.Auth(smtp.PlainAuth("", e.user, e.password.Reveal(), e.host)); err != nil {
			return smtpError("auth", err)
		}
	}
	if err := c.Mail(e.from); err != nil {
		return smtpError("mail from", err)
	}
	for _, rcpt := range e.to {
		if err := c.Rcpt(rcpt); err != nil {
			return smtpError("rcpt to", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpError("data", err)
	}
	if _, err := w.Write(e.compose(m)); err != nil {
		return smtpError("data", err)
	}
	if err := w.Close(); err != nil {
		return smtpError("data", err)
	}
	if err := c.Quit(); err != nil {
		return smtpError("quit", err)
	}
	return nil
}

// smtpError keeps 4xx replies and I/O failures transient; 5xx replies
// are permanent.
func smtpError(step string, err error) error {
	err = fmt.Errorf("smtp %s: %w", step, err)
	var tp *textproto.Error
	if errors.As(err, &tp) && tp.Code >= 500 {
		return err
	}
	return transient(err, 0)
}

// compose builds the RFC 5322 message: UTF-8 subject (RFC 2047),
// quoted-printable body.
func (e *email) compose(m message) []byte {
	var b bytes.Buffer
	id := make([]byte, 12)
	_, _ = rand.Read(id) // crypto/rand.Read never fails
	fmt.Fprintf(&b, "From: %s\r\n", e.from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), e.helo)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(m.text, "\n", "\r\n"))) //nolint:errcheck // bytes.Buffer
	_ = qp.Close()                                                    //nolint:errcheck // bytes.Buffer
	b.WriteString("\r\n")
	return b.Bytes()
}

func (e *email) close() { e.password.Wipe() }
