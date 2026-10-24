package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/events"
	"github.com/alstdev/aldap/internal/secret"
)

// connOpts selects the API endpoint: the IPC socket (no token) or a TCP
// URL with a token file. aldapctl never reads the daemon configuration.
type connOpts struct {
	socket     string
	url        string
	tokenFile  string
	caFile     string
	clientCert string
	clientKey  string
	timeout    time.Duration
	// warn reports non-fatal findings (a token file readable by others).
	warn func(string)
}

// maxTokenFile bounds the token file; tokens are at least 32 bytes.
const maxTokenFile = 4 << 10

// client talks to the aldap API. The token never leaves the
// Authorization header: errors and output do not carry it.
type client struct {
	base    string
	hc      *http.Client
	stream  *http.Client
	token   string
	timeout time.Duration
	// where names the endpoint in error messages.
	where string
}

var (
	errNoToken      = errors.New("--url requires --token-file")
	errSocketAndURL = errors.New("--socket and --url are mutually exclusive")
)

// newClient builds the HTTP client for o.
func newClient(o connOpts) (*client, error) {
	if o.timeout <= 0 {
		o.timeout = 30 * time.Second
	}
	if o.url == "" {
		for _, f := range []string{o.tokenFile, o.caFile, o.clientCert, o.clientKey} {
			if f != "" {
				return nil, errors.New("--token-file, --ca-file, --client-cert and --client-key need --url")
			}
		}
		return newIPCClient(o)
	}
	if o.socket != "" {
		return nil, errSocketAndURL
	}
	return newTCPClient(o)
}

func newIPCClient(o connOpts) (*client, error) {
	path := o.socket
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialIPC(ctx, path) },
		// One local daemon: no proxy, no keep-alive surprises after a restart.
		Proxy:               nil,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 0,
	}
	return &client{base: "http://aldap", hc: &http.Client{Transport: tr, Timeout: o.timeout, CheckRedirect: noRedirect},
		stream: &http.Client{Transport: tr, CheckRedirect: noRedirect}, timeout: o.timeout, where: "IPC socket " + path}, nil
}

func newTCPClient(o connOpts) (*client, error) {
	u, err := url.Parse(o.url)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("--url %q: want scheme://host:port without path, query or credentials", o.url)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// The API serves plain HTTP on loopback only; elsewhere the token
		// would cross the network in clear text.
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("--url %q: plain http is allowed on loopback only, use https", o.url)
		}
	default:
		return nil, fmt.Errorf("--url %q: scheme must be https (or http on loopback)", o.url)
	}
	if o.tokenFile == "" {
		return nil, errNoToken
	}
	token, err := readToken(o.tokenFile, o.warn)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.caFile != "" {
		pem, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, fmt.Errorf("--ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-file %s: no PEM certificate", o.caFile)
		}
		tlsCfg.RootCAs = pool
	}
	if (o.clientCert == "") != (o.clientKey == "") {
		return nil, errors.New("--client-cert and --client-key go together")
	}
	if o.clientCert != "" {
		pair, err := tls.LoadX509KeyPair(o.clientCert, o.clientKey)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     60 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	base := u.Scheme + "://" + u.Host
	return &client{base: base, hc: &http.Client{Transport: tr, Timeout: o.timeout, CheckRedirect: noRedirect},
		stream: &http.Client{Transport: tr, CheckRedirect: noRedirect}, token: token, timeout: o.timeout, where: base}, nil
}

// noRedirect keeps the bearer token from following a redirect elsewhere.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// readToken reads the bearer token from a file (trailing newline trimmed);
// the secret resolver warns about group/world readable files.
func readToken(path string, warn func(string)) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("--token-file: %w", err)
	}
	if fi.Size() > maxTokenFile {
		return "", fmt.Errorf("--token-file %s: larger than %d bytes", path, maxTokenFile)
	}
	v, warns, err := secret.Resolver{}.Resolve(secret.Source{File: path})
	if err != nil {
		return "", fmt.Errorf("--token-file: %w", err)
	}
	for _, w := range warns {
		if warn != nil {
			warn("--token-file: " + w.Msg)
		}
	}
	tok := strings.TrimSpace(v.Reveal())
	if tok == "" || strings.ContainsAny(tok, "\r\n") {
		return "", fmt.Errorf("--token-file %s: want a single non-empty line", path)
	}
	return tok, nil
}

// apiError is an error answer of the API ({error, code}).
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("API: HTTP %d", e.Status)
	}
	return fmt.Sprintf("API: %s (%s, HTTP %d)", e.Message, e.Code, e.Status)
}

// request performs one call and returns the body of a 2xx answer.
func (c *client) request(ctx context.Context, method, path, ctype string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", path, err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	c.authorize(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, c.connError(err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // read-only body
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if resp.StatusCode/100 != 2 {
		return b, decodeAPIError(resp.StatusCode, b)
	}
	return b, nil
}

func (c *client) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// connError explains a transport failure without echoing the request.
func (c *client) connError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("cannot reach aldap at %s: %w", c.where, err)
}

func decodeAPIError(status int, b []byte) error {
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if json.Unmarshal(b, &e) != nil || e.Error == "" {
		return &apiError{Status: status, Message: http.StatusText(status)}
	}
	return &apiError{Status: status, Code: e.Code, Message: e.Error}
}

// getJSON decodes a GET answer into out.
func (c *client) getJSON(ctx context.Context, path string, out any) error {
	b, err := c.request(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return err
	}
	return decodeInto(path, b, out)
}

// sendJSON sends in as JSON and decodes the answer into out (nil = ignore).
func (c *client) sendJSON(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("encode %s: %w", path, err)
		}
	}
	b, err := c.request(ctx, method, path, "application/json", body)
	if err != nil || out == nil {
		return err
	}
	return decodeInto(path, b, out)
}

func decodeInto(path string, b []byte, out any) error {
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// API views (docs/openapi.yaml), defined on the consumer side.

type upstreamBrief struct {
	URL                 string  `json:"url"`
	State               string  `json:"state"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
	LastError           string  `json:"last_error,omitempty"`
	LatencyP50MS        float64 `json:"latency_p50_ms"`
	LatencyP95MS        float64 `json:"latency_p95_ms"`
}

type statusView struct {
	Version       string                     `json:"version"`
	GoVersion     string                     `json:"go_version"`
	UptimeS       int64                      `json:"uptime_s"`
	Lockdown      bool                       `json:"lockdown"`
	Learning      bool                       `json:"learning"`
	Profiles      []string                   `json:"profiles"`
	Upstreams     map[string][]upstreamBrief `json:"upstreams"`
	LocksActive   int                        `json:"locks_active"`
	AttacksActive int                        `json:"attacks_active"`
	EventsSeq     uint64                     `json:"events_seq"`
}

type serverView struct {
	URL             string    `json:"url"`
	State           string    `json:"state"`
	ConsecutiveOK   int       `json:"consecutive_ok"`
	ConsecutiveFail int       `json:"consecutive_fail"`
	LastError       string    `json:"last_error,omitempty"`
	LastErrorAt     time.Time `json:"last_error_at"`
	LastCheck       time.Time `json:"last_check"`
	LastChange      time.Time `json:"last_change"`
	P50             int64     `json:"p50"`
	P95             int64     `json:"p95"`
	IdleConns       int       `json:"idle_conns"`
	ActiveConns     int       `json:"active_conns"`
}

type profileView struct {
	Name        string   `json:"name"`
	Mode        string   `json:"mode"`
	Transport   string   `json:"transport"`
	Listen      []string `json:"listen"`
	Upstream    string   `json:"upstream,omitempty"`
	VirtualBase string   `json:"virtual_base"`
	Bases       []string `json:"bases"`
	Cache       string   `json:"cache"`
}

type lockView struct {
	Target   string    `json:"target"`
	Key      string    `json:"key"`
	Until    time.Time `json:"until"`
	Failures int       `json:"failures"`
	Source   string    `json:"source"`
	Reason   string    `json:"reason,omitempty"`
	Profile  string    `json:"profile,omitempty"`
}

type indicatorView struct {
	Target    string         `json:"target"`
	Key       string         `json:"key"`
	Score     float64        `json:"score"`
	Reasons   []string       `json:"reasons"`
	Hits      map[string]int `json:"hits"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Locked    bool           `json:"locked"`
}

type applyResult struct {
	OK     bool   `json:"ok"`
	DryRun bool   `json:"dry_run,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type learnResult struct {
	Learning bool      `json:"learning"`
	Until    time.Time `json:"until"`
	Scope    string    `json:"scope"`
}

type testRequest struct {
	Base      string   `json:"base,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Filter    string   `json:"filter"`
	Attrs     []string `json:"attrs,omitempty"`
	SizeLimit int      `json:"size_limit,omitempty"`
}

type testEntry struct {
	DN    string              `json:"dn"`
	Attrs map[string][]string `json:"attrs"`
}

type testResult struct {
	ResultCode      int         `json:"result_code"`
	Entries         []testEntry `json:"entries"`
	DeniedAttrs     []string    `json:"denied_attrs"`
	DeniedTerms     []string    `json:"denied_terms"`
	UpstreamQueries int         `json:"upstream_queries"`
	EffectiveFilter string      `json:"effective_filter"`
	PostFilter      string      `json:"post_filter,omitempty"`
	Honeytoken      string      `json:"honeytoken,omitempty"`
	DurationMS      float64     `json:"duration_ms"`
}

// Endpoints.

func (c *client) Status(ctx context.Context) (statusView, error) {
	var v statusView
	return v, c.getJSON(ctx, "/v1/status", &v)
}

func (c *client) Upstreams(ctx context.Context) (map[string][]serverView, error) {
	v := map[string][]serverView{}
	return v, c.getJSON(ctx, "/v1/upstreams", &v)
}

func (c *client) Profiles(ctx context.Context) ([]profileView, error) {
	var v []profileView
	return v, c.getJSON(ctx, "/v1/profiles", &v)
}

func (c *client) Locks(ctx context.Context) ([]lockView, error) {
	var v []lockView
	return v, c.getJSON(ctx, "/v1/locks", &v)
}

func (c *client) Lock(ctx context.Context, target, key string, d time.Duration, reason string) (lockView, error) {
	var v lockView
	req := map[string]string{"target": target, "key": key, "duration": d.String()}
	if reason != "" {
		req["reason"] = reason
	}
	return v, c.sendJSON(ctx, http.MethodPost, "/v1/locks", req, &v)
}

func (c *client) Unlock(ctx context.Context, target, key string) error {
	return c.sendJSON(ctx, http.MethodDelete, "/v1/locks/"+url.PathEscape(target)+"/"+url.PathEscape(key), nil, nil)
}

func (c *client) Lockdown(ctx context.Context, on bool) (bool, error) {
	state := "off"
	if on {
		state = "on"
	}
	var v struct {
		Lockdown bool `json:"lockdown"`
	}
	err := c.sendJSON(ctx, http.MethodPost, "/v1/lockdown", map[string]string{"state": state}, &v)
	return v.Lockdown, err
}

func (c *client) Indicators(ctx context.Context) ([]indicatorView, error) {
	var v []indicatorView
	return v, c.getJSON(ctx, "/v1/indicators", &v)
}

// IndicatorsRaw returns /v1/indicators in one of the API formats.
func (c *client) IndicatorsRaw(ctx context.Context, format string, minScore float64) ([]byte, error) {
	q := url.Values{"format": {format}}
	if minScore > 0 {
		q.Set("min_score", strconv.FormatFloat(minScore, 'f', -1, 64))
	}
	b, err := c.request(ctx, http.MethodGet, "/v1/indicators?"+q.Encode(), "", nil)
	return b, err
}

// EventsRaw returns the buffered events after since as raw JSON objects.
func (c *client) EventsRaw(ctx context.Context, since uint64, limit int, types []string) ([]json.RawMessage, error) {
	q := url.Values{"since": {strconv.FormatUint(since, 10)}}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if len(types) > 0 {
		q.Set("types", strings.Join(types, ","))
	}
	var v []json.RawMessage
	return v, c.getJSON(ctx, "/v1/events?"+q.Encode(), &v)
}

func (c *client) Events(ctx context.Context, since uint64, limit int, types []string) ([]events.Record, error) {
	raw, err := c.EventsRaw(ctx, since, limit, types)
	if err != nil {
		return nil, err
	}
	out := make([]events.Record, 0, len(raw))
	for _, r := range raw {
		var rec events.Record
		if err := json.Unmarshal(r, &rec); err != nil {
			return nil, fmt.Errorf("decode event: %w", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func (c *client) Reload(ctx context.Context) error {
	return c.sendJSON(ctx, http.MethodPost, "/v1/reload", nil, nil)
}

// ConfigGet returns the running configuration with secrets masked.
func (c *client) ConfigGet(ctx context.Context) (string, error) {
	b, err := c.request(ctx, http.MethodGet, "/v1/config", "", nil)
	return string(b), err
}

// ConfigPut validates (dry) or applies a configuration file.
func (c *client) ConfigPut(ctx context.Context, body string, dry bool) (applyResult, error) {
	path := "/v1/config"
	if dry {
		path += "?dry_run=true"
	}
	var v applyResult
	b, err := c.request(ctx, http.MethodPut, path, "application/toml", []byte(body))
	if err != nil {
		return v, err
	}
	return v, decodeInto(path, b, &v)
}

func (c *client) Test(ctx context.Context, profile string, req testRequest) (testResult, error) {
	var v testResult
	return v, c.sendJSON(ctx, http.MethodPost, "/v1/profiles/"+url.PathEscape(profile)+"/test", req, &v)
}

func (c *client) Sync(ctx context.Context, profile string) error {
	return c.sendJSON(ctx, http.MethodPost, "/v1/profiles/"+url.PathEscape(profile)+"/sync", nil, nil)
}

func (c *client) Record(ctx context.Context, profile string, on bool) error {
	state := "off"
	if on {
		state = "on"
	}
	return c.sendJSON(ctx, http.MethodPost, "/v1/profiles/"+url.PathEscape(profile)+"/record", map[string]string{"state": state}, nil)
}

func (c *client) Learn(ctx context.Context, profile string, d time.Duration) (learnResult, error) {
	var v learnResult
	return v, c.sendJSON(ctx, http.MethodPost, "/v1/baseline/"+url.PathEscape(profile)+"/learn", map[string]string{"duration": d.String()}, &v)
}

// Metrics returns the Prometheus text exposition.
func (c *client) Metrics(ctx context.Context) ([]byte, error) {
	b, err := c.request(ctx, http.MethodGet, "/metrics", "", nil)
	return b, err
}

// Health returns the status code and body of /healthz or /readyz; a 503
// is an answer, not an error.
func (c *client) Health(ctx context.Context, path string) (int, []byte, error) {
	b, err := c.request(ctx, http.MethodGet, path, "", nil)
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status, b, nil
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, b, nil
}

// errStreamRefused is a stream answer that a reconnect cannot fix.
var errStreamRefused = errors.New("event stream refused")

// Stream follows /v1/events/stream from since and calls fn for every
// event. It reconnects with Last-Event-ID after a broken connection
// (backoff up to 30 s, onState reports it) and returns nil when ctx ends,
// or the error of fn, or a refusal (401/403/404).
func (c *client) Stream(ctx context.Context, since uint64, types []string, fn func(events.Record) error, onState func(error)) error {
	last := since
	backoff := time.Second
	for {
		err := c.streamOnce(ctx, last, types, func(r events.Record) error {
			last = r.Seq
			backoff = time.Second
			return fn(r)
		})
		if ctx.Err() != nil {
			return nil //nolint:nilerr // the caller ended the stream
		}
		var ae *apiError
		if errors.As(err, &ae) && ae.Status != http.StatusServiceUnavailable && ae.Status != http.StatusTooManyRequests {
			return fmt.Errorf("%w: %w", errStreamRefused, err)
		}
		var cb callbackError
		if errors.As(err, &cb) {
			return cb.err
		}
		if onState != nil {
			onState(err)
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// callbackError carries an error returned by the Stream callback.
type callbackError struct{ err error }

func (e callbackError) Error() string { return e.err.Error() }
func (e callbackError) Unwrap() error { return e.err }

func (c *client) streamOnce(ctx context.Context, since uint64, types []string, fn func(events.Record) error) error {
	q := url.Values{}
	if len(types) > 0 {
		q.Set("types", strings.Join(types, ","))
	}
	path := "/v1/events/stream"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", strconv.FormatUint(since, 10))
	c.authorize(req)
	resp, err := c.stream.Do(req)
	if err != nil {
		return c.connError(err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // read-only body
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) //nolint:errcheck // best effort error body
		return decodeAPIError(resp.StatusCode, b)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if data.Len() == 0 {
				continue
			}
			var rec events.Record
			err := json.Unmarshal([]byte(data.String()), &rec)
			data.Reset()
			if err != nil {
				return fmt.Errorf("decode event: %w", err)
			}
			if err := fn(rec); err != nil {
				return callbackError{err}
			}
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("event stream: %w", err)
	}
	return io.ErrUnexpectedEOF
}
