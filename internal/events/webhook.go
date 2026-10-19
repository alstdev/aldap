package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// SignatureHeader carries the HMAC-SHA256 of the request body ("sha256=<hex>").
const SignatureHeader = "X-ALDAP-Signature"

// WebhookSink POSTs batches of records as a JSON array ([[events.webhook]]).
type WebhookSink struct {
	URL     string
	Headers map[string]string
	// Key signs the body; empty disables the signature header.
	Key []byte
	// Retries is the number of attempts after the first; Backoff doubles
	// up to MaxBackoff between attempts.
	Retries    int
	Backoff    time.Duration
	MaxBackoff time.Duration
	Client     *http.Client
	// Sleep overrides time.Sleep between attempts (tests).
	Sleep func(context.Context, time.Duration)
	// UserAgent is sent with every request.
	UserAgent string
}

// WebhookOptions build a WebhookSink.
type WebhookOptions struct {
	URL        string
	Headers    map[string]string
	Key        []byte
	Timeout    time.Duration
	Retries    int
	Backoff    time.Duration
	MaxBackoff time.Duration
	// TLSCAFile verifies the destination with this bundle instead of the system roots.
	TLSCAFile string
	UserAgent string
}

// NewWebhookSink builds the sink with its own HTTP client.
func NewWebhookSink(o WebhookOptions) (*WebhookSink, error) {
	if o.URL == "" {
		return nil, errors.New("events: webhook url required")
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Backoff <= 0 {
		o.Backoff = time.Second
	}
	if o.MaxBackoff < o.Backoff {
		o.MaxBackoff = 60 * time.Second
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("events: default HTTP transport is not *http.Transport")
	}
	tr = tr.Clone()
	if o.TLSCAFile != "" {
		pem, err := os.ReadFile(o.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("events: webhook tls_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("events: webhook tls_ca_file %s: no certificates", o.TLSCAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	ua := o.UserAgent
	if ua == "" {
		ua = "aldap"
	}
	return &WebhookSink{URL: o.URL, Headers: o.Headers, Key: o.Key, Retries: o.Retries, Backoff: o.Backoff, MaxBackoff: o.MaxBackoff,
		Client: &http.Client{Transport: tr, Timeout: o.Timeout}, UserAgent: ua}, nil
}

// Sign returns the signature header value for body.
func Sign(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// VerifySignature checks a signature header value against body.
func VerifySignature(key, body []byte, header string) bool {
	return hmac.Equal([]byte(Sign(key, body)), []byte(header))
}

// Write implements RecordSink: one POST per batch, retried with backoff on
// network errors, 429 and 5xx; other 4xx responses drop the batch.
func (s *WebhookSink) Write(ctx context.Context, batch []Record) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("events: webhook encode: %w", err)
	}
	backoff := s.Backoff
	var last error
	for attempt := 0; attempt <= s.Retries; attempt++ {
		if attempt > 0 {
			sleep := s.Sleep
			if sleep == nil {
				sleep = sleepCtx
			}
			sleep(ctx, backoff)
			if backoff *= 2; backoff > s.MaxBackoff {
				backoff = s.MaxBackoff
			}
		}
		retry, err := s.post(ctx, body)
		if err == nil {
			return nil
		}
		last = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return last
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// post sends one request; retry says whether the failure is transient.
func (s *WebhookSink) post(ctx context.Context, body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("events: webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.UserAgent)
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	if len(s.Key) > 0 {
		req.Header.Set(SignatureHeader, Sign(s.Key, body))
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return true, fmt.Errorf("events: webhook post: %w", err)
	}
	defer closeQuietly(resp.Body)
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); err != nil {
		return true, fmt.Errorf("events: webhook response: %w", err)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("events: webhook %s: status %d", s.URL, resp.StatusCode)
	default:
		return false, fmt.Errorf("events: webhook %s: status %d", s.URL, resp.StatusCode)
	}
}

// Close implements RecordSink.
func (s *WebhookSink) Close() error {
	s.Client.CloseIdleConnections()
	return nil
}
