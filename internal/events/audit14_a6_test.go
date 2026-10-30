package events

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Audit 14 / A.6: the events webhook sink uses a default http.Client, which
// follows up to ten redirects. A 307/308 from the configured endpoint
// re-sends the signed body, the custom headers (headers / headers_file,
// documented as the place for Authorization and API keys) and the HMAC
// signature to whatever Location says. The notify webhook channel
// (internal/notify/channels.go httpClient) disables redirects; this sink
// does not.
func TestAudit14_A6_WebhookFollowsRedirect(t *testing.T) {
	const apiKey = "S3CR3T-webhook-apikey-7f3a"
	var (
		mu       sync.Mutex
		leaked   []*http.Request
		leakBody []byte
	)
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		mu.Lock()
		leaked = append(leaked, r.Clone(context.Background()))
		leakBody = append([]byte(nil), buf[:n]...)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer attacker.Close()
	siem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer siem.Close()

	s, err := NewWebhookSink(WebhookOptions{URL: siem.URL, Headers: map[string]string{"X-Api-Key": apiKey, "Authorization": "Bearer " + apiKey},
		Key: []byte("hmac-key"), Retries: 0, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Write(context.Background(), []Record{rec(1)})
	mu.Lock()
	defer mu.Unlock()
	if len(leaked) == 0 {
		return // redirect not followed: OK
	}
	r := leaked[0]
	t.Errorf("FINDING: webhook sink followed a %d redirect to %s; method=%s X-Api-Key=%q Authorization=%q %s=%q body=%d bytes (contains event: %v)",
		http.StatusTemporaryRedirect, attacker.URL, r.Method, r.Header.Get("X-Api-Key"), r.Header.Get("Authorization"),
		SignatureHeader, r.Header.Get(SignatureHeader), len(leakBody), strings.Contains(string(leakBody), `"event"`))
}
