package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestNoSecretsInOutput_Headers: webhook header values (inline and from
// headers_file) reach the destination but never GET /v1/config, logs or
// events.
func TestNoSecretsInOutput_Headers(t *testing.T) {
	const (
		fileToken   = "Bearer S3CR3T-headers-file-4b1d"
		inlineToken = "S3CR3T-inline-apikey-9c2e"
	)
	var (
		mu  sync.Mutex
		got []http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Clone())
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	hf := filepath.Join(t.TempDir(), "siem-headers.toml")
	if err := os.WriteFile(hf, []byte("Authorization = \""+fileToken+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := startDaemon(t, `
[[events.webhook]]
name = "siem"
url = "`+srv.URL+`"
batch_size = 1
batch_interval = "50ms"
headers_file = "`+hf+`"
[events.webhook.headers]
X-Api-Key = "`+inlineToken+`"
X-Source = "aldap"
`)
	c := r.ldaps(t)
	_ = c.Bind(tClientDN, "wrong-password")
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) > 0 })
	mu.Lock()
	h := got[0]
	mu.Unlock()
	if h.Get("Authorization") != fileToken || h.Get("X-Api-Key") != inlineToken || h.Get("X-Source") != "aldap" {
		t.Errorf("headers not delivered: %d values", len(h))
	}
	ctl := newController(r.path, true, daemonOptions{}, r.d)
	rendered, err := ctl.ConfigTOML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), `X-Api-Key = "***"`) || !strings.Contains(string(rendered), hf) {
		t.Errorf("rendering: names with masked values and headers_file expected:\n%s", rendered)
	}
	r.d.stop()
	all := string(rendered) + r.logs.String()
	for _, m := range []string{fileToken, inlineToken, "S3CR3T-"} {
		if strings.Contains(all, m) {
			t.Errorf("%q leaks into GET /v1/config, logs or events", m)
		}
	}
}
