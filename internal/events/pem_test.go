package events

import (
	"encoding/pem"
	"net/http/httptest"
	"testing"
)

// pemOf returns the PEM of the test server's leaf certificate.
func pemOf(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
