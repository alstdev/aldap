package testdir

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// certBundle is a throw-away CA and a server certificate for 127.0.0.1.
type certBundle struct {
	caPEM  []byte
	server tls.Certificate
	pool   *x509.CertPool
}

func newCertBundle() (*certBundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("testdir: ca key: %w", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "aldap testdir CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("testdir: ca cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("testdir: ca parse: %w", err)
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("testdir: server key: %w", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "dc.test.aldap"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("testdir: server cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &certBundle{
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		server: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey, Leaf: srvTmpl},
		pool:   pool,
	}, nil
}

func (b *certBundle) serverConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{b.server}, MinVersion: tls.VersionTLS12}
}

func (b *certBundle) clientConfig() *tls.Config {
	return &tls.Config{RootCAs: b.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}
