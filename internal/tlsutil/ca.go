// Package tlsutil manages the built-in certificate authority, server
// certificates (issue, persist, renew) and the listener tls.Config
// (SPEC §3.4 [tls], §9).
package tlsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// File names inside tls.ca_dir.
const (
	CACertFile     = "ca.crt"
	CAKeyFile      = "ca.key"
	ServerCertFile = "server.crt"
	ServerKeyFile  = "server.key"
)

// Lifetimes (SPEC §9).
const (
	CAValidity     = 10 * 365 * 24 * time.Hour
	ServerValidity = 825 * 24 * time.Hour
)

// KeyType selects the key algorithm of issued certificates.
type KeyType string

// Supported key types.
const (
	ECDSAP256 KeyType = "ecdsa-p256"
	RSA2048   KeyType = "rsa-2048"
)

// ParseKeyType validates a tls.key_type value; "" means ECDSAP256.
func ParseKeyType(s string) (KeyType, error) {
	switch KeyType(s) {
	case "", ECDSAP256:
		return ECDSAP256, nil
	case RSA2048:
		return RSA2048, nil
	default:
		return "", fmt.Errorf("unknown key type %q", s)
	}
}

// Sentinel errors.
var (
	// ErrCAExists is returned by GenerateCA when the directory already holds a CA.
	ErrCAExists = errors.New("ca already exists")
	// ErrNoCA is returned by LoadCA when ca.crt or ca.key is missing.
	ErrNoCA = errors.New("ca not found")
)

// CA is a certificate authority with its private key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	// PEM is the CA certificate in PEM form, handed to clients.
	PEM []byte
}

// GenerateKey creates a private key of the given type.
func GenerateKey(kt KeyType) (crypto.Signer, error) {
	switch kt {
	case ECDSAP256, "":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unknown key type %q", kt)
	}
}

func serial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return n, nil
}

// NewCA creates a CA certificate in memory (not written anywhere).
func NewCA(kt KeyType, now time.Time) (*CA, error) {
	key, err := GenerateKey(kt)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "ALDAP built-in CA", Organization: []string{"ALDAP"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(CAValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca certificate: %w", err)
	}
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// GenerateCA creates a CA and writes ca.crt (0644) and ca.key (0600) into
// dir, creating it with 0700. It fails with ErrCAExists when either file
// is present.
func GenerateCA(dir string, kt KeyType, now time.Time) (*CA, error) {
	for _, f := range []string{CACertFile, CAKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return nil, fmt.Errorf("%w: %s", ErrCAExists, filepath.Join(dir, f))
		}
	}
	ca, err := NewCA(kt, now)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca_dir: %w", err)
	}
	if err := WriteKeyPair(filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile), ca.PEM, ca.Key); err != nil {
		return nil, err
	}
	return ca, nil
}

// LoadCA reads ca.crt and ca.key from dir.
func LoadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w in %s", ErrNoCA, dir)
		}
		return nil, fmt.Errorf("read %s: %w", CACertFile, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w in %s", ErrNoCA, dir)
		}
		return nil, fmt.Errorf("read %s: %w", CAKeyFile, err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CACertFile, err)
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CAKeyFile, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s: certificate is not a CA", CACertFile)
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, fmt.Errorf("%s does not match %s", CAKeyFile, CACertFile)
	}
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}, nil
}

// EnsureCA loads the CA from dir or, with autoInit, creates it. created
// reports whether a new CA was written.
func EnsureCA(dir string, autoInit bool, kt KeyType, now time.Time) (ca *CA, created bool, err error) {
	ca, err = LoadCA(dir)
	switch {
	case err == nil:
		return ca, false, nil
	case !errors.Is(err, ErrNoCA):
		return nil, false, err
	case !autoInit:
		return nil, false, fmt.Errorf("%w (run `aldap gen-ca` or set tls.auto_init = true)", err)
	}
	ca, err = GenerateCA(dir, kt, now)
	if err != nil {
		return nil, false, err
	}
	return ca, true, nil
}

// SANs are the names a server certificate must cover.
type SANs struct {
	DNS []string
	IPs []net.IP
}

// ParseSANs sorts host strings into DNS names and IP addresses, ignoring
// empty and wildcard entries; duplicates are dropped.
func ParseSANs(hosts ...string) SANs {
	var out SANs
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.TrimSpace(strings.Trim(h, "[]"))
		if h == "" || h == "0.0.0.0" || h == "::" || seen[strings.ToLower(h)] {
			continue
		}
		seen[strings.ToLower(h)] = true
		if ip := net.ParseIP(h); ip != nil {
			out.IPs = append(out.IPs, ip)
		} else {
			out.DNS = append(out.DNS, strings.ToLower(h))
		}
	}
	return out
}

// Covers reports whether cert lists every name of s.
func (s SANs) Covers(cert *x509.Certificate) bool {
	for _, d := range s.DNS {
		if cert.VerifyHostname(d) != nil {
			return false
		}
	}
	for _, ip := range s.IPs {
		if cert.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}

// Issue signs a server certificate for the names with a fresh key.
func (ca *CA) Issue(sans SANs, kt KeyType, now time.Time, validity time.Duration) (tls.Certificate, error) {
	if validity <= 0 {
		validity = ServerValidity
	}
	key, err := GenerateKey(kt)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("server key: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	cn := "aldap"
	if len(sans.DNS) > 0 {
		cn = sans.DNS[0]
	} else if len(sans.IPs) > 0 {
		cn = sans.IPs[0].String()
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"ALDAP"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     sans.DNS,
		IPAddresses:  sans.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("server certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// WriteKeyPair writes a certificate PEM (0644) and its private key (0600).
// The key file is written first so that a partially written pair never
// has a certificate without a key. Both are written to a fresh temporary
// file (O_EXCL, the final mode) and renamed into place, so a pre-existing
// file with wider permissions or a symbolic link planted at the path is
// replaced, never written through.
func WriteKeyPair(certPath, keyPath string, certPEM []byte, key crypto.Signer) error {
	keyPEM, err := MarshalKeyPEM(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", certPath, err)
	}
	return nil
}

// writeFileAtomic creates a new file next to path with mode, writes data,
// syncs it and renames it over path. A symbolic link or an existing file
// at path is replaced by the new inode; nothing is ever written through a
// link. The directory must exist.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	var f *os.File
	var tmp string
	for i := 0; i < 16; i++ {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return fmt.Errorf("random name: %w", err)
		}
		tmp = filepath.Join(dir, "."+filepath.Base(path)+"."+hex.EncodeToString(buf[:])+".tmp")
		var err error
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return err
		}
	}
	if f == nil {
		return errors.New("could not create a temporary file")
	}
	cleanup := func(err error) error {
		_ = f.Close()      //nolint:errcheck // already failing; the first error is returned
		_ = os.Remove(tmp) //nolint:errcheck // best-effort cleanup of our own temp file
		return err
	}
	if _, err := f.Write(data); err != nil {
		return cleanup(err)
	}
	if err := f.Chmod(mode); err != nil { // independent of the umask
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp) //nolint:errcheck // best-effort cleanup of our own temp file
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) //nolint:errcheck // best-effort cleanup of our own temp file
		return err
	}
	return nil
}

// MarshalKeyPEM encodes a private key as PKCS#8 PEM.
func MarshalKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM decodes a PKCS#8, EC or PKCS#1 RSA private key PEM.
func ParseKeyPEM(b []byte) (crypto.Signer, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, errors.New("no private key found")
		}
		switch blk.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pkcs8 key: %w", err)
			}
			s, ok := k.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("unsupported key type %T", k)
			}
			return s, nil
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("ec key: %w", err)
			}
			return k, nil
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("rsa key: %w", err)
			}
			return k, nil
		}
	}
}

// parseCertPEM decodes the first certificate of a PEM bundle.
func parseCertPEM(b []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, errors.New("no certificate found")
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return c, nil
		}
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(eq); ok {
		return e.Equal(b)
	}
	return false
}

// LoadServerCert reads an external certificate chain and key.
func LoadServerCert(certPath, keyPath string) (tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load certificate: %w", err)
	}
	if c.Leaf == nil {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
		}
		c.Leaf = leaf
	}
	return c, nil
}

// LoadCertPool reads a PEM bundle into a pool (client_ca).
func LoadCertPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return pool, nil
}
