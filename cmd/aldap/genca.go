package main

import (
	"crypto"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/tlsutil"
)

// tlsFromConfig reads [tls] of the configuration (when one is readable) so
// that gen-ca/gen-cert default to the configured ca_dir and key_type.
func tlsFromConfig(cfgPath string) config.TLS {
	path, required := config.ResolvePath(cfgPath, os.LookupEnv)
	cfg, err := config.LoadFile(path, required)
	if err != nil {
		return config.Default().TLS
	}
	return cfg.TLS
}

// runGenCA is `aldap gen-ca`: create the built-in CA (SPEC §3.4 [tls]).
func runGenCA(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gen-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file to read tls.ca_dir and tls.key_type from")
	dir := fs.String("dir", "", "CA directory (default tls.ca_dir)")
	keyType := fs.String("key-type", "", "ecdsa-p256 or rsa-2048 (default tls.key_type)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: aldap gen-ca [--config FILE] [--dir DIR] [--key-type TYPE]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "aldap gen-ca: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	t := tlsFromConfig(*cfgPath)
	if *dir == "" {
		*dir = t.CADir
	}
	if *keyType == "" {
		*keyType = t.KeyType
	}
	kt, err := tlsutil.ParseKeyType(*keyType)
	if err != nil {
		fmt.Fprintf(stderr, "aldap gen-ca: %v\n", err)
		return 2
	}
	ca, err := tlsutil.GenerateCA(*dir, kt, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "aldap gen-ca: %v\n", err)
		if errors.Is(err, tlsutil.ErrCAExists) {
			fmt.Fprintln(stderr, "aldap gen-ca: remove the existing files first if you really want a new CA; clients trusting the old one will stop verifying")
		}
		return 1
	}
	fmt.Fprintf(stdout, "CA created in %s\n  certificate: %s\n  key:         %s (0600)\n  subject:     %s\n  expires:     %s\n",
		*dir, filepath.Join(*dir, tlsutil.CACertFile), filepath.Join(*dir, tlsutil.CAKeyFile), ca.Cert.Subject.String(), ca.Cert.NotAfter.UTC().Format(time.RFC3339))
	return 0
}

// runGenCert is `aldap gen-cert`: issue a server certificate from the
// built-in CA for the given names (for external TLS terminators or tests).
func runGenCert(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gen-cert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file to read tls.ca_dir, tls.key_type and tls.san from")
	dir := fs.String("dir", "", "CA directory (default tls.ca_dir)")
	out := fs.String("out", "", "output directory for server.crt/server.key (default the CA directory)")
	san := fs.String("san", "", "comma separated DNS names and IPs (default tls.san)")
	keyType := fs.String("key-type", "", "ecdsa-p256 or rsa-2048 (default tls.key_type)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: aldap gen-cert [--config FILE] [--dir DIR] [--out DIR] [--san a.example.org,10.0.0.5] [--key-type TYPE]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "aldap gen-cert: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	t := tlsFromConfig(*cfgPath)
	if *dir == "" {
		*dir = t.CADir
	}
	if *out == "" {
		*out = *dir
	}
	if *keyType == "" {
		*keyType = t.KeyType
	}
	names := t.SAN
	if *san != "" {
		names = strings.Split(*san, ",")
	}
	sans := tlsutil.ParseSANs(names...)
	if len(sans.DNS)+len(sans.IPs) == 0 {
		fmt.Fprintln(stderr, "aldap gen-cert: at least one name is required (--san or tls.san)")
		return 2
	}
	kt, err := tlsutil.ParseKeyType(*keyType)
	if err != nil {
		fmt.Fprintf(stderr, "aldap gen-cert: %v\n", err)
		return 2
	}
	ca, err := tlsutil.LoadCA(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "aldap gen-cert: %v\n", err)
		return 1
	}
	cert, err := ca.Issue(sans, kt, time.Now(), tlsutil.ServerValidity)
	if err != nil {
		fmt.Fprintf(stderr, "aldap gen-cert: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		fmt.Fprintf(stderr, "aldap gen-cert: %v\n", err)
		return 1
	}
	certPath, keyPath := filepath.Join(*out, tlsutil.ServerCertFile), filepath.Join(*out, tlsutil.ServerKeyFile)
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		fmt.Fprintf(stderr, "aldap gen-cert: unsupported key type %T\n", cert.PrivateKey)
		return 1
	}
	if err := tlsutil.WriteKeyPair(certPath, keyPath, tlsutil.ChainPEM(cert), key); err != nil {
		fmt.Fprintf(stderr, "aldap gen-cert: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "server certificate written\n  certificate: %s\n  key:         %s (0600)\n  names:       %s %s\n  expires:     %s\n",
		certPath, keyPath, strings.Join(sans.DNS, ","), fmt.Sprint(sans.IPs), cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return 0
}
