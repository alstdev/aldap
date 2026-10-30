package tlsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Audit 14 / A.6: file handling of the built-in CA directory.
//
// WriteKeyPair uses os.WriteFile, which follows symlinks and keeps the mode
// of an existing file. An attacker with write access to ca_dir (or a stale
// world-readable server.key left by a previous tool) therefore decides
// where and with which permissions the private keys land.

func a6Dir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes/symlinks")
	}
	return t.TempDir()
}

// TestAudit14_A6_ServerKeyKeepsWideMode: a pre-existing server.key with
// mode 0644 is overwritten with the new private key but keeps 0644.
func TestAudit14_A6_ServerKeyKeepsWideMode(t *testing.T) {
	dir := a6Dir(t)
	if _, err := GenerateCA(dir, ECDSAP256, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Stale/planted files: unusable as a certificate, so the manager reissues.
	if err := os.WriteFile(filepath.Join(dir, ServerKeyFile), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ServerCertFile), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Profile: "p", Mode: ModeBuiltinCA, CADir: dir, SANs: ParseSANs("localhost")}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ServerKeyFile))
	if err != nil || !strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatalf("server.key not rewritten: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, ServerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("FINDING: server.key holds a fresh private key with mode %04o (want 0600)", fi.Mode().Perm())
	}
}

// TestAudit14_A6_ServerKeySymlinkFollowed: server.key -> victim file. The
// manager writes the new private key through the symlink: the victim is
// truncated and now holds the key with the victim's mode.
func TestAudit14_A6_ServerKeySymlinkFollowed(t *testing.T) {
	dir := a6Dir(t)
	if _, err := GenerateCA(dir, ECDSAP256, time.Now()); err != nil {
		t.Fatal(err)
	}
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "aldap.toml")
	if err := os.WriteFile(victim, []byte("[server]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ServerKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Profile: "p", Mode: ModeBuiltinCA, CADir: dir, SANs: ParseSANs("localhost")}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PRIVATE KEY") {
		fi, _ := os.Stat(victim)
		t.Errorf("FINDING: the file behind the server.key symlink was overwritten with the server private key (mode %04o)", fi.Mode().Perm())
	}
}

// TestAudit14_A6_CAKeyDanglingSymlinkFollowed: GenerateCA checks existence
// with os.Stat (follows symlinks) and then writes with os.WriteFile. A
// dangling symlink ca.key -> elsewhere passes the check and the CA private
// key is created at the attacker-chosen path.
func TestAudit14_A6_CAKeyDanglingSymlinkFollowed(t *testing.T) {
	dir := a6Dir(t)
	outside := filepath.Join(t.TempDir(), "stolen-ca.key")
	if err := os.Symlink(outside, filepath.Join(dir, CAKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateCA(dir, ECDSAP256, time.Now()); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if b, err := os.ReadFile(outside); err == nil && strings.Contains(string(b), "PRIVATE KEY") {
		t.Errorf("FINDING: CA private key written through a dangling symlink to %s", outside)
	}
}
