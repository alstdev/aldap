package secret

// Audit 14, area A.10: *_file secret sources. A failing test is a finding
// documented in the audit report, not a regression to silence.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A *_file pointing at a FIFO must not block `aldap check` / start forever:
// os.ReadFile opens the FIFO and waits for a writer.
func TestAudit14_A10_FIFODoesNotHang(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pw.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Default.Probe(Source{File: fifo})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was accepted as a secret file")
		}
	case <-time.After(2 * time.Second):
		t.Error("Probe blocks on a FIFO (no regular-file check, no timeout)")
		// release the blocked reader so the test binary can exit cleanly
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_, _ = w.WriteString("x\n")
			_ = w.Close()
		}
		<-done
	}
}

// A *_file has no size cap: the whole file is read into memory. 64 MiB of
// a sparse file (never /dev/zero) is enough to show the absence of a
// limit; a path like /dev/zero or a multi-GiB file would exhaust memory.
func TestAudit14_A10_LargeFileCapped(t *testing.T) {
	const size = 64 << 20
	p := filepath.Join(t.TempDir(), "big")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	// non-zero tail so TrimRight("\r\n") keeps the length
	if _, err := f.WriteAt([]byte("x"), size-1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	v, _, err := Default.Resolve(Source{File: p})
	if err != nil {
		return // a size limit refuses the file: fine
	}
	defer v.Wipe()
	if n := len(v.Reveal()); n >= size {
		t.Errorf("secret file read without a size cap: %d bytes held in memory", n)
	}
}

// A symlinked secret file is followed (no Lstat): evidence for the report.
func TestAudit14_A10_SymlinkFollowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink:", err)
	}
	v, _, err := Default.Resolve(Source{File: link})
	if err != nil {
		t.Logf("symlink refused: %v", err)
		return
	}
	defer v.Wipe()
	if v.Reveal() != "pw" {
		t.Errorf("unexpected content %q", v.Reveal())
	}
	t.Log("symlink followed (os.ReadFile, no Lstat)")
}
