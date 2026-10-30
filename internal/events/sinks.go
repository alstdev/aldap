package events

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// WriterSink writes records as JSON lines to w (the stdout sink).
type WriterSink struct {
	W io.Writer
}

// Write implements RecordSink.
func (s *WriterSink) Write(_ context.Context, batch []Record) error {
	buf := make([]byte, 0, 512*len(batch))
	for _, r := range batch {
		buf = append(buf, r.JSON()...)
		buf = append(buf, '\n')
	}
	_, err := s.W.Write(buf)
	return err
}

// Close implements RecordSink; stdout is never closed.
func (s *WriterSink) Close() error { return nil }

// FileSink appends JSON lines to a file and rotates it by size
// ([events.file]): path → path.1(.gz) … path.<max_files>(.gz).
type FileSink struct {
	Path     string
	MaxBytes int64
	MaxFiles int
	Compress bool

	mu   sync.Mutex
	f    *os.File
	size int64
}

// NewFileSink opens (or creates, 0600) the file in append mode.
func NewFileSink(path string, maxMB, maxFiles int, compress bool) (*FileSink, error) {
	if maxFiles <= 0 {
		maxFiles = 10
	}
	s := &FileSink{Path: path, MaxBytes: int64(maxMB) << 20, MaxFiles: maxFiles, Compress: compress}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileSink) open() error {
	// Never append events through a link or to a device/FIFO/directory:
	// the path must be absent or a regular file (also guards the CA key or
	// the configuration against being named here).
	if fi, err := os.Lstat(s.Path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("events: open %s: not a regular file (%s)", s.Path, fi.Mode().Type())
	}
	f, err := os.OpenFile(s.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("events: open %s: %w", s.Path, err)
	}
	st, err := f.Stat()
	if err != nil {
		closeQuietly(f)
		return fmt.Errorf("events: stat %s: %w", s.Path, err)
	}
	s.f, s.size = f, st.Size()
	return nil
}

// Write implements RecordSink.
func (s *FileSink) Write(_ context.Context, batch []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		if err := s.open(); err != nil {
			return err
		}
	}
	for _, r := range batch {
		line := append(r.JSON(), '\n')
		if s.MaxBytes > 0 && s.size > 0 && s.size+int64(len(line)) > s.MaxBytes {
			if err := s.rotate(); err != nil {
				return err
			}
		}
		n, err := s.f.Write(line)
		s.size += int64(n)
		if err != nil {
			return fmt.Errorf("events: write %s: %w", s.Path, err)
		}
	}
	return nil
}

// rotated names the i-th rotated file.
func (s *FileSink) rotated(i int) string {
	name := s.Path + "." + strconv.Itoa(i)
	if s.Compress {
		name += ".gz"
	}
	return name
}

// rotate closes the current file, shifts the older ones and reopens.
func (s *FileSink) rotate() error {
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("events: close %s: %w", s.Path, err)
	}
	s.f = nil
	if err := os.Remove(s.rotated(s.MaxFiles)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("events: rotate: %w", err)
	}
	for i := s.MaxFiles - 1; i >= 1; i-- {
		if _, err := os.Stat(s.rotated(i)); err == nil {
			if err := os.Rename(s.rotated(i), s.rotated(i+1)); err != nil {
				return fmt.Errorf("events: rotate: %w", err)
			}
		}
	}
	if s.Compress {
		if err := gzipFile(s.Path, s.rotated(1)); err != nil {
			return err
		}
		if err := os.Remove(s.Path); err != nil {
			return fmt.Errorf("events: rotate: %w", err)
		}
	} else if err := os.Rename(s.Path, s.rotated(1)); err != nil {
		return fmt.Errorf("events: rotate: %w", err)
	}
	return s.open()
}

// gzipFile compresses src into dst (0600).
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("events: compress: %w", err)
	}
	defer closeQuietly(in)
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("events: compress: %w", err)
	}
	gz := gzip.NewWriter(out)
	gz.Name = filepath.Base(src)
	if _, err := io.Copy(gz, in); err != nil {
		closeQuietly(out)
		return fmt.Errorf("events: compress: %w", err)
	}
	if err := gz.Close(); err != nil {
		closeQuietly(out)
		return fmt.Errorf("events: compress: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("events: compress: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("events: compress: %w", err)
	}
	return nil
}

// closeQuietly closes c; the error is irrelevant on an abandoned handle.
func closeQuietly(c io.Closer) {
	if err := c.Close(); err != nil {
		slog.Default().Debug("events: close failed", "err", err)
	}
}

// Close implements RecordSink.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
