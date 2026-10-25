package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alstdev/aldap/internal/vdir"
)

// FileMode is the mode of recordings: they hold filters and DNs of the
// directory.
const FileMode fs.FileMode = 0o600

// ErrNotRegular refuses a recording path that is a symbolic link or not
// a regular file.
var ErrNotRegular = errors.New("not a regular file")

// RecorderOptions configure a Recorder.
type RecorderOptions struct {
	Profile string
	Path    string
	// MaxBytes rotates the file when the next line would exceed it (0 =
	// never); MaxFiles rotated files are kept (default 5).
	MaxBytes int64
	MaxFiles int
	// Queue bounds the searches waiting to be written (default 1024); a
	// search arriving when the queue is full is dropped and counted.
	Queue  int
	Logger *slog.Logger
	Now    func() time.Time
}

// Recorder writes client searches of one profile as JSON lines in the
// replay format (Search). It implements vdir.Tap: the connection only
// hands the search over a bounded queue without waiting, a goroutine
// renders and writes it, so recording never delays an answer. The
// goroutine and the file exist only between Start and Stop.
type Recorder struct {
	o   RecorderOptions
	log *slog.Logger

	on      atomic.Bool
	dropped atomic.Uint64
	lastLog atomic.Int64

	ctl  sync.Mutex   // serializes Start and Stop (a Stop drains before a Start reopens)
	life sync.RWMutex // ch, done
	ch   chan op
	done chan struct{}

	// Owned by the writer goroutine (and by Start before it runs).
	f    *os.File
	size int64
	wErr time.Time
}

type op struct {
	ts time.Time
	s  vdir.TapSearch
}

var _ vdir.Tap = (*Recorder)(nil)

// NewRecorder returns a stopped recorder.
func NewRecorder(o RecorderOptions) *Recorder {
	if o.MaxFiles <= 0 {
		o.MaxFiles = 5
	}
	if o.Queue <= 0 {
		o.Queue = 1024
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	r := &Recorder{o: o, log: o.Logger}
	if r.log == nil {
		r.log = slog.Default()
	}
	r.log = r.log.With("profile", o.Profile, "record_file", o.Path)
	return r
}

// Path returns the recording file.
func (r *Recorder) Path() string { return r.o.Path }

// On reports whether searches are being recorded.
func (r *Recorder) On() bool { return r.on.Load() }

// Dropped counts searches lost because the queue was full.
func (r *Recorder) Dropped() uint64 { return r.dropped.Load() }

// Start opens (or creates, mode 0600) the file in append mode and starts
// recording; a running recorder is left as it is. A path that is a
// symbolic link or not a regular file is refused; a more permissive
// existing file is narrowed to 0600.
func (r *Recorder) Start() error {
	r.ctl.Lock()
	defer r.ctl.Unlock()
	r.life.Lock()
	defer r.life.Unlock()
	if r.ch != nil {
		return nil
	}
	if err := r.open(); err != nil {
		return err
	}
	r.ch, r.done = make(chan op, r.o.Queue), make(chan struct{})
	go r.loop(r.ch, r.done)
	r.on.Store(true)
	r.log.Info("recording started")
	return nil
}

// Stop ends recording: the searches already queued are written, then the
// file is closed. A stopped recorder is left as it is.
func (r *Recorder) Stop() {
	r.ctl.Lock()
	defer r.ctl.Unlock()
	r.life.Lock()
	ch, done := r.ch, r.done
	r.ch, r.done = nil, nil
	r.on.Store(false)
	r.life.Unlock()
	if ch == nil {
		return
	}
	// No sender holds ch any more: Search sends under life.RLock.
	close(ch)
	<-done
	r.log.Info("recording stopped", "dropped_total", r.dropped.Load())
}

// Search implements vdir.Tap. Searches whose filter does not parse are
// not recorded (their password values could not be redacted).
func (r *Recorder) Search(t vdir.TapSearch) {
	if !r.on.Load() || t.Filter == nil {
		return
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.ch == nil {
		return
	}
	select {
	case r.ch <- op{ts: r.o.Now(), s: t}:
	default:
		n := r.dropped.Add(1)
		now := time.Now().Unix()
		if last := r.lastLog.Load(); now-last >= 60 && r.lastLog.CompareAndSwap(last, now) {
			r.log.Warn("record: queue full, searches not recorded", "dropped_total", n)
		}
	}
}

func (r *Recorder) loop(ch <-chan op, done chan<- struct{}) {
	defer close(done)
	for o := range ch {
		var err error
		if r.f == nil {
			err = r.open() // after a failed rotation
		}
		if r.f != nil {
			err = r.write(Line(r.o.Profile, o.ts, o.s))
		}
		if err != nil && time.Since(r.wErr) > time.Minute {
			r.wErr = time.Now()
			r.log.Warn("record: write failed", "err", err)
		}
	}
	r.closeFile()
}

// Line renders one search as a JSON line (with the newline). dns is left
// out when the line would exceed MaxLine.
func Line(profile string, ts time.Time, t vdir.TapSearch) []byte {
	code, n := t.Result.Code, len(t.Entries)
	attrs := t.Attrs
	if attrs == nil {
		attrs = []string{}
	}
	s := Search{TS: ts.UTC().Format(time.RFC3339Nano), Profile: profile, Base: t.Base, Scope: t.Scope.String(),
		Filter: RedactFilter(t.Filter), Attrs: attrs, SizeLimit: t.SizeLimit, ResultCode: &code, Entries: &n, DNList: make([]string, 0, n)}
	for _, e := range t.Entries {
		s.DNList = append(s.DNList, e.DN)
	}
	b, err := json.Marshal(s)
	if err == nil && len(b) > MaxLine {
		s.DNList = nil
		b, err = json.Marshal(s)
	}
	if err != nil { // strings and ints only
		return nil
	}
	return append(b, '\n')
}

func (r *Recorder) open() error {
	if fi, err := os.Lstat(r.o.Path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("record: %s: %w", r.o.Path, ErrNotRegular)
	}
	f, err := os.OpenFile(r.o.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, FileMode)
	if err != nil {
		return fmt.Errorf("record: open %s: %w", r.o.Path, err)
	}
	st, err := f.Stat()
	if err == nil && st.Mode().Perm() != FileMode {
		err = f.Chmod(FileMode)
	}
	if err != nil {
		_ = f.Close() //nolint:errcheck // abandoned handle
		return fmt.Errorf("record: %s: %w", r.o.Path, err)
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *Recorder) closeFile() {
	if r.f == nil {
		return
	}
	if err := r.f.Close(); err != nil {
		r.log.Warn("record: close failed", "err", err)
	}
	r.f = nil
}

func (r *Recorder) write(line []byte) error {
	if len(line) == 0 {
		return nil
	}
	if r.o.MaxBytes > 0 && r.size > 0 && r.size+int64(len(line)) > r.o.MaxBytes {
		if err := r.rotate(); err != nil {
			return err
		}
	}
	n, err := r.f.Write(line)
	r.size += int64(n)
	return err
}

// Rotated names the i-th rotated file of path (path.1 is the newest).
func Rotated(path string, i int) string { return path + "." + strconv.Itoa(i) }

// rotate shifts path → path.1 → … → path.<MaxFiles>; the oldest goes.
func (r *Recorder) rotate() error {
	r.closeFile()
	if err := os.Remove(Rotated(r.o.Path, r.o.MaxFiles)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("record: rotate: %w", err)
	}
	for i := r.o.MaxFiles - 1; i >= 1; i-- {
		if _, err := os.Lstat(Rotated(r.o.Path, i)); err == nil {
			if err := os.Rename(Rotated(r.o.Path, i), Rotated(r.o.Path, i+1)); err != nil {
				return fmt.Errorf("record: rotate: %w", err)
			}
		}
	}
	if err := os.Rename(r.o.Path, Rotated(r.o.Path, 1)); err != nil {
		return fmt.Errorf("record: rotate: %w", err)
	}
	return r.open()
}
