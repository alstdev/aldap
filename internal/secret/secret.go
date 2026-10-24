// Package secret resolves secret values from inline, file and environment sources (SPEC §3.2).
//
// Every sensitive configuration key X accepts exactly one of three forms:
// X (inline), X_file (path, trailing newline trimmed) and X_env (variable name).
// Resolved values and inline values never print themselves: fmt, JSON, slog and
// encoding.TextMarshaler all see "***".
package secret

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
)

// Redacted is what every secret renders as outside Reveal().
const Redacted = "***"

// MaxFileMode is the most permissive mode a secret file may have without a warning.
const MaxFileMode fs.FileMode = 0o640

// Sentinel errors, matched with errors.Is.
var (
	ErrMultipleSources = errors.New("secret has more than one source")
	ErrEnvNotSet       = errors.New("environment variable is not set")
	ErrEmpty           = errors.New("secret is empty")
)

// Inline is a secret given directly in the configuration. It decodes from TOML
// like a plain string but redacts itself in every textual representation.
type Inline string

// String implements fmt.Stringer and always returns Redacted.
func (Inline) String() string { return Redacted }

// GoString keeps %#v from printing the value.
func (Inline) GoString() string { return "secret.Inline(" + Redacted + ")" }

// MarshalText redacts the value for JSON, TOML and similar encoders. An
// unset value encodes empty, so a rendered configuration loads back with
// the key unset instead of an inline secret "***".
func (s Inline) MarshalText() ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	return []byte(Redacted), nil
}

// LogValue redacts the value for log/slog.
func (Inline) LogValue() slog.Value { return slog.StringValue(Redacted) }

// Reveal returns the raw value. Callers must not log or persist it.
func (s Inline) Reveal() string { return string(s) }

// IsSet reports whether an inline value was given.
func (s Inline) IsSet() bool { return s != "" }

// Value is a resolved secret.
type Value struct {
	b []byte
}

// String implements fmt.Stringer and always returns Redacted.
func (Value) String() string { return Redacted }

// GoString keeps %#v from printing the value.
func (Value) GoString() string { return "secret.Value(" + Redacted + ")" }

// MarshalText redacts the value for JSON and similar encoders.
func (Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue redacts the value for log/slog.
func (Value) LogValue() slog.Value { return slog.StringValue(Redacted) }

// Reveal returns the raw value. Callers must not log or persist it.
func (v Value) Reveal() string { return string(v.b) }

// Bytes returns a copy of the raw bytes.
func (v Value) Bytes() []byte { return append([]byte(nil), v.b...) }

// IsZero reports whether no value is held.
func (v Value) IsZero() bool { return len(v.b) == 0 }

// Wipe overwrites the held bytes with zeros and empties the value.
func (v *Value) Wipe() {
	for i := range v.b {
		v.b[i] = 0
	}
	v.b = nil
}

// Source is the triple of alternative sources of one secret key.
type Source struct {
	Inline Inline
	File   string
	Env    string
}

// Kind names the form a Source uses: "inline", "file", "env" or "" when unset.
func (s Source) Kind() string {
	switch {
	case s.Inline.IsSet():
		return "inline"
	case s.File != "":
		return "file"
	case s.Env != "":
		return "env"
	}
	return ""
}

// IsSet reports whether any form is given.
func (s Source) IsSet() bool { return s.Kind() != "" }

// Check verifies the source is well formed without reading it: at most one form.
func (s Source) Check() error {
	n := 0
	for _, set := range []bool{s.Inline.IsSet(), s.File != "", s.Env != ""} {
		if set {
			n++
		}
	}
	if n > 1 {
		return ErrMultipleSources
	}
	return nil
}

// Warning is a non-fatal finding about a source, e.g. a too permissive file.
type Warning struct {
	Msg string
}

// Resolver reads secrets using injectable file system and environment accessors,
// so tests never touch real secrets.
type Resolver struct {
	// ReadFile defaults to os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Stat defaults to os.Stat.
	Stat func(string) (fs.FileInfo, error)
	// LookupEnv defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// Default resolves against the real file system and environment.
var Default = Resolver{}

func (r Resolver) readFile() func(string) ([]byte, error) {
	if r.ReadFile != nil {
		return r.ReadFile
	}
	return os.ReadFile
}

func (r Resolver) stat() func(string) (fs.FileInfo, error) {
	if r.Stat != nil {
		return r.Stat
	}
	return os.Stat
}

func (r Resolver) lookupEnv() func(string) (string, bool) {
	if r.LookupEnv != nil {
		return r.LookupEnv
	}
	return os.LookupEnv
}

// Resolve reads the secret. It returns ErrMultipleSources when more than one
// form is set, ErrEnvNotSet for a missing variable, ErrEmpty for an empty
// value and the wrapped I/O error for an unreadable file. A file more
// permissive than MaxFileMode yields a Warning, not an error. An unset Source
// resolves to a zero Value without error.
func (r Resolver) Resolve(s Source) (Value, []Warning, error) {
	if err := s.Check(); err != nil {
		return Value{}, nil, err
	}
	switch s.Kind() {
	case "inline":
		return Value{b: []byte(s.Inline.Reveal())}, nil, nil
	case "file":
		return r.resolveFile(s.File)
	case "env":
		v, ok := r.lookupEnv()(s.Env)
		if !ok {
			return Value{}, nil, fmt.Errorf("%s: %w", s.Env, ErrEnvNotSet)
		}
		if v == "" {
			return Value{}, nil, fmt.Errorf("%s: %w", s.Env, ErrEmpty)
		}
		return Value{b: []byte(v)}, nil, nil
	}
	return Value{}, nil, nil
}

func (r Resolver) resolveFile(path string) (Value, []Warning, error) {
	var warns []Warning
	if fi, err := r.stat()(path); err == nil {
		if mode := fi.Mode().Perm(); mode&^MaxFileMode != 0 {
			warns = append(warns, Warning{Msg: fmt.Sprintf("%s: mode %04o is more permissive than %04o", path, mode, MaxFileMode)})
		}
	}
	b, err := r.readFile()(path)
	if err != nil {
		return Value{}, warns, fmt.Errorf("read secret file: %w", err)
	}
	b = []byte(strings.TrimRight(string(b), "\r\n"))
	if len(b) == 0 {
		return Value{}, warns, fmt.Errorf("%s: %w", path, ErrEmpty)
	}
	return Value{b: b}, warns, nil
}

// Probe checks that a file-backed source can be read later without returning
// its content. It is used by offline validation. It returns the read error (if
// any) and permission warnings.
func (r Resolver) Probe(s Source) ([]Warning, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	if s.Kind() != "file" {
		return nil, nil
	}
	v, warns, err := r.resolveFile(s.File)
	v.Wipe()
	return warns, err
}
