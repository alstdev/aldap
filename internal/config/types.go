package config

import (
	"encoding"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that decodes from a TOML string such as "15m".
type Duration time.Duration

var (
	_ encoding.TextUnmarshaler = (*Duration)(nil)
	_ encoding.TextMarshaler   = Duration(0)
)

// UnmarshalText parses a Go duration string.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(b), err)
	}
	*d = Duration(v)
	return nil
}

// MarshalText renders the duration in Go syntax.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// String renders the duration in Go syntax.
func (d Duration) String() string { return time.Duration(d).String() }

// D returns the value as time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// ByteSize is a size in bytes that decodes from "1MiB", "512KiB", "2MB" or a bare integer.
type ByteSize int64

var (
	_ encoding.TextUnmarshaler = (*ByteSize)(nil)
	_ encoding.TextMarshaler   = ByteSize(0)
)

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"GB", 1_000_000_000}, {"MB", 1_000_000}, {"KB", 1_000},
	{"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1},
}

// UnmarshalText parses a size with an optional binary or decimal unit.
func (s *ByteSize) UnmarshalText(b []byte) error {
	txt := strings.TrimSpace(string(b))
	num, mult := txt, int64(1)
	for _, u := range byteUnits {
		if strings.HasSuffix(txt, u.suffix) {
			num, mult = strings.TrimSpace(strings.TrimSuffix(txt, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid byte size %q", txt)
	}
	*s = ByteSize(n * mult)
	return nil
}

// MarshalText renders the size with the largest exact binary unit.
func (s ByteSize) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// String renders the size with the largest exact binary unit.
func (s ByteSize) String() string {
	v := int64(s)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if v != 0 && v%u.mult == 0 {
			return strconv.FormatInt(v/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(v, 10)
}

// Percent is a ratio that decodes from "20%" or "0.2".
type Percent float64

var (
	_ encoding.TextUnmarshaler = (*Percent)(nil)
	_ encoding.TextMarshaler   = Percent(0)
)

// UnmarshalText parses "N%" into N/100 or a bare float as is.
func (p *Percent) UnmarshalText(b []byte) error {
	txt := strings.TrimSpace(string(b))
	if strings.HasSuffix(txt, "%") {
		f, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(txt, "%")), 64)
		if err != nil || f < 0 {
			return fmt.Errorf("invalid percent %q", txt)
		}
		*p = Percent(f / 100)
		return nil
	}
	f, err := strconv.ParseFloat(txt, 64)
	if err != nil || f < 0 {
		return fmt.Errorf("invalid percent %q", txt)
	}
	*p = Percent(f)
	return nil
}

// MarshalText renders the ratio as "N%".
func (p Percent) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// String renders the ratio as "N%".
func (p Percent) String() string {
	return strconv.FormatFloat(float64(p)*100, 'f', -1, 64) + "%"
}
