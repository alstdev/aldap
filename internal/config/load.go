package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Sentinel errors, matched with errors.Is.
var (
	ErrUnknownKey    = errors.New("unknown configuration key")
	ErrDuplicateName = errors.New("duplicate name")
	ErrNoConfig      = errors.New("no configuration file")
)

// EnvConfigPath is the environment variable naming the configuration file.
const EnvConfigPath = "ALDAP_CONFIG"

// DefaultConfigPath is used when neither --config nor ALDAP_CONFIG is given.
const DefaultConfigPath = "/etc/aldap/aldap.toml"

// document is the TOML shape of one file: the scalar sections of Config plus
// the named tables kept as primitives so that per-name defaults can be applied
// before decoding them.
type document struct {
	Config
	Upstream map[string]toml.Primitive `toml:"upstream"`
	Profile  map[string]toml.Primitive `toml:"profile"`
}

// Loader reads configuration with injectable file system and environment
// accessors, so tests never touch the real ones.
type Loader struct {
	// ReadFile defaults to os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Glob defaults to filepath.Glob.
	Glob func(string) ([]string, error)
	// Environ defaults to os.Environ.
	Environ func() []string
}

func (l Loader) readFile() func(string) ([]byte, error) {
	if l.ReadFile != nil {
		return l.ReadFile
	}
	return os.ReadFile
}

func (l Loader) glob() func(string) ([]string, error) {
	if l.Glob != nil {
		return l.Glob
	}
	return filepath.Glob
}

func (l Loader) environ() func() []string {
	if l.Environ != nil {
		return l.Environ
	}
	return os.Environ
}

// Load reads path (and its includes), overlays ALDAP_* environment variables,
// applies defaults and returns the configuration without validating it.
//
// When path is "" and required is false, a missing default file is not an
// error: the configuration then comes from the environment only (SPEC §3.3).
func (l Loader) Load(path string, required bool) (*Config, error) {
	cfg := Default()
	doc := &document{Config: *cfg}
	if path != "" {
		if err := l.loadFile(doc, path, true); err != nil {
			if !required && errors.Is(err, fs.ErrNotExist) {
				cfg = &doc.Config
				goto overlay
			}
			return nil, err
		}
	}
	cfg = &doc.Config
overlay:
	if err := applyEnv(cfg, l.environ()()); err != nil {
		return nil, err
	}
	finalize(cfg)
	return cfg, nil
}

// LoadFile is Load with the real file system and environment.
func LoadFile(path string, required bool) (*Config, error) {
	return Loader{}.Load(path, required)
}

// ResolvePath picks the configuration path: flag, then ALDAP_CONFIG, then the
// default. required reports whether the file must exist (true unless the
// default was chosen).
func ResolvePath(flag string, lookupEnv func(string) (string, bool)) (path string, required bool) {
	if flag != "" {
		return flag, true
	}
	if v, ok := lookupEnv(EnvConfigPath); ok && v != "" {
		return v, true
	}
	return DefaultConfigPath, false
}

func (l Loader) loadFile(doc *document, path string, followIncludes bool) error {
	data, err := l.readFile()(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := l.decode(doc, path, string(data)); err != nil {
		return err
	}
	if !followIncludes {
		return nil
	}
	for _, pattern := range doc.Server.Include {
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(filepath.Dir(path), pattern)
		}
		matches, err := l.glob()(pattern)
		if err != nil {
			return fmt.Errorf("server.include %q: %w", pattern, err)
		}
		sort.Strings(matches)
		for _, m := range matches {
			if err := l.loadFile(doc, m, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l Loader) decode(doc *document, path, data string) error {
	doc.Upstream, doc.Profile = nil, nil
	md, err := toml.Decode(data, doc)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for name, prim := range doc.Upstream {
		if _, dup := doc.Upstreams[name]; dup {
			return fmt.Errorf("%s: upstream.%s: %w", path, name, ErrDuplicateName)
		}
		u := DefaultUpstream()
		if err := md.PrimitiveDecode(prim, u); err != nil {
			return fmt.Errorf("%s: upstream.%s: %w", path, name, err)
		}
		doc.Upstreams[name] = u
	}
	for name, prim := range doc.Profile {
		if _, dup := doc.Profiles[name]; dup {
			return fmt.Errorf("%s: profile.%s: %w", path, name, ErrDuplicateName)
		}
		p := DefaultProfile()
		if err := md.PrimitiveDecode(prim, p); err != nil {
			return fmt.Errorf("%s: profile.%s: %w", path, name, err)
		}
		doc.Profiles[name] = p
	}
	doc.Upstream, doc.Profile = nil, nil
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		return fmt.Errorf("%s: %w: %s", path, ErrUnknownKey, strings.Join(keys, ", "))
	}
	return nil
}

// finalize applies the defaults that depend on other values or on array
// elements, which the TOML decoder cannot pre-populate.
func finalize(cfg *Config) {
	for _, p := range cfg.Profiles {
		if p.Filter == "" && p.Mode != "mock" {
			if u, ok := cfg.Upstreams[p.Upstream]; ok && u.Kind == "ad" {
				p.Filter = DefaultADFilter
			}
		}
		for name, g := range p.Groups {
			if g.ObjectClass == "" {
				g.ObjectClass = DefaultGroup().ObjectClass
				p.Groups[name] = g
			}
		}
	}
	for i := range cfg.Events.Webhooks {
		w, def := &cfg.Events.Webhooks[i], DefaultWebhook()
		setInt(&w.BatchSize, def.BatchSize)
		setDur(&w.BatchInterval, def.BatchInterval)
		setDur(&w.Timeout, def.Timeout)
		setInt(&w.Retry.Max, def.Retry.Max)
		setDur(&w.Retry.Backoff, def.Retry.Backoff)
		setDur(&w.Retry.MaxBackoff, def.Retry.MaxBackoff)
		setInt(&w.QueueSize, def.QueueSize)
		setStr(&w.OnOverflow, def.OnOverflow)
	}
	for i := range cfg.Notify.Channels {
		c, def := &cfg.Notify.Channels[i], DefaultChannel()
		if len(c.Events) == 0 {
			c.Events = def.Events
		}
		setStr(&c.MinLevel, def.MinLevel)
		setStr(&c.ParseMode, def.ParseMode)
		setStr(&c.APIBase, def.APIBase)
		setInt(&c.SMTPPort, def.SMTPPort)
		setStr(&c.TLSMode, def.TLSMode)
		setStr(&c.Method, def.Method)
		setDur(&c.Timeout, def.Timeout)
		setInt(&c.Retry.Max, def.Retry.Max)
		setDur(&c.Retry.Backoff, def.Retry.Backoff)
		setDur(&c.Retry.MaxBackoff, def.Retry.MaxBackoff)
	}
}

func setInt(dst *int, v int) {
	if *dst == 0 {
		*dst = v
	}
}

func setDur(dst *Duration, v Duration) {
	if *dst == 0 {
		*dst = v
	}
}

func setStr(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}
