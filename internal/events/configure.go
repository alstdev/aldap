package events

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/secret"
)

// ConfigureOptions supply what [events] needs from the process.
type ConfigureOptions struct {
	// Stdout receives the stdout sink (default os.Stdout).
	Stdout io.Writer
	// Secrets resolves webhook HMAC keys.
	Secrets secret.Resolver
	// UserAgent is sent by webhook sinks.
	UserAgent string
	// Logger receives warnings about secret files (nil: discarded).
	Logger *slog.Logger
}

// BusFromConfig builds a bus with the filters and hashing of cfg; the
// sinks are attached by Configure. The salt comes from salt_file or, when
// unset, is random for the process (hashes then differ between restarts).
func BusFromConfig(cfg config.Events, o Options) (*Bus, error) {
	o.BufferSize = cfg.BufferSize
	o.Include, o.Exclude = cfg.Include, cfg.Exclude
	o.HashAccounts = cfg.HashAccounts
	if cfg.HashAccounts {
		if cfg.SaltFile != "" {
			salt, err := os.ReadFile(cfg.SaltFile)
			if err != nil {
				return nil, fmt.Errorf("events.salt_file: %w", err)
			}
			o.Salt = salt
		} else {
			o.Salt = make([]byte, 32)
			if _, err := rand.Read(o.Salt); err != nil {
				return nil, fmt.Errorf("events: salt: %w", err)
			}
			if o.Logger != nil {
				o.Logger.Warn("events.hash_accounts without salt_file: account hashes change at every restart")
			}
		}
	}
	return NewBus(o), nil
}

// Configure builds the sinks of cfg and installs them on the bus,
// replacing the previous ones (reload).
func (b *Bus) Configure(cfg config.Events, o ConfigureOptions) error {
	specs, err := buildSinks(cfg, o)
	if err != nil {
		return err
	}
	b.SetSinks(specs)
	return nil
}

func buildSinks(cfg config.Events, o ConfigureOptions) ([]SinkSpec, error) {
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	var specs []SinkSpec
	if cfg.Stdout.Enabled {
		specs = append(specs, SinkSpec{Sink: &WriterSink{W: o.Stdout}, Options: SinkOptions{Name: "stdout", QueueSize: 10000, BatchSize: 256}})
	}
	if cfg.File.Enabled {
		fs, err := NewFileSink(cfg.File.Path, cfg.File.MaxSizeMB, cfg.File.MaxFiles, cfg.File.Compress)
		if err != nil {
			return nil, err
		}
		specs = append(specs, SinkSpec{Sink: fs, Options: SinkOptions{Name: "file", QueueSize: 10000, BatchSize: 256}})
	}
	if cfg.Syslog.Enabled {
		ss, err := NewSyslogSink(cfg.Syslog.Network, cfg.Syslog.Address, cfg.Syslog.Facility)
		if err != nil {
			return nil, err
		}
		specs = append(specs, SinkSpec{Sink: ss, Options: SinkOptions{Name: "syslog", QueueSize: 10000, BatchSize: 64}})
	}
	for i, w := range cfg.Webhooks {
		name := w.Name
		if name == "" {
			name = fmt.Sprintf("webhook[%d]", i)
		}
		var key []byte
		if src := w.HMACSecretSource(); src.IsSet() {
			v, _, err := o.Secrets.Resolve(src)
			if err != nil {
				return nil, fmt.Errorf("events.webhook %s: hmac_secret: %w", name, err)
			}
			key = v.Bytes()
		}
		headers, warns, err := config.LoadHeaders(o.Secrets, w.Headers, w.HeadersFile)
		for _, wn := range warns {
			if o.Logger != nil {
				o.Logger.Warn("events.webhook: headers_file", "sink", name, "warning", wn.Msg)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("events.webhook %s: %w", name, err)
		}
		ws, err := NewWebhookSink(WebhookOptions{URL: w.URL, Headers: headers, Key: key, Timeout: w.Timeout.D(),
			Retries: w.Retry.Max, Backoff: w.Retry.Backoff.D(), MaxBackoff: w.Retry.MaxBackoff.D(), TLSCAFile: w.TLSCAFile, UserAgent: o.UserAgent})
		if err != nil {
			return nil, fmt.Errorf("events.webhook %s: %w", name, err)
		}
		batch := w.BatchSize
		if batch <= 0 {
			batch = 100
		}
		interval := w.BatchInterval.D()
		if interval <= 0 {
			interval = 2 * time.Second
		}
		specs = append(specs, SinkSpec{Sink: ws, Options: SinkOptions{Name: name, Kinds: w.Events, QueueSize: w.QueueSize,
			OnOverflow: w.OnOverflow, BatchSize: batch, BatchInterval: interval}})
	}
	return specs, nil
}
