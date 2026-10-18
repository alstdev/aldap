package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const raw = "s3cr3t-value"

func TestInline_Redacts(t *testing.T) {
	t.Parallel()
	s := Inline(raw)
	for name, got := range map[string]string{
		"String":  s.String(),
		"v":       fmt.Sprintf("%v", s),
		"plus_v":  fmt.Sprintf("%+v", s),
		"sharp_v": fmt.Sprintf("%#v", s),
		"s":       fmt.Sprintf("[%s]", s),
	} {
		if strings.Contains(got, raw) {
			t.Errorf("%s leaked the secret: %q", name, got)
		}
	}
	b, err := json.Marshal(struct{ P Inline }{s})
	if err != nil || strings.Contains(string(b), raw) || !strings.Contains(string(b), Redacted) {
		t.Errorf("json = %s, err = %v", b, err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "pw", s)
	if strings.Contains(buf.String(), raw) {
		t.Errorf("slog leaked the secret: %s", buf.String())
	}
	if s.Reveal() != raw {
		t.Errorf("Reveal() = %q", s.Reveal())
	}
}

func TestValue_Redacts(t *testing.T) {
	t.Parallel()
	v, _, err := Resolver{}.Resolve(Source{Inline: raw})
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"String":  v.String(),
		"plus_v":  fmt.Sprintf("%+v", v),
		"sharp_v": fmt.Sprintf("%#v", v),
		"ptr":     fmt.Sprintf("%v", &v),
	} {
		if strings.Contains(got, raw) {
			t.Errorf("%s leaked the secret: %q", name, got)
		}
	}
	b, err := json.Marshal(v)
	if err != nil || strings.Contains(string(b), raw) {
		t.Errorf("json = %s, err = %v", b, err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "pw", v)
	if strings.Contains(buf.String(), raw) {
		t.Errorf("slog leaked the secret: %s", buf.String())
	}
	if v.Reveal() != raw || string(v.Bytes()) != raw || v.IsZero() {
		t.Errorf("Reveal/Bytes/IsZero wrong: %q %q %v", v.Reveal(), v.Bytes(), v.IsZero())
	}
	v.Wipe()
	if !v.IsZero() {
		t.Error("Wipe() left data")
	}
}

func TestSource_Check(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		src     Source
		kind    string
		wantErr error
	}{
		{"unset", Source{}, "", nil},
		{"inline", Source{Inline: "x"}, "inline", nil},
		{"file", Source{File: "/f"}, "file", nil},
		{"env", Source{Env: "V"}, "env", nil},
		{"inline_and_file", Source{Inline: "x", File: "/f"}, "inline", ErrMultipleSources},
		{"file_and_env", Source{File: "/f", Env: "V"}, "file", ErrMultipleSources},
		{"all_three", Source{Inline: "x", File: "/f", Env: "V"}, "inline", ErrMultipleSources},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.src.Kind(); got != tt.kind {
				t.Errorf("Kind() = %q, want %q", got, tt.kind)
			}
			if err := tt.src.Check(); !errors.Is(err, tt.wantErr) {
				t.Errorf("Check() = %v, want %v", err, tt.wantErr)
			}
			if tt.src.IsSet() != (tt.kind != "") {
				t.Errorf("IsSet() = %v", tt.src.IsSet())
			}
		})
	}
}

func writeFile(t *testing.T, name, content string, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolver_Resolve(t *testing.T) {
	t.Parallel()
	good := writeFile(t, "good", raw+"\n", 0o600)
	crlf := writeFile(t, "crlf", raw+"\r\n", 0o600)
	loose := writeFile(t, "loose", raw, 0o644)
	empty := writeFile(t, "empty", "\n", 0o600)
	env := map[string]string{"ALDAP_TEST_PW": raw, "ALDAP_TEST_EMPTY": ""}
	r := Resolver{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}

	tests := []struct {
		name      string
		src       Source
		want      string
		wantWarn  bool
		wantErr   error
		wantIsErr bool
	}{
		{name: "unset", src: Source{}, want: ""},
		{name: "inline", src: Source{Inline: raw}, want: raw},
		{name: "file_trims_newline", src: Source{File: good}, want: raw},
		{name: "file_trims_crlf", src: Source{File: crlf}, want: raw},
		{name: "file_loose_mode_warns", src: Source{File: loose}, want: raw, wantWarn: true},
		{name: "file_empty", src: Source{File: empty}, wantErr: ErrEmpty},
		{name: "file_missing", src: Source{File: filepath.Join(t.TempDir(), "nope")}, wantErr: fs.ErrNotExist},
		{name: "env", src: Source{Env: "ALDAP_TEST_PW"}, want: raw},
		{name: "env_unset", src: Source{Env: "ALDAP_TEST_NOPE"}, wantErr: ErrEnvNotSet},
		{name: "env_empty", src: Source{Env: "ALDAP_TEST_EMPTY"}, wantErr: ErrEmpty},
		{name: "two_sources", src: Source{Inline: raw, Env: "ALDAP_TEST_PW"}, wantErr: ErrMultipleSources},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, warns, err := r.Resolve(tt.src)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), raw) {
				t.Errorf("error leaked the secret: %v", err)
			}
			if got := v.Reveal(); got != tt.want {
				t.Errorf("Reveal() = %q, want %q", got, tt.want)
			}
			if (len(warns) > 0) != tt.wantWarn {
				t.Errorf("warnings = %v, wantWarn %v", warns, tt.wantWarn)
			}
		})
	}
}

func TestResolver_Probe(t *testing.T) {
	t.Parallel()
	good := writeFile(t, "good", raw, 0o600)
	loose := writeFile(t, "loose", raw, 0o666)
	r := Resolver{}
	if warns, err := r.Probe(Source{File: good}); err != nil || len(warns) != 0 {
		t.Errorf("good: warns=%v err=%v", warns, err)
	}
	if warns, err := r.Probe(Source{File: loose}); err != nil || len(warns) != 1 {
		t.Errorf("loose: warns=%v err=%v", warns, err)
	}
	if _, err := r.Probe(Source{File: "/nonexistent/aldap-secret"}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: err=%v", err)
	}
	if warns, err := r.Probe(Source{Inline: raw}); err != nil || warns != nil {
		t.Errorf("inline: warns=%v err=%v", warns, err)
	}
	if _, err := r.Probe(Source{File: good, Env: "X"}); !errors.Is(err, ErrMultipleSources) {
		t.Errorf("multiple: err=%v", err)
	}
}

func TestResolver_DefaultsUseOS(t *testing.T) {
	t.Setenv("ALDAP_TEST_DEFAULT_PW", raw)
	v, _, err := Default.Resolve(Source{Env: "ALDAP_TEST_DEFAULT_PW"})
	if err != nil || v.Reveal() != raw {
		t.Fatalf("Default.Resolve: %q %v", v.Reveal(), err)
	}
}
