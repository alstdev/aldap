package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/alstdev/aldap/internal/secret"
)

const headerToken = "Bearer h3ader-T0ken-That-Must-Not-Leak"

func webhookTOML(extra string) string {
	return minimalTOML + `
[[events.webhook]]
name = "siem"
url = "https://siem.example.org/in"
` + extra + `
[[notify.channel]]
name = "hook"
type = "webhook"
events = ["attack_start"]
url = "https://hook.example.org/in"
` + extra
}

func writeHeadersFile(t *testing.T, body string, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "headers.toml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHeaders_Validation(t *testing.T) {
	t.Parallel()
	good := writeHeadersFile(t, "Authorization = \""+headerToken+"\"\n", 0o600)
	loose := writeHeadersFile(t, "Authorization = \""+headerToken+"\"\n", 0o644)
	dup := writeHeadersFile(t, "x-source = \"file\"\n", 0o600)
	notTable := writeHeadersFile(t, "Authorization = 1\n", 0o600)
	badName := writeHeadersFile(t, "\"Bad Name\" = \"x\"\n", 0o600)
	for _, tc := range []struct {
		name, extra    string
		strict         bool
		errPath, errIn string
		warnPath, warn string
	}{
		{name: "plain header", extra: "headers = { X-Source = \"aldap\" }\n"},
		{name: "inline authorization warned", extra: "headers = { Authorization = \"" + headerToken + "\" }\n",
			warnPath: "events.webhook[0].headers.Authorization", warn: "move it to events.webhook[0].headers_file"},
		{name: "inline cookie warned any case", extra: "headers = { cookie = \"s=1\" }\n",
			warnPath: "notify.channel[0].headers.cookie", warn: "credential given inline"},
		{name: "inline api key warned", extra: "headers = { X-Api-Key = \"k\" }\n",
			warnPath: "notify.channel[0].headers.X-Api-Key", warn: "headers_file"},
		{name: "masked placeholder refused", extra: "headers = { Authorization = \"***\" }\n",
			errPath: "events.webhook[0].headers.Authorization", errIn: "masked placeholder"},
		{name: "control character refused", extra: "headers = { X-Source = \"a\\r\\nX-Evil: 1\" }\n",
			errPath: "notify.channel[0].headers", errIn: "control character"},
		{name: "bad name refused", extra: "headers = { \"X Source\" = \"a\" }\n",
			errPath: "events.webhook[0].headers", errIn: "not a token"},
		{name: "file", extra: "headers_file = \"" + good + "\"\n", strict: true},
		{name: "file with plain headers", extra: "headers = { X-Source = \"aldap\" }\nheaders_file = \"" + good + "\"\n", strict: true},
		{name: "file permissions warned", extra: "headers_file = \"" + loose + "\"\n", strict: true,
			warnPath: "events.webhook[0].headers_file", warn: "more permissive"},
		{name: "missing file strict", extra: "headers_file = \"/nonexistent/h.toml\"\n", strict: true,
			errPath: "events.webhook[0].headers_file", errIn: "headers_file"},
		{name: "missing file offline", extra: "headers_file = \"/nonexistent/h.toml\"\n",
			warnPath: "events.webhook[0].headers_file", warn: "verified again at start"},
		{name: "duplicate name", extra: "headers = { X-Source = \"aldap\" }\nheaders_file = \"" + dup + "\"\n",
			errPath: "notify.channel[0].headers_file", errIn: "both inline and in headers_file"},
		{name: "not a table of strings", extra: "headers_file = \"" + notTable + "\"\n", strict: true,
			errPath: "events.webhook[0].headers_file", errIn: "not a TOML table of strings"},
		{name: "bad name in file", extra: "headers_file = \"" + badName + "\"\n", strict: true,
			errPath: "events.webhook[0].headers_file", errIn: "not a token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := mustLoad(t, webhookTOML(tc.extra))
			v := Validator{StrictFiles: tc.strict, Secrets: secret.Resolver{LookupEnv: func(string) (string, bool) { return "x", true }}}
			rep := v.Validate(cfg)
			if tc.errPath == "" && !rep.OK() {
				t.Fatalf("unexpected errors: %v", rep.Errors)
			}
			if tc.errPath != "" && !hasIssue(rep.Errors, tc.errPath, tc.errIn) {
				t.Fatalf("want error %s: %s, got %v", tc.errPath, tc.errIn, rep.Errors)
			}
			if tc.warnPath != "" && !hasIssue(rep.Warnings, tc.warnPath, tc.warn) {
				t.Fatalf("want warning %s: %s, got %v", tc.warnPath, tc.warn, rep.Warnings)
			}
			if strings.Contains(fmt.Sprintf("%v %v", rep.Errors, rep.Warnings), "h3ader-T0ken") {
				t.Fatal("the report leaks a header value")
			}
		})
	}
}

func TestLoadHeaders(t *testing.T) {
	t.Parallel()
	file := writeHeadersFile(t, "Authorization = \""+headerToken+"\"\n", 0o600)
	got, warns, err := LoadHeaders(secret.Default, Headers{"X-Source": "aldap"}, file)
	if err != nil || len(warns) != 0 {
		t.Fatalf("LoadHeaders: %v %v", warns, err)
	}
	if got["X-Source"] != "aldap" || got["Authorization"] != headerToken || len(got) != 2 {
		t.Fatalf("headers: %d", len(got))
	}
	got, _, err = LoadHeaders(secret.Default, Headers{"x": "1"}, "")
	if err != nil || got["x"] != "1" {
		t.Fatalf("inline only: %v", err)
	}
	if _, _, err := LoadHeaders(secret.Default, Headers{"authorization": "a"}, file); !errors.Is(err, ErrHeaderDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	broken := writeHeadersFile(t, "Authorization = \""+headerToken+"\n", 0o600)
	if _, _, err := LoadHeaders(secret.Default, nil, broken); err == nil || strings.Contains(err.Error(), "h3ader") {
		t.Fatalf("a parse error must not quote the value: %v", err)
	}
}

// TestNoSecretsInOutput_Headers: header values never leave through fmt,
// JSON, TOML (GET /v1/config) or slog-style rendering of the model.
func TestNoSecretsInOutput_Headers(t *testing.T) {
	t.Parallel()
	cfg := mustLoad(t, webhookTOML("headers = { Authorization = \""+headerToken+"\", X-Source = \"aldap\" }\n"))
	if cfg.Events.Webhooks[0].Headers["Authorization"].Reveal() != headerToken {
		t.Fatal("Reveal() must still return the value")
	}
	var tb bytes.Buffer
	if err := toml.NewEncoder(&tb).Encode(cfg); err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rep := validate(cfg)
	outputs := map[string]string{
		"plus_v": fmt.Sprintf("%+v", cfg.Events), "sharp_v": fmt.Sprintf("%#v", cfg.Notify),
		"toml": tb.String(), "json": string(js), "report": fmt.Sprintf("%+v", rep),
	}
	for name, out := range outputs {
		if strings.Contains(out, "h3ader-T0ken") {
			t.Errorf("%s leaks a header value", name)
		}
	}
	if !strings.Contains(tb.String(), "Authorization = \"***\"") || !strings.Contains(tb.String(), "X-Source = \"***\"") {
		t.Errorf("header names must stay with masked values:\n%s", tb.String())
	}
	// The rendering does not load back as a valid configuration: applying
	// it would store "***" as a header value.
	back := mustLoad(t, tb.String())
	if r := validate(back); !hasIssue(r.Errors, "events.webhook[0].headers.Authorization", "masked placeholder") {
		t.Errorf("a rendered configuration must be refused: %v", r.Errors)
	}
}
