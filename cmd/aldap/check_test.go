package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validTOML = `
[upstream.ad]
servers = ["ldaps://dc.example.org:636"]
bind_dn = "CN=svc,DC=example,DC=org"
bind_password_env = "ALDAP_TEST_PW"
[profile.app]
listen = [":1636"]
upstream = "ad"
virtual_base = "ou=app,dc=aldap"
bases = ["OU=People,DC=example,DC=org"]
[profile.app.attrs]
allow = ["cn"]
`

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aldap.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunCheck_Example(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"check", "--config", "../../aldap.toml.example"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK: ") || strings.Contains(stdout.String(), "ERROR") {
		t.Errorf("stdout = %s", stdout.String())
	}
}

func TestRunCheck_Cases(t *testing.T) {
	valid := writeTemp(t, validTOML)
	invalid := writeTemp(t, "[server]\nlog_level = \"loud\"\n[profile.p]\nlisten = [\":1\"]\n")
	unknown := writeTemp(t, "[server]\nlog_levl = \"info\"\n")
	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{name: "valid", args: []string{"--config", valid}, wantCode: 0, wantOut: "OK: " + valid + ", 0 errors"},
		{name: "valid_quick", args: []string{"--config", valid, "--quick"}, wantCode: 0, wantOut: "OK:"},
		{name: "invalid", args: []string{"--config", invalid}, wantCode: 1, wantOut: "ERROR server.log_level: \"loud\" is not one of"},
		{name: "invalid_lists_all", args: []string{"--config", invalid}, wantCode: 1, wantOut: "ERROR profile.p.virtual_base: required"},
		{name: "unknown_key", args: []string{"--config", unknown}, wantCode: 1, wantOut: "ERROR config: " + unknown + ": unknown configuration key: server.log_levl"},
		{name: "missing_explicit", args: []string{"--config", filepath.Join(t.TempDir(), "nope.toml")}, wantCode: 1, wantOut: "ERROR config:"},
		{name: "env_path", env: map[string]string{"ALDAP_CONFIG": valid}, wantCode: 0, wantOut: "OK: " + valid},
		{name: "env_override_breaks", args: []string{"--config", valid}, env: map[string]string{"ALDAP_SERVER_LOG_LEVEL": "loud"}, wantCode: 1, wantOut: "server.log_level"},
		{name: "online_unsupported", args: []string{"--config", valid, "--online"}, wantCode: 2, wantErr: "not implemented"},
		{name: "extra_arg", args: []string{"--config", valid, "extra"}, wantCode: 2, wantErr: "unexpected argument"},
		{name: "bad_flag", args: []string{"--nope"}, wantCode: 2, wantErr: "flag provided but not defined"},
		{name: "help", args: []string{"-h"}, wantCode: 2, wantErr: "Usage: aldap check"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ALDAP_CONFIG", "")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			var stdout, stderr bytes.Buffer
			code := run(append([]string{"check"}, tt.args...), &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantOut)
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestRunCheck_JSON(t *testing.T) {
	p := writeTemp(t, "[upstream.u]\nservers = [\"ldap://dc\"]\n[profile.p]\nlisten = [\":1\"]\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"check", "--json", "--config", p}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, stderr %s", code, stderr.String())
	}
	var res checkResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout.String())
	}
	if res.OK || res.Config != p || len(res.Errors) == 0 || len(res.Warnings) == 0 {
		t.Errorf("result = %+v", res)
	}
	found := false
	for _, w := range res.Warnings {
		if w.Path == "upstream.u.starttls" {
			found = true
		}
	}
	if !found {
		t.Errorf("want starttls warning in %+v", res.Warnings)
	}
}

func TestRunCheck_NoSecretsInOutput(t *testing.T) {
	const pw = "Inline-Pa55word-Must-Not-Print"
	p := writeTemp(t, "[upstream.u]\nservers = [\"ldaps://dc\"]\nbind_dn = \"cn=a\"\nbind_password = \""+pw+"\"\n")
	for _, args := range [][]string{{"check", "--config", p}, {"check", "--json", "--config", p}} {
		var stdout, stderr bytes.Buffer
		run(args, &stdout, &stderr)
		if strings.Contains(stdout.String()+stderr.String(), pw) {
			t.Errorf("%v leaks the inline secret", args)
		}
		if !strings.Contains(stdout.String(), "inline secret") {
			t.Errorf("%v: want inline warning, got %s", args, stdout.String())
		}
	}
}
