package config

import "testing"

func TestValidate_RecordShadow(t *testing.T) {
	t.Parallel()
	second := `
[profile.two]
listen = [":1636"]
upstream = "ad-main"
virtual_base = "ou=two,dc=aldap"
bases = ["OU=People,DC=example,DC=org"]
[profile.two.attrs]
allow = ["mail"]
`
	for _, tc := range []struct {
		name, extra    string
		errPath, errIn string
	}{
		{name: "defaults", extra: "[profile.app.shadow]\nfilter = \"(mail=*)\"\n[profile.app.record]\nfile = \"/var/lib/aldap/app.jsonl\"\n"},
		{name: "enabled without file", extra: "[profile.app.record]\nenabled = true\n", errPath: "profile.app.record.file", errIn: "required"},
		{name: "size", extra: "[profile.app.record]\nfile = \"/x\"\nmax_size_mb = 0\n", errPath: "profile.app.record.max_size_mb", errIn: "at least 1"},
		{name: "files", extra: "[profile.app.record]\nfile = \"/x\"\nmax_files = 0\n", errPath: "profile.app.record.max_files", errIn: "at least 1"},
		{name: "same file twice", extra: "[profile.app.record]\nfile = \"/var/lib/aldap/r.jsonl\"\n" + second + "[profile.two.record]\nfile = \"/var/lib/aldap/./r.jsonl\"\n",
			errPath: "profile.two.record.file", errIn: "already written by profile.app.record.file"},
		{name: "events file", extra: "[events.file]\nenabled = true\npath = \"/var/log/aldap/ev.jsonl\"\n[profile.app.record]\nfile = \"/var/log/aldap/ev.jsonl\"\n",
			errPath: "profile.app.record.file", errIn: "events.file.path"},
		{name: "parallel", extra: "[profile.app.shadow]\nfilter = \"(mail=*)\"\nmax_parallel = 0\n", errPath: "profile.app.shadow.max_parallel", errIn: "at least 1"},
		{name: "timeout", extra: "[profile.app.shadow]\nfilter = \"(mail=*)\"\ntimeout = \"0s\"\n", errPath: "profile.app.shadow.timeout", errIn: "positive"},
		{name: "bad filter", extra: "[profile.app.shadow]\nfilter = \"(mail=\"\n", errPath: "profile.app.shadow.filter", errIn: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep := validate(mustLoad(t, minimalTOML+tc.extra))
			if tc.errPath == "" && !rep.OK() {
				t.Fatalf("errors: %v", rep.Errors)
			}
			if tc.errPath != "" && !hasIssue(rep.Errors, tc.errPath, tc.errIn) {
				t.Fatalf("want %s: %s, got %v", tc.errPath, tc.errIn, rep.Errors)
			}
		})
	}
	cfg := mustLoad(t, minimalTOML+"[profile.app.shadow]\nfilter = \"(mail=*)\"\n")
	cfg.Profiles["app"].Mode = "honeypot"
	if rep := validate(cfg); !hasIssue(rep.Warnings, "profile.app.shadow", "ignored for mode = honeypot") {
		t.Errorf("honeypot shadow: %v", rep.Warnings)
	}
	if !(Shadow{Bases: []string{"x"}}).Enabled() || (Shadow{}).Enabled() {
		t.Error("Shadow.Enabled")
	}
}
