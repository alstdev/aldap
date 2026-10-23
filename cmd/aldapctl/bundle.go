package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/alstdev/aldap/internal/config"
	"github.com/alstdev/aldap/internal/secret"
)

// bundleFormat names the layout of the support bundle.
const bundleFormat = "aldap-bundle.v1"

// maxBundleEvents bounds --events (GET /v1/events serves at most 10000).
const maxBundleEvents = 10000

// secretKeys are the TOML keys of inline secrets in the configuration
// (fields of type secret.Inline), collected from the config types so a new
// secret key is redacted without a list to keep in sync.
var secretKeys = sync.OnceValue(func() map[string]bool {
	keys := map[string]bool{}
	seen := map[reflect.Type]bool{}
	inline := reflect.TypeFor[secret.Inline]()
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map || t.Kind() == reflect.Array {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Type == inline {
				if name, _, _ := strings.Cut(f.Tag.Get("toml"), ","); name != "" && name != "-" {
					keys[name] = true
				}
				continue
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeFor[config.Config]())
	walk(reflect.TypeFor[config.Upstream]())
	walk(reflect.TypeFor[config.Profile]())
	return keys
})

// isSecretKey reports a key whose value must not leave the host: inline
// secrets, anything with "password" (hashes included) and *_secret /
// *_token; *_file and *_env name where a secret lives, not the secret.
func isSecretKey(k string) bool {
	l := strings.ToLower(k)
	if strings.HasSuffix(l, "_file") || strings.HasSuffix(l, "_env") {
		return false
	}
	return secretKeys()[l] || strings.Contains(l, "password") || strings.HasSuffix(l, "_secret") || strings.HasSuffix(l, "_token")
}

// maskAll replaces every string value of a table (webhook headers may carry
// credentials such as Authorization).
func maskAll(m map[string]any) {
	for k, v := range m {
		if s, ok := v.(string); ok && s != "" {
			m[k] = secret.Redacted
		}
	}
}

// redactValue masks secret keys in a decoded TOML/JSON tree. Values that
// are already empty or masked stay as they are.
func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if h, ok := val.(map[string]any); ok && strings.EqualFold(k, "headers") {
				maskAll(h)
				continue
			}
			if s, ok := val.(string); ok && isSecretKey(k) {
				if s != "" && s != secret.Redacted {
					x[k] = secret.Redacted
				}
				continue
			}
			x[k] = redactValue(val)
		}
	case []map[string]any:
		for _, m := range x {
			redactValue(m)
		}
	case []any:
		for i := range x {
			x[i] = redactValue(x[i])
		}
	}
	return v
}

// redactTOML re-encodes a configuration with every secret key masked; the
// daemon masks already, this is a second line of defense. A configuration
// that does not parse is not included at all.
func redactTOML(text string) ([]byte, error) {
	var tree map[string]any
	if _, err := toml.Decode(text, &tree); err != nil {
		return nil, fmt.Errorf("configuration left out: it does not parse: %w", err)
	}
	redactValue(tree)
	var b bytes.Buffer
	if err := toml.NewEncoder(&b).Encode(tree); err != nil {
		return nil, fmt.Errorf("configuration left out: %w", err)
	}
	return b.Bytes(), nil
}

// redactJSON masks secret keys in one JSON document.
func redactJSON(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(redactValue(v))
}

// bundleFile is one member of the archive.
type bundleFile struct {
	name string
	data []byte
}

type bundleManifest struct {
	Format    string            `json:"format"`
	Created   string            `json:"created"`
	Aldapctl  string            `json:"aldapctl"`
	Transport string            `json:"transport"`
	Files     []string          `json:"files"`
	Errors    map[string]string `json:"errors,omitempty"`
}

// collectBundle reads every part from the API; a failing part is noted in
// the manifest, an unreachable daemon fails the bundle.
func collectBundle(s *session, c *client, nEvents int) ([]bundleFile, bundleManifest, error) {
	ctx := s.ctx()
	man := bundleManifest{Format: bundleFormat, Created: s.app.now().UTC().Format(time.RFC3339), Aldapctl: versionLine(),
		Transport: yesNo(c.token == "", "ipc", "tcp"), Errors: map[string]string{}}
	var files []bundleFile
	add := func(name string, data []byte) { files = append(files, bundleFile{name, data}) }
	note := func(name string, err error) { man.Errors[name] = err.Error() }
	jsonFile := func(name string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			note(name, err)
			return
		}
		add(name, append(b, '\n'))
	}

	st, err := c.Status(ctx)
	if err != nil {
		return nil, man, err
	}
	jsonFile("status.json", st)
	jsonFile("version.json", map[string]string{
		"aldapctl": versionLine(), "aldapctl_go": runtime.Version(),
		"aldap": st.Version, "aldap_go": st.GoVersion,
	})
	health := map[string]any{}
	for _, p := range []string{"/healthz", "/readyz"} {
		code, body, err := c.Health(ctx, p)
		if err != nil {
			note("health.json", err)
			continue
		}
		var v any
		if json.Unmarshal(body, &v) != nil {
			v = strings.TrimSpace(string(body))
		}
		health[strings.TrimPrefix(p, "/")] = map[string]any{"status": code, "body": v}
	}
	jsonFile("health.json", health)
	if ups, err := c.Upstreams(ctx); err != nil {
		note("upstreams.json", err)
	} else {
		jsonFile("upstreams.json", ups)
	}
	if ps, err := c.Profiles(ctx); err != nil {
		note("profiles.json", err)
	} else {
		jsonFile("profiles.json", ps)
	}
	if text, err := c.ConfigGet(ctx); err != nil {
		note("config.toml", err)
	} else if red, err := redactTOML(text); err != nil {
		note("config.toml", err)
	} else {
		add("config.toml", red)
	}
	if ev, err := bundleEvents(s, c, st.EventsSeq, nEvents); err != nil {
		note("events.jsonl", err)
	} else {
		add("events.jsonl", ev)
	}
	if m, err := c.Metrics(ctx); err != nil {
		note("metrics.txt", err)
	} else {
		add("metrics.txt", m)
	}
	return files, man, nil
}

// bundleEvents returns the last n buffered events as JSON lines with
// secret keys masked.
func bundleEvents(s *session, c *client, seq uint64, n int) ([]byte, error) {
	var since uint64
	if seq > uint64(n) { //nolint:gosec // n is 1..10000
		since = seq - uint64(n) //nolint:gosec // see above
	}
	raw, err := c.EventsRaw(s.ctx(), since, n, nil)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, r := range raw {
		red, err := redactJSON(r)
		if err != nil {
			return nil, fmt.Errorf("decode event: %w", err)
		}
		b.Write(red)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// scrub removes the API token from a part, whatever put it there.
func scrub(data []byte, token string) []byte {
	if token == "" || !bytes.Contains(data, []byte(token)) {
		return data
	}
	return bytes.ReplaceAll(data, []byte(token), []byte(secret.Redacted))
}

// writeBundle packs the files and the manifest into a gzip tar archive.
func writeBundle(files []bundleFile, man bundleManifest, token string, now time.Time) ([]byte, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	for _, f := range files {
		man.Files = append(man.Files, f.name)
	}
	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return nil, err
	}
	all := append([]bundleFile{{"manifest.json", append(mb, '\n')}}, files...)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range all {
		data := scrub(f.data, token)
		hdr := &tar.Header{Name: "aldap-bundle/" + f.name, Mode: 0o600, Size: int64(len(data)), ModTime: now, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := errors.Join(tw.Close(), gz.Close()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func cmdBundle(s *session, _ []string) error {
	if s.o.out == "" {
		s.o.out = "aldap-bundle.tgz"
	}
	if s.o.nEvents < 1 || s.o.nEvents > maxBundleEvents {
		return usagef("bundle: --events must be 1–%d", maxBundleEvents)
	}
	c, err := s.client()
	if err != nil {
		return err
	}
	files, man, err := collectBundle(s, c, s.o.nEvents)
	if err != nil {
		return err
	}
	data, err := writeBundle(files, man, c.token, s.app.now())
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if err := s.writeOut(data); err != nil {
		return err
	}
	fmt.Fprintf(s.out(), "wrote %s (%d files", s.o.out, len(files)+1)
	if len(man.Errors) > 0 {
		fmt.Fprintf(s.out(), ", %d parts failed: see manifest.json", len(man.Errors))
	}
	fmt.Fprintln(s.out(), ")")
	return nil
}
