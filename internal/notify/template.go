package notify

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

//go:embed templates/*.tmpl
var builtinFS embed.FS

// Template names besides the event types.
const (
	tmplDefault = "default"
	tmplDigest  = "digest"
	tmplSubject = "subject"
)

// Data is what a template receives: the event record (SPEC §6) plus the
// host name and version. Digest is set for digest messages only; Event is
// then "digest" and Level the highest level of the digested events.
type Data struct {
	events.Record
	Hostname string
	Version  string
	Digest   *Digest
}

// Digest summarizes the events of one channel collected during an attack.
type Digest struct {
	From, To time.Time
	Total    int
	// Counts are the events per type, most frequent first.
	Counts []Count
	// IPs are the most frequent client addresses (at most 10).
	IPs []Count
	// Accounts is the number of distinct accounts (or account hashes).
	Accounts int
	// Attacks is the latest record (start or summary) per attack.
	Attacks []events.Record
}

// Count is one key of a digest with its number of events.
type Count struct {
	Key string
	N   int
}

// funcs are the template functions; config.NotifyTemplateFuncs names them
// for the validator (TestTemplateFuncsInSync).
var funcs = template.FuncMap{
	// get returns m[key], or "" when the key is missing.
	"get": func(m map[string]any, key string) any {
		if v, ok := m[key]; ok && v != nil {
			return v
		}
		return ""
	},
	// join renders a list as "a, b"; other values as fmt.Sprint.
	"join": join,
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	// md escapes a value for Telegram MarkdownV2.
	"md":    func(v any) string { return escapeMarkdownV2(fmt.Sprint(v)) },
	"html":  func(v any) string { return html.EscapeString(fmt.Sprint(v)) },
	"upper": func(v any) string { return strings.ToUpper(fmt.Sprint(v)) },
	"lower": func(v any) string { return strings.ToLower(fmt.Sprint(v)) },
	// default returns def when v is empty: {{get .Data "x" | default "-"}}.
	"default": func(def, v any) any {
		if v == nil || fmt.Sprint(v) == "" {
			return def
		}
		return v
	},
}

func join(v any, sep string) string {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return ""
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return fmt.Sprint(v)
	}
	parts := make([]string, rv.Len())
	for i := range parts {
		parts[i] = fmt.Sprint(rv.Index(i).Interface())
	}
	return strings.Join(parts, sep)
}

// markdownV2Special are the characters Telegram MarkdownV2 requires to be
// escaped outside entities (Bot API, "MarkdownV2 style").
const markdownV2Special = "_*[]()~`>#+-=|{}.!\\"

func escapeMarkdownV2(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if strings.ContainsRune(markdownV2Special, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// templates is the template set of one channel: the built-in files,
// overridden per name by the files of template_dir.
type templates struct {
	set map[string]*template.Template
	// custom marks names loaded from template_dir: their output is sent
	// as rendered (no automatic escaping).
	custom  map[string]bool
	subject *template.Template
	body    *template.Template
}

func parse(name, text string) (*template.Template, error) {
	return template.New(name).Funcs(funcs).Option("missingkey=zero").Parse(text)
}

// loadTemplates reads the built-in templates, then *.tmpl of dir (a file
// named <event>.tmpl, digest.tmpl, default.tmpl or subject.tmpl replaces
// the built-in one). subject and body are the inline subject_template and
// body_template of the channel (empty = built-in subject / record JSON).
func loadTemplates(dir, subject, body string) (*templates, error) {
	t := &templates{set: map[string]*template.Template{}, custom: map[string]bool{}}
	if err := t.load(builtinFS, "templates", false); err != nil {
		return nil, err
	}
	if dir != "" {
		fi, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("template_dir: %w", err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("template_dir: %s is not a directory", dir)
		}
		if err := t.load(os.DirFS(dir), ".", true); err != nil {
			return nil, err
		}
	}
	var err error
	t.subject = t.set[tmplSubject]
	if subject != "" {
		if t.subject, err = parse("subject_template", subject); err != nil {
			return nil, fmt.Errorf("subject_template: %w", err)
		}
	}
	if body != "" {
		if t.body, err = parse("body_template", body); err != nil {
			return nil, fmt.Errorf("body_template: %w", err)
		}
	}
	return t, nil
}

func (t *templates) load(fsys fs.FS, dir string, custom bool) error {
	names, err := fs.Glob(fsys, filepath.ToSlash(filepath.Join(dir, "*.tmpl")))
	if err != nil {
		return fmt.Errorf("templates: %w", err)
	}
	for _, p := range names {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("templates: %w", err)
		}
		name := strings.TrimSuffix(filepath.Base(p), ".tmpl")
		tpl, err := parse(name, string(raw))
		if err != nil {
			return fmt.Errorf("templates: %w", err)
		}
		t.set[name] = tpl
		t.custom[name] = custom
	}
	return nil
}

// render executes the template of d.Event (digest for digests, default
// when the event has none) and reports whether it came from template_dir.
func (t *templates) render(d Data) (string, bool, error) {
	name := d.Event
	if d.Digest != nil {
		name = tmplDigest
	}
	tpl, ok := t.set[name]
	if !ok {
		name = tmplDefault
		tpl = t.set[name]
	}
	out, err := execute(tpl, d)
	return strings.TrimSpace(out), t.custom[name], err
}

func execute(tpl *template.Template, d Data) (string, error) {
	if tpl == nil {
		return "", errors.New("template missing")
	}
	var b bytes.Buffer
	if err := tpl.Execute(&b, d); err != nil {
		return "", fmt.Errorf("template %s: %w", tpl.Name(), err)
	}
	return b.String(), nil
}

// renderSubject renders the email subject as one header-safe line.
func (t *templates) renderSubject(d Data) (string, error) {
	s, err := execute(t.subject, d)
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(s), " "), nil
}

// renderBody renders the webhook body: body_template (must yield JSON) or
// the record itself (aldap.event.v1) / the digest as JSON.
func (t *templates) renderBody(d Data) ([]byte, error) {
	if t.body != nil {
		s, err := execute(t.body, d)
		if err != nil {
			return nil, err
		}
		if !json.Valid([]byte(s)) {
			return nil, errors.New("body_template: output is not valid JSON")
		}
		return []byte(s), nil
	}
	if d.Digest == nil {
		return d.JSON(), nil
	}
	return json.Marshal(digestJSON(d))
}

// digestJSON is the default webhook body of a digest.
func digestJSON(d Data) map[string]any {
	counts := map[string]int{}
	for _, c := range d.Digest.Counts {
		counts[c.Key] = c.N
	}
	ips := map[string]int{}
	for _, c := range d.Digest.IPs {
		ips[c.Key] = c.N
	}
	attacks := make([]json.RawMessage, 0, len(d.Digest.Attacks))
	for _, r := range d.Digest.Attacks {
		attacks = append(attacks, r.JSON())
	}
	return map[string]any{
		"event": "digest", "level": d.Level, "host": d.Hostname, "version": d.Version,
		"from": d.Digest.From.UTC().Format(time.RFC3339Nano), "to": d.Digest.To.UTC().Format(time.RFC3339Nano),
		"total": d.Digest.Total, "counts": counts, "ips": ips, "accounts": d.Digest.Accounts, "attacks": attacks,
	}
}

// topCounts returns the counts of m, most frequent first (ties by key), at
// most limit entries (limit <= 0 = all).
func topCounts(m map[string]int, limit int) []Count {
	out := make([]Count, 0, len(m))
	for k, n := range m {
		out = append(out, Count{Key: k, N: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
