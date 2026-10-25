// Package schematest validates event records against docs/events.schema.json
// in tests (TESTING.md 34). It implements the subset of JSON Schema
// draft 2020-12 the file uses: type, const, enum, pattern, format
// date-time, minimum, required, properties, additionalProperties, items,
// maxItems, allOf and if/then.
package schematest

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

// Schema is a loaded JSON Schema document.
type Schema struct {
	root map[string]any
}

var (
	loadOnce sync.Once
	loaded   *Schema
	loadErr  error
)

// Path returns the location of docs/events.schema.json relative to this file.
func Path() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "events.schema.json")
}

// Load reads the schema once per test binary.
func Load() (*Schema, error) {
	loadOnce.Do(func() {
		raw, err := os.ReadFile(Path())
		if err != nil {
			loadErr = err
			return
		}
		var root map[string]any
		if err := json.Unmarshal(raw, &root); err != nil {
			loadErr = fmt.Errorf("decode schema: %w", err)
			return
		}
		loaded = &Schema{root: root}
	})
	return loaded, loadErr
}

// EventKinds returns the event enum of the schema.
func (s *Schema) EventKinds() []string {
	props, _ := s.root["properties"].(map[string]any)
	ev, _ := props["event"].(map[string]any)
	enum, _ := ev["enum"].([]any)
	out := make([]string, 0, len(enum))
	for _, e := range enum {
		out = append(out, e.(string))
	}
	return out
}

// Validate checks one JSON document (decoded with encoding/json into any).
func (s *Schema) Validate(doc any) []error {
	return validate(s.root, doc, "$")
}

// ValidateRecord checks a record after a JSON round trip.
func (s *Schema) ValidateRecord(r events.Record) []error {
	var doc any
	if err := json.Unmarshal(r.JSON(), &doc); err != nil {
		return []error{fmt.Errorf("record is not JSON: %w", err)}
	}
	return s.Validate(doc)
}

// Check fails t for every record of rs that violates the schema.
func Check(tb testing.TB, rs ...events.Record) {
	tb.Helper()
	s, err := Load()
	if err != nil {
		tb.Fatalf("schema: %v", err)
	}
	for _, r := range rs {
		for _, e := range s.ValidateRecord(r) {
			tb.Errorf("event %s (seq %d) violates docs/events.schema.json: %v\n%s", r.Event, r.Seq, e, r.JSON())
		}
	}
}

// CheckEvents wraps raw events with a private bus and checks them.
func CheckEvents(tb testing.TB, es ...events.Event) {
	tb.Helper()
	bus := events.NewBus(events.Options{Host: "test"})
	rs := make([]events.Record, 0, len(es))
	for _, e := range es {
		rs = append(rs, bus.Wrap(e))
	}
	Check(tb, rs...)
}

func validate(schema map[string]any, v any, path string) []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
	}
	if t, ok := schema["type"]; ok && !typeMatches(t, v) {
		fail("type %v, got %s", t, typeOf(v))
		return errs
	}
	if c, ok := schema["const"]; ok && !equal(c, v) {
		fail("must be %v, got %v", c, v)
	}
	if e, ok := schema["enum"].([]any); ok {
		found := false
		for _, c := range e {
			if equal(c, v) {
				found = true
				break
			}
		}
		if !found {
			fail("%v not in enum %v", v, e)
		}
	}
	if p, ok := schema["pattern"].(string); ok {
		if str, isStr := v.(string); isStr && !regexp.MustCompile(p).MatchString(str) {
			fail("%q does not match %s", str, p)
		}
	}
	if f, ok := schema["format"].(string); ok && f == "date-time" {
		if str, isStr := v.(string); isStr {
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				fail("%q is not a date-time", str)
			}
		}
	}
	if m, ok := schema["minimum"].(float64); ok {
		if n, isNum := v.(float64); isNum && n < m {
			fail("%v below minimum %v", n, m)
		}
	}
	if obj, isObj := v.(map[string]any); isObj {
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				if _, present := obj[r.(string)]; !present {
					fail("missing required %q", r)
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		for k, pv := range obj {
			ps, known := props[k].(map[string]any)
			if known {
				errs = append(errs, validate(ps, pv, path+"."+k)...)
				continue
			}
			if ap, ok := schema["additionalProperties"].(bool); ok && !ap {
				fail("additional property %q", k)
			}
		}
	}
	if arr, isArr := v.([]any); isArr {
		if m, ok := schema["maxItems"].(float64); ok && float64(len(arr)) > m {
			fail("%d items, at most %v", len(arr), m)
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, it := range arr {
				errs = append(errs, validate(items, it, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	if all, ok := schema["allOf"].([]any); ok {
		for _, sub := range all {
			errs = append(errs, validate(sub.(map[string]any), v, path)...)
		}
	}
	if cond, ok := schema["if"].(map[string]any); ok {
		if len(validate(cond, v, path)) == 0 {
			if then, ok := schema["then"].(map[string]any); ok {
				errs = append(errs, validate(then, v, path)...)
			}
		} else if els, ok := schema["else"].(map[string]any); ok {
			errs = append(errs, validate(els, v, path)...)
		}
	}
	return errs
}

func typeMatches(t any, v any) bool {
	switch tt := t.(type) {
	case string:
		return isType(tt, v)
	case []any:
		for _, one := range tt {
			if isType(one.(string), v) {
				return true
			}
		}
	}
	return false
}

func isType(t string, v any) bool {
	switch t {
	case "null":
		return v == nil
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		n, ok := v.(float64)
		return ok && n == math.Trunc(n)
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	}
	return false
}

func typeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", v), "*")
}

func equal(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
