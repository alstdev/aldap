package config

import (
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/alstdev/aldap/internal/secret"
)

// EnvPrefix is the prefix of every configuration environment variable.
const EnvPrefix = "ALDAP_"

// envIgnoredPrefixes are ALDAP_* variables that are not configuration keys.
var envIgnoredPrefixes = []string{EnvConfigPath, "ALDAP_TEST_"}

// ErrAmbiguousEnv is returned when a variable matches more than one key.
var ErrAmbiguousEnv = errors.New("ambiguous environment variable")

// envLeaf is one settable key: its TOML path, with "*" standing for a table
// name, and the environment variable pattern (SPEC §3.3).
type envLeaf struct {
	segs []string
	env  string
	// secret marks an inline secret leaf (secret.Inline), whose _FILE and
	// _ENV siblings are the other sources of the same secret.
	secret bool
}

// ambiguousTable is the panic value namedEntry raises; setLeaf turns it into
// ErrAmbiguousTable.
type ambiguousTable struct {
	tableName string
	names     []string
}

// Wildcard reports whether the leaf lives under a named table.
func (l envLeaf) wildcard() bool { return strings.Contains(l.env, "*") }

var textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()

// envLeaves lists every environment-settable key of Config.
func envLeaves() []envLeaf {
	var out []envLeaf
	walkEnv(reflect.TypeFor[Config](), nil, &out)
	return out
}

func walkEnv(t reflect.Type, segs []string, out *[]envLeaf) {
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		key := f.Tag.Get("toml")
		if key == "-" {
			key = f.Tag.Get("env")
		}
		if key == "" || key == "-" {
			continue
		}
		path := append(append([]string(nil), segs...), key)
		ft := f.Type
		switch {
		case isNamedTable(ft):
			walkEnv(ft.Elem().Elem(), append(path, "*"), out)
		case envSettable(ft):
			*out = append(*out, envLeaf{segs: path, env: envName(path), secret: ft == inlineType})
		case ft.Kind() == reflect.Struct:
			walkEnv(ft, path, out)
		}
	}
}

// isNamedTable reports whether t is map[string]*T with T a struct: the
// [upstream.<name>] and [profile.<name>] shapes.
func isNamedTable(t reflect.Type) bool {
	return t.Kind() == reflect.Map && t.Key().Kind() == reflect.String &&
		t.Elem().Kind() == reflect.Pointer && t.Elem().Elem().Kind() == reflect.Struct
}

func envSettable(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		return envSettable(t.Elem())
	}
	if reflect.PointerTo(t).Implements(textUnmarshaler) {
		return true
	}
	switch t.Kind() {
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Float64:
		return true
	case reflect.Slice:
		return t.Elem().Kind() == reflect.String
	default:
		return false
	}
}

func envName(segs []string) string {
	return EnvPrefix + strings.ToUpper(strings.Join(segs, "_"))
}

// normalizeName maps a table name to its environment spelling: upper case, "-" becomes "_".
func normalizeName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// envToName maps an environment spelling to a new table name: lower case, "_" becomes "-".
func envToName(env string) string {
	return strings.ToLower(strings.ReplaceAll(env, "_", "-"))
}

// applyEnv overlays ALDAP_* variables on cfg. Every variable must map to
// exactly one key; unknown or ambiguous variables are errors.
func applyEnv(cfg *Config, environ []string) error {
	leaves := envLeaves()
	exact := make(map[string]envLeaf, len(leaves))
	var wild []envLeaf
	for _, l := range leaves {
		if l.wildcard() {
			wild = append(wild, l)
		} else {
			exact[l.env] = l
		}
	}
	sort.Strings(environ)
	if err := checkEnvSecretSources(environ); err != nil {
		return err
	}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, EnvPrefix) || envIgnored(name) {
			continue
		}
		if l, ok := exact[name]; ok {
			if err := setLeaf(cfg, l, "", value); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			continue
		}
		var match *envLeaf
		var tableName string
		for i := range wild {
			if n, ok := matchWild(wild[i].env, name); ok {
				if match != nil {
					return fmt.Errorf("%s: %w (%s or %s)", name, ErrAmbiguousEnv,
						strings.Join(match.segs, "."), strings.Join(wild[i].segs, "."))
				}
				match, tableName = &wild[i], n
			}
		}
		if match == nil {
			return fmt.Errorf("%s: %w", name, ErrUnknownKey)
		}
		if err := setLeaf(cfg, *match, tableName, value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func envIgnored(name string) bool {
	for _, p := range envIgnoredPrefixes {
		if name == p || (strings.HasSuffix(p, "_") && strings.HasPrefix(name, p)) {
			return true
		}
	}
	return false
}

// matchWild matches PREFIX_*_SUFFIX against name and returns the middle part.
func matchWild(pattern, name string) (string, bool) {
	prefix, suffix, _ := strings.Cut(pattern, "*")
	if len(name) <= len(prefix)+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return "", false
	}
	return name[len(prefix) : len(name)-len(suffix)], true
}

// setLeaf navigates cfg along the leaf path, creating a named table when
// needed, and sets the value. Setting any form of a secret clears the other
// forms, so the environment wins over the file (SPEC §3.1).
func setLeaf(cfg *Config, l envLeaf, tableName, value string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			at, ok := r.(ambiguousTable)
			if !ok {
				panic(r)
			}
			err = fmt.Errorf("%s: %w: %s", at.tableName, ErrAmbiguousTable, strings.Join(at.names, ", "))
		}
	}()
	v := reflect.ValueOf(cfg).Elem()
	var parent reflect.Value
	var lastKey string
	for _, seg := range l.segs {
		if seg == "*" {
			v = namedEntry(v, tableName)
			continue
		}
		parent, lastKey = v, seg
		f, ok := fieldByKey(v, seg)
		if !ok {
			return fmt.Errorf("internal: key %q not found", seg)
		}
		v = f
	}
	if err := setValue(v, value); err != nil {
		return err
	}
	clearSecretSiblings(parent, lastKey)
	return nil
}

// ErrAmbiguousTable reports two configured tables that share one
// environment spelling (my-app and my_app both become MY_APP).
var ErrAmbiguousTable = errors.New("several tables share this environment name")

// checkEnvSecretSources refuses two forms of one secret from the environment
// (X and X_FILE, X and X_ENV, X_FILE and X_ENV): SPEC §3.2 allows exactly one
// source; a silent last-one-wins would hide a misconfiguration.
func checkEnvSecretSources(environ []string) error {
	seen := map[string]string{}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, EnvPrefix) || envIgnored(name) {
			continue
		}
		base := name
		switch {
		case strings.HasSuffix(name, "_FILE"):
			base = strings.TrimSuffix(name, "_FILE")
		case strings.HasSuffix(name, "_ENV"):
			base = strings.TrimSuffix(name, "_ENV")
		}
		if !envIsSecretBase(base) {
			continue
		}
		if other, dup := seen[base]; dup {
			return fmt.Errorf("%s and %s: %w", other, name, secret.ErrMultipleSources)
		}
		seen[base] = name
	}
	return nil
}

// envIsSecretBase reports whether an environment name (without _FILE/_ENV)
// addresses an inline secret leaf.
func envIsSecretBase(name string) bool {
	for _, l := range envLeaves() {
		if !l.secret {
			continue
		}
		if l.wildcard() {
			if _, ok := matchWild(l.env, name); ok {
				return true
			}
		} else if l.env == name {
			return true
		}
	}
	return false
}

// namedEntry returns the entry of a named table, creating it with defaults;
// it panics (caught as an error by the caller) when several existing tables
// share the environment spelling.
func namedEntry(m reflect.Value, tableName string) reflect.Value {
	if m.IsNil() {
		m.Set(reflect.MakeMap(m.Type()))
	}
	var found []reflect.Value
	for _, k := range m.MapKeys() {
		if normalizeName(k.String()) == tableName {
			found = append(found, k)
		}
	}
	if len(found) > 1 {
		names := make([]string, len(found))
		for i, k := range found {
			names[i] = k.String()
		}
		sort.Strings(names)
		panic(ambiguousTable{tableName: tableName, names: names})
	}
	if len(found) == 1 {
		return m.MapIndex(found[0]).Elem()
	}
	var entry reflect.Value
	switch m.Type().Elem() {
	case reflect.TypeFor[*Upstream]():
		entry = reflect.ValueOf(DefaultUpstream())
	case reflect.TypeFor[*Profile]():
		entry = reflect.ValueOf(DefaultProfile())
	default:
		entry = reflect.New(m.Type().Elem().Elem())
	}
	m.SetMapIndex(reflect.ValueOf(envToName(tableName)), entry)
	return entry.Elem()
}

func fieldByKey(v reflect.Value, key string) (reflect.Value, bool) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		k := f.Tag.Get("toml")
		if k == "-" {
			k = f.Tag.Get("env")
		}
		if k == key {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func setValue(v reflect.Value, s string) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return setValue(v.Elem(), s)
	}
	if u, ok := v.Addr().Interface().(encoding.TextUnmarshaler); ok {
		return u.UnmarshalText([]byte(s))
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
	case reflect.Bool:
		b, err := strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("invalid boolean %q", s)
		}
		v.SetBool(b)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer %q", s)
		}
		v.SetInt(n)
	case reflect.Float64:
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return fmt.Errorf("invalid number %q", s)
		}
		v.SetFloat(f)
	case reflect.Slice:
		v.Set(reflect.ValueOf(splitList(s)))
	default:
		return fmt.Errorf("internal: unsupported kind %s", v.Kind())
	}
	return nil
}

// splitList splits a comma separated list, trimming blanks and dropping empties.
func splitList(s string) []string {
	out := []string{}
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var inlineType = reflect.TypeFor[secret.Inline]()

// clearSecretSiblings empties the other forms of a secret triple (x, x_file,
// x_env) in parent after key was set from the environment.
func clearSecretSiblings(parent reflect.Value, key string) {
	base := strings.TrimSuffix(strings.TrimSuffix(key, "_file"), "_env")
	inline, ok := fieldByKey(parent, base)
	if !ok || inline.Type() != inlineType {
		return
	}
	for _, k := range []string{base, base + "_file", base + "_env"} {
		if k == key {
			continue
		}
		if f, ok := fieldByKey(parent, k); ok {
			f.Set(reflect.Zero(f.Type()))
		}
	}
}
