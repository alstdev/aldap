package config

import (
	"fmt"
	"reflect"
	"strings"
)

// DocKey is one documented configuration key.
type DocKey struct {
	Path    string
	Type    string
	Default string
	Doc     string
}

// Keys lists every configuration key with its type, default and description,
// walking the Config model. Named tables appear as upstream.<name>.* and
// profile.<name>.*; arrays of tables as events.webhook[].* and so on.
func Keys() []DocKey {
	var out []DocKey
	def := Default()
	walkDoc(reflect.ValueOf(def).Elem(), "", &out)
	return out
}

func walkDoc(v reflect.Value, prefix string, out *[]DocKey) {
	t := v.Type()
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
		path := prefix + key
		fv := v.Field(i)
		doc := f.Tag.Get("doc")
		switch {
		case isNamedTable(f.Type):
			elem := namedDefault(f.Type.Elem())
			*out = append(*out, DocKey{Path: path + ".<name>", Type: "table", Doc: doc})
			walkDoc(elem, path+".<name>.", out)
		case f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Struct:
			elem := sliceDefault(f.Type.Elem())
			*out = append(*out, DocKey{Path: path + "[]", Type: "array of tables", Doc: doc})
			walkDoc(elem, path+"[].", out)
		case f.Type.Kind() == reflect.Map && f.Type.Elem().Kind() == reflect.Struct:
			elem := reflect.ValueOf(DefaultGroup())
			*out = append(*out, DocKey{Path: path + ".<name>", Type: "table", Doc: doc})
			walkDoc(elem, path+".<name>.", out)
		case f.Type.Kind() == reflect.Struct && !envSettable(f.Type):
			*out = append(*out, DocKey{Path: path, Type: "table", Doc: doc})
			walkDoc(fv, path+".", out)
		default:
			*out = append(*out, DocKey{Path: path, Type: typeName(f.Type), Default: defaultString(fv), Doc: doc})
		}
	}
}

func namedDefault(ptrType reflect.Type) reflect.Value {
	switch ptrType {
	case reflect.TypeFor[*Upstream]():
		return reflect.ValueOf(DefaultUpstream()).Elem()
	case reflect.TypeFor[*Profile]():
		return reflect.ValueOf(DefaultProfile()).Elem()
	}
	return reflect.New(ptrType.Elem()).Elem()
}

func sliceDefault(t reflect.Type) reflect.Value {
	switch t {
	case reflect.TypeFor[Webhook]():
		return reflect.ValueOf(DefaultWebhook())
	case reflect.TypeFor[Channel]():
		return reflect.ValueOf(DefaultChannel())
	}
	return reflect.New(t).Elem()
}

func typeName(t reflect.Type) string {
	if t.Kind() == reflect.Pointer {
		return typeName(t.Elem())
	}
	switch t {
	case reflect.TypeFor[Duration]():
		return "duration"
	case reflect.TypeFor[ByteSize]():
		return "size"
	case reflect.TypeFor[Percent]():
		return "percent"
	}
	switch t.Kind() {
	case reflect.String:
		if t.PkgPath() != "" {
			return "secret"
		}
		return "string"
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int64:
		return "int"
	case reflect.Float64:
		return "float"
	case reflect.Slice:
		return "[]" + typeName(t.Elem())
	case reflect.Map:
		return "table of " + typeName(t.Elem())
	default:
		return t.Kind().String()
	}
}

func defaultString(v reflect.Value) string {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "inherit"
		}
		v = v.Elem()
	}
	if s, ok := v.Interface().(fmt.Stringer); ok {
		if v.Kind() == reflect.String && v.Type().PkgPath() != "" {
			return "" // secret.Inline: never render
		}
		return s.String()
	}
	switch v.Kind() {
	case reflect.String:
		if v.Len() == 0 {
			return ""
		}
		return fmt.Sprintf("%q", v.String())
	case reflect.Slice:
		if v.Len() == 0 {
			return "[]"
		}
		parts := make([]string, v.Len())
		for i := range v.Len() {
			parts[i] = fmt.Sprintf("%q", v.Index(i).String())
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case reflect.Map:
		return "{}"
	case reflect.Bool, reflect.Int, reflect.Int64, reflect.Float64:
		return fmt.Sprint(v.Interface())
	default:
		return ""
	}
}

// RenderDocs renders docs/config.md from Keys().
func RenderDocs() string {
	var b strings.Builder
	b.WriteString("# Configuration keys\n\n")
	b.WriteString("Generated from the `internal/config` model; `TestConfigDocsInSync` fails when this file is stale.\n")
	b.WriteString("Regenerate with `go test ./internal/config -run TestConfigDocsInSync -update`.\n")
	b.WriteString("See `aldap.toml.example` for a complete annotated example and SPEC.md §3 for semantics.\n\n")
	b.WriteString("Precedence (highest first): `ALDAP_*` environment variables, secret files, `aldap.toml` with includes, built-in defaults.\n")
	b.WriteString("Environment variable names are `ALDAP_` + the key path in upper case with `.` and `-` replaced by `_`; ")
	b.WriteString("lists are comma separated. Tables with free-form keys (`attrs.map`, `groups`, `headers`) and arrays of tables cannot be set from the environment.\n\n")
	b.WriteString("| Key | Type | Default | Description |\n|---|---|---|---|\n")
	for _, k := range Keys() {
		def := k.Default
		if def != "" {
			def = "`" + strings.ReplaceAll(def, "|", "\\|") + "`"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", k.Path, k.Type, def, strings.ReplaceAll(k.Doc, "|", "\\|"))
	}
	return b.String()
}
