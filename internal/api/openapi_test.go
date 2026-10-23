package api

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	reOpenAPIPath   = regexp.MustCompile(`^  (/\S*):\s*$`)
	reOpenAPIMethod = regexp.MustCompile(`^    (get|put|post|delete|patch|head|options):`)
	reOpenAPIScope  = regexp.MustCompile(`^      x-scope:\s*(\S+)\s*$`)
	reOpenAPIPublic = regexp.MustCompile(`^      security:\s*\[\]\s*$`)
)

// openAPIOps reads "METHOD path scope" from the paths section of
// docs/openapi.yaml. The file keeps the two-space layout this parser
// expects; the project has no YAML dependency (CLAUDE.md).
func openAPIOps(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ops []string
	inPaths := false
	path, method, scope := "", "", ""
	public := false
	flush := func() {
		if method == "" {
			return
		}
		if public {
			scope = "public"
		}
		ops = append(ops, method+" "+path+" "+scope)
		method, scope, public = "", "", false
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "paths:" {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if m := reOpenAPIPath.FindStringSubmatch(line); m != nil {
			flush()
			path = m[1]
			continue
		}
		if m := reOpenAPIMethod.FindStringSubmatch(line); m != nil {
			flush()
			method = strings.ToUpper(m[1])
			continue
		}
		if m := reOpenAPIScope.FindStringSubmatch(line); m != nil {
			scope = m[1]
		}
		if reOpenAPIPublic.MatchString(line) {
			public = true
		}
	}
	flush()
	sort.Strings(ops)
	return ops
}

// TestOpenAPIRoutes checks that the routes of the code and of
// docs/openapi.yaml match in both directions, scopes included.
func TestOpenAPIRoutes(t *testing.T) {
	spec := openAPIOps(t)
	routes := Routes()
	code := make([]string, 0, len(routes))
	for _, r := range routes {
		scope := r.Scope
		switch scope {
		case ScopePublic:
			scope = "public"
		case ScopeMetrics:
			scope = "status:read"
		}
		code = append(code, r.Method+" "+r.Path+" "+scope)
	}
	sort.Strings(code)
	inSpec := map[string]bool{}
	for _, op := range spec {
		inSpec[op] = true
	}
	inCode := map[string]bool{}
	for _, op := range code {
		inCode[op] = true
		if !inSpec[op] {
			t.Errorf("route %q is not in docs/openapi.yaml", op)
		}
	}
	for _, op := range spec {
		if !inCode[op] {
			t.Errorf("docs/openapi.yaml operation %q has no route", op)
		}
	}
	if len(spec) != len(inSpec) {
		t.Errorf("duplicate operations in docs/openapi.yaml: %v", spec)
	}
	if len(spec) < 19 {
		t.Errorf("parsed only %d operations; layout changed?", len(spec))
	}
}
