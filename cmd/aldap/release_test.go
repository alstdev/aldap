package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func repoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func match1(t *testing.T, re, s, what string) string {
	t.Helper()
	m := regexp.MustCompile(re).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("%s not found (%s)", what, re)
	}
	return m[1]
}

// TestDHITagsPinned keeps the DHI tags of Dockerfile and build.sh equal and
// the golang image on the go.mod toolchain (docs/DECISIONS.md «DHI tags»).
func TestDHITagsPinned(t *testing.T) {
	docker, build, gomod := repoFile(t, "Dockerfile"), repoFile(t, "build.sh"), repoFile(t, "go.mod")
	golangD := match1(t, `(?m)^ARG DHI_GOLANG_TAG=(\S+)$`, docker, "Dockerfile DHI_GOLANG_TAG")
	staticD := match1(t, `(?m)^ARG DHI_STATIC_TAG=(\S+)$`, docker, "Dockerfile DHI_STATIC_TAG")
	golangB := match1(t, `(?m)^DHI_GOLANG_TAG="\$\{DHI_GOLANG_TAG:-([^}]+)\}"$`, build, "build.sh DHI_GOLANG_TAG")
	staticB := match1(t, `(?m)^DHI_STATIC_TAG="\$\{DHI_STATIC_TAG:-([^}]+)\}"$`, build, "build.sh DHI_STATIC_TAG")
	toolchain := match1(t, `(?m)^toolchain go(\S+)$`, gomod, "go.mod toolchain")
	if golangD != golangB || staticD != staticB {
		t.Errorf("Dockerfile %s/%s, build.sh %s/%s", golangD, staticD, golangB, staticB)
	}
	if golangD != toolchain+"-debian13-dev" {
		t.Errorf("dhi.io/golang:%s does not match toolchain go%s", golangD, toolchain)
	}
	for _, tag := range []string{golangD, staticD} {
		if tag == "latest" || !regexp.MustCompile(`\d`).MatchString(tag) {
			t.Errorf("DHI tag %q is not pinned", tag)
		}
	}
}

// TestActionsPinnedBySHA: every third-party action in the workflows is
// pinned to a full commit SHA (a tag can be moved by its owner or by whoever
// takes the repository over); local reusable workflows (./...) are exempt.
func TestActionsPinnedBySHA(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("workflows: %v %v", files, err)
	}
	use := regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s+(\S+)`)
	pinned := regexp.MustCompile(`@[0-9a-f]{40}$`)
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // repository file
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range use.FindAllStringSubmatch(string(b), -1) {
			if strings.HasPrefix(m[1], "./") || pinned.MatchString(m[1]) {
				continue
			}
			t.Errorf("%s: %q is not pinned to a commit SHA", filepath.Base(f), m[1])
		}
	}
}
