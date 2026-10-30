package main

import (
	"encoding/json"
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

// TestSeccompCoversObservedSyscalls: deploy/seccomp.json must allow every
// syscall a static Go binary made under strace for `aldap check` and a
// listening `aldap run`, plus the ones runc needs to start the container
// (statx, arch_prctl, setgroups-free user setup). The previous profile lacked
// these, so docker-compose.yml's seccomp:./deploy/seccomp.json container
// never started (audit A9-1). Verified by running the plain image under the
// profile (docs/AUDIT.md).
func TestSeccompCoversObservedSyscalls(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "seccomp.json")) //nolint:gosec // repository file
	if err != nil {
		t.Fatal(err)
	}
	var prof struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
			Args   []any    `json:"args"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(b, &prof); err != nil {
		t.Fatal(err)
	}
	if prof.DefaultAction == "SCMP_ACT_ALLOW" {
		t.Fatal("defaultAction must deny")
	}
	allowed := map[string]bool{}
	for _, s := range prof.Syscalls {
		if s.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, n := range s.Names {
			allowed[n] = true
		}
	}
	observed := strings.Fields(`accept4 access arch_prctl bind brk clone close connect dup3 epoll_create1 epoll_ctl
		epoll_pwait eventfd2 execve exit_group faccessat2 fchmodat fcntl fstat futex getegid geteuid getgid getpid
		getppid getrandom getsockname getsockopt gettid getuid listen madvise mmap mprotect munmap nanosleep
		newfstatat openat pidfd_open pidfd_send_signal pipe2 prctl pread64 prlimit64 read readlinkat renameat
		restart_syscall rseq rt_sigaction rt_sigprocmask rt_sigreturn sched_getaffinity sched_yield set_robust_list
		set_tid_address setsockopt sigaltstack socket statfs tgkill uname unlinkat waitid write`)
	for _, n := range observed {
		if !allowed[n] {
			t.Errorf("syscall %s is used by aldap but not allowed by deploy/seccomp.json", n)
		}
	}
	for _, bad := range []string{"ptrace", "mount", "umount2", "bpf", "keyctl", "add_key", "setns", "unshare", "userfaultfd",
		"process_vm_readv", "process_vm_writev", "kexec_load", "init_module", "finit_module", "reboot", "perf_event_open", "iopl", "ioperm"} {
		if allowed[bad] {
			t.Errorf("dangerous syscall %s is allowed", bad)
		}
	}
	// socket is limited to AF_UNIX, AF_INET and AF_INET6 (no AF_NETLINK, AF_PACKET).
	for _, s := range prof.Syscalls {
		for _, n := range s.Names {
			if n == "socket" && len(s.Args) == 0 {
				t.Error("socket is allowed for every address family")
			}
		}
	}
}
