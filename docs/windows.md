# Windows — manual checklist

Windows is best effort (SPEC §10.5): CI only cross-compiles `windows/amd64` (`make build`), there is no
Windows runner. Run this checklist by hand on Windows 10/11 or Server 2019+ before a release and record
the result (date, Windows build, ALDAP version) in the release notes.

## Build

- [ ] `make build` (or CI artifact `binaries`) produces `dist/aldap_windows_amd64.exe` and
      `dist/aldapctl_windows_amd64.exe`; `aldap.exe version` prints `windows/amd64`.

## Configuration

- [ ] `aldap.exe check --config C:\ProgramData\ALDAP\aldap.toml` passes; without `[server].ipc_socket`
      the default is `\\.\pipe\aldap`.
- [ ] `ipc_socket = "C:\\aldap.sock"` (not a pipe path) → `aldap.exe run` refuses to start with
      `ipc: ... is not a named pipe path`.

## IPC named pipe (`github.com/Microsoft/go-winio`)

Run the daemon from an **elevated** PowerShell (`aldap.exe run --config ...`).

- [ ] The pipe exists: `Get-ChildItem \\.\pipe\ | Where-Object Name -eq aldap`.
- [ ] ACL is SYSTEM + Administrators only:
      `[System.IO.Directory]::GetAccessControl('\\.\pipe\aldap').Access` (or Sysinternals
      `accesschk.exe \pipe\aldap`) lists `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` only.
- [ ] Elevated shell: `go test -run TestListenIPC ./internal/api/` passes without the skip.
- [ ] A non-elevated shell of the same user cannot open the pipe (access denied); the same test skips
      with the access error.
- [ ] A second `aldap.exe run` with the same `ipc_socket` refuses to start (pipe in use).
- [ ] From another host `\\<host>\pipe\aldap` is refused (remote clients rejected).
- [ ] After `Ctrl+C` the pipe is gone and a new `aldap.exe run` starts.

## aldapctl over the pipe

From an **elevated** PowerShell (the pipe ACL admits SYSTEM and Administrators only):

- [ ] `aldapctl.exe status` (default `--socket \\.\pipe\aldap`) prints the status; a non-elevated shell
      gets `cannot reach aldap at IPC socket \\.\pipe\aldap: ... Access is denied`.
- [ ] `aldapctl.exe lock 192.0.2.7 --for 1m --yes`, `aldapctl.exe locks`, `aldapctl.exe unlock 192.0.2.7 --yes`.
- [ ] `aldapctl.exe` without a command opens the TUI in Windows Terminal and in the classic console
      (`conhost`, 16 colors); `?` lists the keys, `q` quits; `$EDITOR` unset → `e` on Config opens Notepad.
- [ ] `aldapctl.exe --url https://<host>:8636 --token-file C:\path\token --ca-file ca.pem status` over TCP.

## Not yet available

- `aldap.exe service install` (`kardianos/service`, Event Log) — Stage 12.
