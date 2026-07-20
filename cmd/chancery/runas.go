//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Privilege separation for the spawned tool server (SECURITY.md G17).
//
// Sealed secrets are injected into the server's environment, and
// /proc/<pid>/environ is readable by any process that passes
// PTRACE_MODE_READ — same-UID processes, and ancestors under the
// default yama ptrace_scope=1. Because the agent runtime is normally
// the process that spawned the wrap, a hostile runtime is inside that
// set even though a prompt-injected *model* is not.
//
// The only boundary that actually holds on POSIX is a different UID:
// ptrace checks credentials, and being an ancestor does not override
// them. Approaches that look like they should work but don't:
//
//   - PR_SET_DUMPABLE(0) makes /proc/<pid>/* root-owned, but execve
//     resets dumpable to 1 for non-setuid binaries, so it is gone the
//     moment we spawn the server.
//   - Passing the secret by unlinked fd instead of env moves the
//     exposure to /proc/<pid>/fd, which is gated identically.
//   - A user namespace without subuid ranges maps back to the same
//     host UID, so it buys nothing.

// runAsCredential resolves a user name or numeric uid into the
// credential the child should run under. Returns nil when runAs is
// empty (the default: child shares our UID).
func runAsCredential(runAs string) (*syscall.Credential, string, error) {
	if runAs == "" {
		return nil, "", nil
	}
	if os.Geteuid() != 0 {
		// Fail closed, like --confine: refusing beats pretending the
		// boundary exists.
		return nil, "", fmt.Errorf("--run-as %s needs privilege to change the child's user (running as uid %d): "+
			"start chancery as root, or drop --run-as and accept that the tool server shares your UID (SECURITY.md G17)",
			runAs, os.Geteuid())
	}
	u, err := user.Lookup(runAs)
	if err != nil {
		if u2, err2 := user.LookupId(runAs); err2 == nil {
			u = u2
		} else {
			return nil, "", fmt.Errorf("--run-as %q: no such user", runAs)
		}
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, "", fmt.Errorf("--run-as %q: unusable uid %q", runAs, u.Uid)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, "", fmt.Errorf("--run-as %q: unusable gid %q", runAs, u.Gid)
	}
	if uid == 0 {
		return nil, "", fmt.Errorf("--run-as %q resolves to root, which is not a privilege boundary", runAs)
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true},
		fmt.Sprintf("%s(%d:%d)", u.Username, uid, gid), nil
}

// applyRunAs attaches the credential to the child process.
func applyRunAs(cmd *exec.Cmd, cred *syscall.Credential) {
	if cred == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = cred
}

// chownForChild hands ownership of a materialized secret file (or its
// run dir) to the child's uid — otherwise privilege separation breaks
// the very feature it protects: a 0600 file we own is unreadable by
// the user the server now runs as.
func chownForChild(path string, cred *syscall.Credential) error {
	if cred == nil {
		return nil
	}
	return os.Chown(path, int(cred.Uid), int(cred.Gid))
}

// ptraceScope reports the Linux yama setting, or "" where it does not
// apply. 0 = any same-UID process may read; 1 = ancestors only (the
// common default, which still includes the agent runtime); 2+ = admin
// only, which closes G17 without a separate user.
func ptraceScope() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// secretExposureWarning returns the operator-facing warning when
// secrets are being injected into a child that shares our UID, or ""
// when the configuration is already sound. Stated plainly rather than
// hidden: the gap is real and the mitigation is one flag away.
func secretExposureWarning(injecting bool, cred *syscall.Credential) string {
	if !injecting || cred != nil {
		return ""
	}
	if s := ptraceScope(); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 2 {
			return "" // yama already denies same-UID reads
		}
	}
	msg := "warning: the tool server runs as your own user, so any process sharing this UID can read its " +
		"environment (/proc/<pid>/environ) and with it the injected secrets — including the agent runtime " +
		"that spawned this wrap. See SECURITY.md G17."
	if s := ptraceScope(); s != "" {
		msg += fmt.Sprintf(" (yama ptrace_scope=%s)", s)
	}
	return msg + "\n  fix: run the server under its own user — `chancery mcp wrap --run-as chancery-tools ...` (needs root)"
}
