//go:build unix

package main

// Privilege separation for the spawned tool server (SECURITY.md G17).
// The setuid path itself needs root, so CI exercises the refusal, the
// resolution rules, and the warning logic — the parts that decide
// whether an operator is protected or merely thinks they are.

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestRunAsRequiresPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this test covers the unprivileged refusal")
	}
	_, _, err := runAsCredential("nobody")
	if err == nil {
		t.Fatal("--run-as without privilege must refuse, not silently share the UID")
	}
	// The error has to tell the operator both why and what to do.
	for _, want := range []string{"needs privilege", "G17"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal should mention %q, got: %v", want, err)
		}
	}
}

func TestRunAsEmptyIsNoOp(t *testing.T) {
	cred, desc, err := runAsCredential("")
	if err != nil || cred != nil || desc != "" {
		t.Fatalf("no --run-as must mean no credential change, got (%v, %q, %v)", cred, desc, err)
	}
	// applyRunAs must tolerate a nil credential without touching the cmd.
	cmd := exec.Command("true")
	applyRunAs(cmd, nil)
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Fatal("nil credential must not set SysProcAttr.Credential")
	}
	if err := chownForChild("/nonexistent/path", nil); err != nil {
		t.Fatalf("chownForChild with nil credential must be a no-op, got %v", err)
	}
}

func TestApplyRunAsSetsCredential(t *testing.T) {
	cred := &syscall.Credential{Uid: 4242, Gid: 4243, NoSetGroups: true}
	cmd := exec.Command("true")
	applyRunAs(cmd, cred)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("credential was not attached to the child")
	}
	if got := cmd.SysProcAttr.Credential.Uid; got != 4242 {
		t.Errorf("child uid = %d, want 4242", got)
	}
	// Preserve a SysProcAttr the caller already set.
	cmd2 := exec.Command("true")
	cmd2.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	applyRunAs(cmd2, cred)
	if !cmd2.SysProcAttr.Setsid {
		t.Error("applyRunAs clobbered existing SysProcAttr fields")
	}
}

// TestSecretExposureWarning: the warning must fire exactly when the
// operator is actually exposed — silence otherwise, or it becomes noise
// people learn to ignore.
func TestSecretExposureWarning(t *testing.T) {
	cred := &syscall.Credential{Uid: 4242, Gid: 4243}

	if w := secretExposureWarning(false, nil); w != "" {
		t.Errorf("no secrets injected: want silence, got %q", w)
	}
	if w := secretExposureWarning(true, cred); w != "" {
		t.Errorf("--run-as in effect: want silence, got %q", w)
	}

	w := secretExposureWarning(true, nil)
	// On a host with ptrace_scope>=2 the exposure is already closed and
	// silence is correct; everywhere else the warning must be actionable.
	if w == "" {
		if s := ptraceScope(); s == "" || s < "2" {
			t.Fatalf("secrets into a same-UID child must warn (ptrace_scope=%q)", s)
		}
		return
	}
	for _, want := range []string{"environ", "G17", "--run-as"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning should mention %q, got: %s", want, w)
		}
	}
}

func TestRunAsRejectsRootAndUnknownUsers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to reach the resolution branch")
	}
	if _, _, err := runAsCredential("root"); err == nil {
		t.Error("--run-as root is not a privilege boundary and must be refused")
	}
	if _, _, err := runAsCredential("chancery-no-such-user-xyz"); err == nil {
		t.Error("unknown user must be refused")
	}
}
