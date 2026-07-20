//go:build !unix

package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

// Privilege separation is a POSIX credential mechanism; on platforms
// without it, --run-as refuses rather than silently doing nothing
// (same posture as --confine).

func runAsCredential(runAs string) (*syscall.Credential, string, error) {
	if runAs == "" {
		return nil, "", nil
	}
	return nil, "", fmt.Errorf("--run-as is not supported on this platform")
}

func applyRunAs(cmd *exec.Cmd, cred *syscall.Credential) {}

func chownForChild(path string, cred *syscall.Credential) error { return nil }

func ptraceScope() string { return "" }

func secretExposureWarning(injecting bool, cred *syscall.Credential) string { return "" }
