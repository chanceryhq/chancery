package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/chanceryhq/chancery/internal/confine"
)

// applyConfinement (RFC-018) turns a pin's manifest into an OS boundary
// around the server spawn:
//
//   - a Chancery-owned loopback egress proxy is started with the
//     manifest's host allow-list; the child env routes HTTP(S) through
//     it and every refused host is audited (host only);
//   - the command is wrapped in an OS sandbox that (a) restricts
//     outbound network to loopback, so the proxy is the only road out
//     even for a client that ignores proxy env vars, and (b) makes the
//     filesystem read-only outside the manifest's writable paths and a
//     private temp dir.
//
// macOS uses sandbox-exec (seatbelt); Linux uses bubblewrap for the
// filesystem boundary (egress there is proxy-env cooperative until the
// netns phase — stated in RFC-018 §7). Anywhere the OS layer is
// unavailable the spawn is REFUSED: fail closed, never
// silently-unconfined.
func applyConfinement(egress, writable []string, args, env []string, onDeny func(host string)) (newArgs, newEnv []string, cleanup func(), err error) {
	proxy := &confine.EgressProxy{Egress: egress, OnDeny: onDeny}
	addr, err := proxy.Start()
	if err != nil {
		return nil, nil, nil, err
	}
	tmp, err := os.MkdirTemp("", "chancery-confine-")
	if err != nil {
		proxy.Close()
		return nil, nil, nil, err
	}
	cleanup = func() { proxy.Close(); os.RemoveAll(tmp) }
	env = append(env, confine.ProxyEnv(addr)...)
	env = append(env, "TMPDIR="+tmp)

	// Sandbox subpath rules match REAL paths; /tmp is a symlink on
	// macOS, so resolve everything first.
	realTmp, _ := filepath.EvalSymlinks(tmp)
	var realWritable []string
	for _, w := range writable {
		abs, err := filepath.Abs(w)
		if err == nil {
			if r, rerr := filepath.EvalSymlinks(abs); rerr == nil {
				abs = r
			}
			realWritable = append(realWritable, abs)
		}
	}

	switch runtime.GOOS {
	case "darwin":
		sb, lerr := exec.LookPath("sandbox-exec")
		if lerr != nil {
			cleanup()
			return nil, nil, nil, fmt.Errorf("--confine needs sandbox-exec on macOS and it was not found: refusing to spawn unconfined (fail closed)")
		}
		profile := confine.SandboxProfile(realWritable, realTmp)
		return append([]string{sb, "-p", profile}, args...), env, cleanup, nil
	case "linux":
		bw, lerr := exec.LookPath("bwrap")
		if lerr != nil {
			cleanup()
			return nil, nil, nil, fmt.Errorf("--confine needs bubblewrap (bwrap) on Linux and it was not found: refusing to spawn unconfined (fail closed)")
		}
		bwArgs := []string{bw, "--ro-bind", "/", "/", "--dev", "/dev", "--bind", realTmp, realTmp, "--die-with-parent"}
		for _, w := range realWritable {
			bwArgs = append(bwArgs, "--bind", w, w)
		}
		return append(append(bwArgs, "--"), args...), env, cleanup, nil
	default:
		cleanup()
		return nil, nil, nil, fmt.Errorf("--confine is not supported on %s: refusing to spawn unconfined (fail closed)", runtime.GOOS)
	}
}
