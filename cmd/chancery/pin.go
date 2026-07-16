package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/chanceryhq/chancery/internal/store"
)

// Server pin identity resolution (RFC-016). Three tiers, strongest
// applicable wins:
//
//	T3 digest — the server command references a container image pinned
//	            by digest (image@sha256:…): the digest IS the identity;
//	            the container runtime's content-addressing enforces it.
//	T2 tree   — the operator passed --pin-tree <dir>: Merkle hash of
//	            the whole directory (full dependency tree).
//	T1 binary — default: SHA-256 of the resolved executable. Honest
//	            limit: for interpreter launchers (npx, uvx) this pins
//	            the LAUNCHER, not the package tree behind it (G13).

var imageDigestRe = regexp.MustCompile(`^[\w./:-]+@sha256:([0-9a-f]{64})$`)

// extractImageDigest scans a server command's arguments for a container
// image reference pinned by digest and returns (imageRef, digestHex).
// Only digest-pinned references count — a mutable tag ("image:latest")
// is not an identity.
func extractImageDigest(args []string) (string, string) {
	for _, a := range args {
		if m := imageDigestRe.FindStringSubmatch(a); m != nil {
			return a, m[1]
		}
	}
	return "", ""
}

// hashTree computes a Merkle-style identity for a directory: the
// SHA-256 over each regular file's (sorted, slash-normalized) relative
// path, mode-bit executability, and content hash. Any added, removed,
// renamed, or modified file changes the result. Symlinks hash their
// target string (not what it points at — that would escape the tree).
func hashTree(dir string) (string, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	type entry struct{ rel, line string }
	var entries []entry
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			entries = append(entries, entry{rel, rel + "\x1fsymlink\x1f" + target})
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unsupported file type at %s (fail closed)", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, cerr := io.Copy(h, f)
		f.Close()
		if cerr != nil {
			return cerr
		}
		mode := "-"
		if info.Mode()&0o111 != 0 {
			mode = "x"
		}
		entries = append(entries, entry{rel, rel + "\x1f" + mode + "\x1f" + hex.EncodeToString(h.Sum(nil))})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	top := sha256.New()
	for _, e := range entries {
		top.Write([]byte(e.line))
		top.Write([]byte{'\n'})
	}
	return hex.EncodeToString(top.Sum(nil)), nil
}

// resolvePinIdentity computes the strongest applicable pin identity for
// a server command (RFC-016): digest if the args carry one, tree if the
// operator asked, binary otherwise.
func resolvePinIdentity(args []string, pinTree string) (kind, path, sha string, err error) {
	if ref, digest := extractImageDigest(args); digest != "" {
		return store.PinDigest, ref, digest, nil
	}
	if pinTree != "" {
		sha, err := hashTree(pinTree)
		if err != nil {
			return "", "", "", fmt.Errorf("hash tree %s: %w", pinTree, err)
		}
		return store.PinTree, pinTree, sha, nil
	}
	path, sha, err = resolveServerHash(args[0])
	return store.PinBinary, path, sha, err
}

// resolveServerHash resolves a server command on PATH and returns the
// binary's path and SHA-256 (RFC-016 T1). Honest limit, documented: for
// interpreter launchers (npx, uvx, docker) this pins the LAUNCHER, not
// the package tree behind it — use --pin-tree or an image digest for
// full-tree coverage (T2/T3).
func resolveServerHash(cmd string) (string, string, error) {
	path, err := exec.LookPath(cmd)
	if err != nil {
		return "", "", err
	}
	if abs, err := filepath.EvalSymlinks(path); err == nil {
		path = abs
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	return path, hex.EncodeToString(h.Sum(nil)), nil
}

// pinDescribe renders a pin identity for messages and audit reasons.
func pinDescribe(kind, sha string) string {
	return kind + ":" + sha[:16]
}
