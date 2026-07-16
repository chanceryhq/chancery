package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chanceryhq/chancery/internal/store"
)

// `chancery mcp install` (RFC-018): a Chancery-managed frozen install.
// The package is installed once, at an EXACT version, with lifecycle
// scripts disabled, into $CHANCERY_DATA/servers/<name>; the whole tree
// is Merkle-hashed and pinned (RFC-016 T2). `mcp wrap` then launches
// from that dir and re-verifies the tree before every spawn — closing
// the npx hole (G13) without requiring Docker: `npx pkg` resolves the
// package fresh on every run; an installed server never resolves again.

var exactVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][\w.]+)?$`)

// splitSpec splits an npm package spec into (name, version), handling
// scoped packages (@scope/name@1.2.3).
func splitSpec(spec string) (name, version string) {
	i := strings.LastIndex(spec, "@")
	if i <= 0 { // no version, or the @ is the scope marker
		return spec, ""
	}
	return spec[:i], spec[i+1:]
}

func installCmd(mcpParent *cobra.Command) {
	var serverName string
	var egress, writable []string
	install := &cobra.Command{
		Use:   "install <package>@<exact-version>",
		Short: "Frozen, tree-pinned server install (RFC-018) — closes the npx hole without Docker",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			spec := args[0]
			name, version := splitSpec(spec)
			// A mutable spec is not an identity (same rule as image
			// tags, RFC-016): demand an exact version so the pin means
			// something. Local paths are allowed (offline installs).
			if fi, err := os.Stat(spec); err != nil || !fi.IsDir() {
				if !exactVersionRe.MatchString(version) {
					return fmt.Errorf("%q is not an exact version — install pins identity, so ranges and tags (latest, ^, ~) are refused; use %s@<x.y.z>", spec, name)
				}
			}
			if serverName == "" {
				serverName = filepath.Base(name)
			}
			dir := filepath.Join(dataDir, "servers", serverName)
			if _, err := os.Stat(dir); err == nil {
				return fmt.Errorf("%s already exists — a frozen install never changes in place; remove it and reinstall, then `chancery mcp repin`", dir)
			}
			npm, err := exec.LookPath("npm")
			if err != nil {
				return fmt.Errorf("npm not found on PATH (only npm packages are supported today)")
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			// --ignore-scripts: install-time lifecycle scripts are
			// arbitrary code from the registry; a frozen install does
			// not run them. Packages that require a build step need a
			// manual install + `mcp wrap --pin-tree`.
			// --install-links: local-path installs must be COPIES, not
			// symlinks — a symlink's tree hash is just its target
			// string, which would pin nothing.
			npmCmd := exec.Command(npm, "install", "--prefix", dir,
				"--ignore-scripts", "--install-links", "--no-audit", "--no-fund", spec)
			npmCmd.Stdout = os.Stderr
			npmCmd.Stderr = os.Stderr
			if err := npmCmd.Run(); err != nil {
				os.RemoveAll(dir)
				return fmt.Errorf("npm install failed: %w", err)
			}
			sha, err := hashTree(dir)
			if err != nil {
				os.RemoveAll(dir)
				return fmt.Errorf("hash installed tree: %w", err)
			}
			if err := e.st.SetServerPin(serverName, store.PinTree, dir, sha); err != nil {
				return err
			}
			if len(egress) > 0 || len(writable) > 0 {
				if err := e.st.SetServerManifest(serverName, egress, writable); err != nil {
					return err
				}
			}
			e.st.Audit(store.AuditEvent{Event: "mcp.server_install", Resource: serverName,
				Reason: fmt.Sprintf("spec=%s tree:%s dir=%s egress=%s writable=%s",
					spec, sha[:16], dir, strings.Join(egress, ","), strings.Join(writable, ","))})

			bins, _ := filepath.Glob(filepath.Join(dir, "node_modules", ".bin", "*"))
			fmt.Printf("installed %s\n  dir      %s\n  identity tree:%s (pinned — wrap re-verifies before every spawn)\n", spec, dir, sha[:16])
			if len(bins) > 0 {
				var names []string
				for _, b := range bins {
					names = append(names, filepath.Base(b))
				}
				fmt.Printf("  bins     %s\n", strings.Join(names, ", "))
				fmt.Printf("\nrun it:\n  chancery mcp wrap --agent <name> --writ <id> --server-name %s -- %s\n",
					serverName, bins[0])
			}
			return nil
		},
	}
	install.Flags().StringVar(&serverName, "server-name", "", "pin namespace (default: package basename)")
	install.Flags().StringSliceVar(&egress, "egress", nil,
		"confinement manifest: host the server may reach (repeatable; empty = no network under --confine)")
	install.Flags().StringSliceVar(&writable, "writable", nil,
		"confinement manifest: path the server may write (repeatable; empty = read-only under --confine)")
	mcpParent.AddCommand(install)
}
