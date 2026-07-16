// chancery is the CLI for the Chancery control plane: the registry of
// agent identities (RFC-001) and writs (RFC-002).
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/chanceryhq/chancery/internal/api"
	"github.com/chanceryhq/chancery/internal/identity"
	"github.com/chanceryhq/chancery/internal/mcp"
	"github.com/chanceryhq/chancery/internal/policy"
	"github.com/chanceryhq/chancery/internal/seal"
	"github.com/chanceryhq/chancery/internal/service"
	"github.com/chanceryhq/chancery/internal/store"
	"github.com/chanceryhq/chancery/internal/writ"
)

var dataDir string

// Build metadata, injected at release time via -ldflags (goreleaser).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func defaultDataDir() string {
	if d := os.Getenv("CHANCERY_DATA"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".chancery"
	}
	return filepath.Join(home, ".chancery")
}

type env struct {
	st  *store.Store
	iss *identity.Issuer
	svc *service.Service
}

func openEnv() (*env, error) {
	st, err := store.Open(filepath.Join(dataDir, "chancery.db"))
	if err != nil {
		return nil, err
	}
	td, err := st.GetConfig("trust_domain")
	if err != nil {
		return nil, fmt.Errorf("not initialized — run `chancery init --trust-domain <your-domain>` first")
	}
	issuerURL, _ := st.GetConfig("issuer_url")
	iss, err := identity.LoadOrCreate(dataDir, td, issuerURL)
	if err != nil {
		return nil, err
	}
	// The CLI and the HTTP API are thin clients over one service layer
	// (RFC-008 §4): register/instance/grant/delegate/check share exactly
	// one implementation.
	return &env{st: st, iss: iss, svc: &service.Service{St: st, Iss: iss}}, nil
}

// hashArg content-addresses a file path or, if the path does not exist,
// the literal string. Only the digest is ever stored (RFC-000 D6).
func hashArg(s string) string {
	data := []byte(s)
	if raw, err := os.ReadFile(s); err == nil {
		data = raw
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func table(rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
}

func main() {
	root := &cobra.Command{
		Use:           "chancery",
		Short:         "Chancery — the identity provider for AI agents",
		Version:       fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&dataDir, "data-dir", defaultDataDir(), "state directory")

	root.AddCommand(initCmd(), agentCmd(), templateCmd(), instanceCmd(), tokenCmd(), writCmd(), auditCmd(), secretCmd(), mcpCmd(), serveCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	var trustDomain, issuerURL string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the Chancery control plane state",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				return err
			}
			st, err := store.Open(filepath.Join(dataDir, "chancery.db"))
			if err != nil {
				return err
			}
			defer st.Close()
			if issuerURL == "" {
				issuerURL = "https://chancery." + trustDomain
			}
			if err := st.SetConfig("trust_domain", trustDomain); err != nil {
				return err
			}
			if err := st.SetConfig("issuer_url", issuerURL); err != nil {
				return err
			}
			if _, err := identity.LoadOrCreate(dataDir, trustDomain, issuerURL); err != nil {
				return err
			}
			// Mint the admin API token once; only its hash is stored
			// (RFC-008 §4).
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return err
			}
			adminToken := "chy_" + hex.EncodeToString(raw)
			sum := sha256.Sum256([]byte(adminToken))
			if err := st.SetConfig("admin_token_hash", hex.EncodeToString(sum[:])); err != nil {
				return err
			}
			fmt.Printf("initialized trust domain %s (issuer %s) in %s\n", trustDomain, issuerURL, dataDir)
			fmt.Printf("\nadmin API token (shown ONCE — store it now):\n  %s\n", adminToken)
			return nil
		},
	}
	cmd.Flags().StringVar(&trustDomain, "trust-domain", "", "trust domain, e.g. acme.com (required)")
	cmd.Flags().StringVar(&issuerURL, "issuer-url", "", "issuer URL (default https://chancery.<trust-domain>)")
	cmd.MarkFlagRequired("trust-domain")
	return cmd
}

func agentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Manage agent identities (RFC-001)"}

	var owner, purpose, prompt, config, tools, model string
	register := &cobra.Command{
		Use:   "register <name>",
		Short: "Register a durable agent identity and its first version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			a, v, err := e.svc.RegisterAgent(args[0], owner, purpose,
				hashArg(prompt), hashArg(config), hashArg(tools), model)
			if err != nil {
				return err
			}
			fmt.Printf("registered %s\n  id       %s\n  owner    %s\n  version  %d (%s)\n",
				e.iss.SubjectURI(a.Name), a.ID, a.Owner, v.Seq, v.Digest())
			return nil
		},
	}
	register.Flags().StringVar(&owner, "owner", "", "accountable owner principal, e.g. user:aneesh@acme.com (required)")
	register.Flags().StringVar(&purpose, "purpose", "", "stated purpose (required)")
	register.Flags().StringVar(&prompt, "prompt", "", "system prompt: file path or literal (hashed, never stored)")
	register.Flags().StringVar(&config, "config", "", "configuration: file path or literal (hashed, never stored)")
	register.Flags().StringVar(&tools, "tools", "", "tool manifest: file path or literal (hashed, never stored)")
	register.Flags().StringVar(&model, "model", "", "model identifier")
	register.MarkFlagRequired("owner")
	register.MarkFlagRequired("purpose")

	var vPrompt, vConfig, vTools, vModel string
	version := &cobra.Command{
		Use:   "version <name>",
		Short: "Record a new immutable version of an agent (RFC-001: change = new version)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			a, v, err := e.svc.AddVersion(args[0], hashArg(vPrompt), hashArg(vConfig), hashArg(vTools), vModel)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n  version  %d (%s)  — supersedes prior; old versions kept\n",
				e.iss.SubjectURI(a.Name), v.Seq, v.Digest())
			return nil
		},
	}
	version.Flags().StringVar(&vPrompt, "prompt", "", "system prompt: file path or literal (hashed, never stored)")
	version.Flags().StringVar(&vConfig, "config", "", "configuration: file path or literal (hashed, never stored)")
	version.Flags().StringVar(&vTools, "tools", "", "tool manifest: file path or literal (hashed, never stored)")
	version.Flags().StringVar(&vModel, "model", "", "model identifier")

	list := &cobra.Command{
		Use:   "list",
		Short: "List registered agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			agents, err := e.st.ListAgents()
			if err != nil {
				return err
			}
			rows := [][]string{{"NAME", "STATE", "OWNER", "SPAWNED BY", "EXPIRES", "PURPOSE"}}
			for _, a := range agents {
				state, spawnedBy, expires := a.State, a.SpawnedBy, ""
				if spawnedBy == "" {
					spawnedBy = "-"
				}
				if a.ExpiresAt != nil {
					expires = a.ExpiresAt.UTC().Format(time.RFC3339)
					// An expired ephemeral is already denied in-path
					// even before `agent sweep` retires it.
					if a.State == store.StateActive && time.Now().UTC().After(*a.ExpiresAt) {
						state = "expired"
					}
				} else {
					expires = "-"
				}
				rows = append(rows, []string{a.Name, state, a.Owner, spawnedBy, expires, a.Purpose})
			}
			table(rows)
			return nil
		},
	}

	describe := &cobra.Command{
		Use:   "describe <name>",
		Short: "Show an agent's versions and instances",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			a, err := e.st.GetAgentByName(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("%s\n  state   %s\n  owner   %s\n  purpose %s\n\nversions:\n",
				e.iss.SubjectURI(a.Name), a.State, a.Owner, a.Purpose)
			versions, err := e.st.ListVersions(a.ID)
			if err != nil {
				return err
			}
			rows := [][]string{{"  SEQ", "DIGEST", "MODEL", "STATE"}}
			for i := range versions {
				v := versions[i]
				state := "active"
				if v.RevokedAt != nil {
					state = "revoked"
				}
				rows = append(rows, []string{fmt.Sprintf("  %d", v.Seq), v.Digest(), v.Model, state})
			}
			table(rows)
			instances, err := e.st.ListInstances(a.ID)
			if err != nil {
				return err
			}
			fmt.Println("\ninstances:")
			rows = [][]string{{"  ID", "STATE", "ATTESTATION", "STARTED"}}
			for _, in := range instances {
				rows = append(rows, []string{"  " + in.ID, in.State, in.AttestationType,
					in.CreatedAt.Format(time.RFC3339)})
			}
			table(rows)
			return nil
		},
	}

	state := func(use, short, target string) *cobra.Command {
		return &cobra.Command{
			Use: use + " <name>", Short: short, Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				e, err := openEnv()
				if err != nil {
					return err
				}
				defer e.st.Close()
				a, err := e.st.GetAgentByName(args[0])
				if err != nil {
					return err
				}
				if err := e.st.SetAgentState(args[0], target); err != nil {
					return err
				}
				e.st.Audit(store.AuditEvent{Event: "agent." + use, AgentID: a.ID})
				note := ""
				if target == store.StateRevoked || target == store.StateRetired {
					note = " (TERMINAL — this cannot be undone)"
				}
				fmt.Printf("%s is now %s — takes effect on the next in-path check%s\n", args[0], target, note)
				return nil
			},
		}
	}

	var toolPatterns []string
	allow := &cobra.Command{
		Use:   "allow <name>",
		Short: "Set an agent's tool allow-list (RFC-004 L2; subtractive — only the writ grants)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			a, err := e.st.GetAgentByName(args[0])
			if err != nil {
				return err
			}
			for _, p := range toolPatterns {
				if p == policy.DenyAll {
					continue
				}
				if err := policy.ValidateResourcePattern(p); err != nil {
					return err
				}
			}
			if err := e.st.SetAllowlist(a.ID, toolPatterns); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "agent.allowlist", AgentID: a.ID,
				Reason: "patterns=" + strings.Join(toolPatterns, ",")})
			if len(toolPatterns) == 0 {
				fmt.Printf("%s: allow-list cleared (writ authority still binds)\n", args[0])
			} else {
				fmt.Printf("%s: allow-list set to %s\n", args[0], strings.Join(toolPatterns, ", "))
			}
			return nil
		},
	}
	allow.Flags().StringSliceVar(&toolPatterns, "tool", nil,
		"allowed tool pattern (repeatable; empty clears; '!none' denies all)")

	var newOwner string
	transfer := &cobra.Command{
		Use:   "transfer <name>",
		Short: "Transfer ownership — the only exit from orphaned (RFC-007)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			a, err := e.st.GetAgentByName(args[0])
			if err != nil {
				return err
			}
			if err := e.st.TransferOwner(args[0], newOwner); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "agent.transfer", AgentID: a.ID,
				Reason: fmt.Sprintf("from=%s to=%s", a.Owner, newOwner)})
			fmt.Printf("%s ownership transferred to %s\n", args[0], newOwner)
			return nil
		},
	}
	transfer.Flags().StringVar(&newOwner, "owner", "", "new accountable owner principal (required)")
	transfer.MarkFlagRequired("owner")

	var spWrit, spBlock, spParent, spTemplate, spPrompt, spConfig, spTools, spModel string
	var spCaps []string
	var spTTL time.Duration
	spawn := &cobra.Command{
		Use:   "spawn <name>",
		Short: "Spawn an ephemeral agent at runtime, writ-gated by admin:spawn/<template> (RFC-012)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			child, blockID, err := e.svc.SpawnAgent(spWrit, spBlock, spParent, spTemplate,
				args[0], spCaps, spTTL, hashArg(spPrompt), hashArg(spConfig), hashArg(spTools), spModel)
			if err != nil {
				return err
			}
			fmt.Printf("spawned %s\n  owner     %s (inherited from %s)\n  template  %s\n  expires   %s\n  block     %s (writ %s)\n",
				e.iss.SubjectURI(child.Name), child.Owner, child.SpawnedBy, child.Template,
				child.ExpiresAt.Format(time.RFC3339), blockID, spWrit)
			return nil
		},
	}
	spawn.Flags().StringVar(&spWrit, "writ", "", "the spawning agent's writ id (required)")
	spawn.Flags().StringVar(&spBlock, "block", "", "the spawning agent's block (default: its own block on the writ)")
	spawn.Flags().StringVar(&spParent, "agent", "", "the spawning (parent) agent name (required)")
	spawn.Flags().StringVar(&spTemplate, "template", "", "pre-approved template to spawn from (required)")
	spawn.Flags().StringSliceVar(&spCaps, "cap", nil, "capability for the child (repeatable; default: full template ceiling)")
	spawn.Flags().DurationVar(&spTTL, "ttl", 0, "child lifetime (default: template max; may not exceed it)")
	spawn.Flags().StringVar(&spPrompt, "prompt", "", "child system prompt: file path or literal (hashed, never stored)")
	spawn.Flags().StringVar(&spConfig, "config", "", "child configuration: file path or literal (hashed, never stored)")
	spawn.Flags().StringVar(&spTools, "tools", "", "child tool manifest: file path or literal (hashed, never stored)")
	spawn.Flags().StringVar(&spModel, "model", "", "child model identifier")
	spawn.MarkFlagRequired("writ")
	spawn.MarkFlagRequired("agent")
	spawn.MarkFlagRequired("template")

	sweep := &cobra.Command{
		Use:   "sweep",
		Short: "Retire expired ephemeral agents (expiry already denies in-path; this is registry hygiene)",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			names, err := e.st.SweepExpired()
			if err != nil {
				return err
			}
			for _, n := range names {
				if a, err := e.st.GetAgentByName(n); err == nil {
					e.st.Audit(store.AuditEvent{Event: "agent.expired", AgentID: a.ID,
						Reason: "ephemeral ttl elapsed; retired by sweep"})
				}
				fmt.Printf("retired %s (expired)\n", n)
			}
			if len(names) == 0 {
				fmt.Println("nothing to sweep")
			}
			return nil
		},
	}

	cmd.AddCommand(register, version, list, describe, allow, transfer, spawn, sweep,
		state("suspend", "Suspend an agent (reversible)", store.StateSuspended),
		state("resume", "Reactivate a suspended agent", store.StateActive),
		state("retire", "Retire an agent — terminal, administrative end-of-life", store.StateRetired),
		state("orphan", "Mark an agent ownerless — blocks issuance until transfer", store.StateOrphaned),
		state("revoke", "Revoke an agent identity — terminal; kills all versions and instances", store.StateRevoked))
	return cmd
}

func templateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "template", Short: "Pre-approved shapes for runtime-spawned agents (RFC-012)"}

	var purpose string
	var maxCaps []string
	var maxTTL time.Duration
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Lock a spawn ceiling: max capabilities and max lifetime for agents spawned from it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			t, err := e.svc.CreateTemplate(args[0], purpose, maxCaps, maxTTL)
			if err != nil {
				return err
			}
			fmt.Printf("template %s\n  max caps  %s\n  max ttl   %s\n  spawn cap %s\n",
				t.Name, strings.Join(t.MaxCaps, ", "), t.MaxTTL, "admin:spawn/"+t.Name)
			return nil
		},
	}
	create.Flags().StringVar(&purpose, "purpose", "", "purpose stamped on every agent spawned from this template")
	create.Flags().StringSliceVar(&maxCaps, "max-cap", nil, "capability ceiling (repeatable, required)")
	create.Flags().DurationVar(&maxTTL, "max-ttl", 0, "maximum lifetime of a spawned agent (required)")
	create.MarkFlagRequired("max-cap")
	create.MarkFlagRequired("max-ttl")

	list := &cobra.Command{
		Use:   "list",
		Short: "List spawn templates",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			templates, err := e.st.ListTemplates()
			if err != nil {
				return err
			}
			rows := [][]string{{"NAME", "MAX TTL", "MAX CAPS", "PURPOSE"}}
			for _, t := range templates {
				rows = append(rows, []string{t.Name, t.MaxTTL.String(),
					strings.Join(t.MaxCaps, ","), t.Purpose})
			}
			table(rows)
			return nil
		},
	}

	cmd.AddCommand(create, list)
	return cmd
}

func instanceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "instance", Short: "Manage runtime instances (RFC-001)"}

	var agentName string
	var ttl time.Duration
	start := &cobra.Command{
		Use:   "start",
		Short: "Register an instance and issue its first identity document",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			in, tok, err := e.svc.StartInstance(agentName, ttl)
			if err != nil {
				return err
			}
			fmt.Printf("instance %s of %s\nidentity document (ttl %s):\n%s\n",
				in.ID, e.iss.SubjectURI(agentName), max(ttl, identity.DefaultTTL), tok)
			return nil
		},
	}
	start.Flags().StringVar(&agentName, "agent", "", "agent name (required)")
	start.Flags().DurationVar(&ttl, "ttl", 0, "document ttl (default 5m, max 60m)")
	start.MarkFlagRequired("agent")

	revoke := &cobra.Command{
		Use:   "revoke <instance-id>",
		Short: "Revoke a single runaway instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			if err := e.st.RevokeInstance(args[0]); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "instance.revoke", Instance: args[0]})
			fmt.Printf("instance %s revoked — takes effect on the next in-path check\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(start, revoke)
	return cmd
}

func tokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Work with identity documents"}
	verify := &cobra.Command{
		Use:   "verify <jwt>",
		Short: "Verify an identity document: signature, expiry, AND registry state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			doc, err := e.iss.Verify(args[0])
			if err != nil {
				return err
			}
			// A valid signature is necessary, never sufficient: the
			// registry is checked in-path (RFC-001 §4).
			if _, _, _, err := e.st.CheckIssuable(doc.Instance); err != nil {
				return fmt.Errorf("document cryptographically valid but REFUSED by registry: %w", err)
			}
			fmt.Printf("VALID\n  subject   %s\n  version   %s\n  instance  %s\n  owner     %s\n  expires   %s\n",
				doc.Subject, doc.Version, doc.Instance, doc.Owner, doc.Expires.Format(time.RFC3339))
			return nil
		},
	}
	cmd.AddCommand(verify)
	return cmd
}

func writCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "writ", Short: "Manage writs — delegated, attenuating authority (RFC-002)"}

	var forP, toAgent, task string
	var capStrs []string
	var ttl time.Duration
	var maxDepth int
	grant := &cobra.Command{
		Use:   "grant",
		Short: "Mint a writ: block-0 capability grant to an agent, under a named authority",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			wid, rootBlockID, err := e.svc.GrantWrit(forP, toAgent, capStrs, ttl, maxDepth, task)
			if err != nil {
				return err
			}
			fmt.Printf("writ %s\n  for    %s\n  to     %s\n  block  %s\n  caps   %s\n  expires %s\n",
				wid, forP, e.iss.SubjectURI(toAgent), rootBlockID,
				strings.Join(capStrs, ", "), time.Now().UTC().Add(ttl).Format(time.RFC3339))
			if task != "" {
				fmt.Printf("  task   %s\n", task)
			}
			return nil
		},
	}
	grant.Flags().StringVar(&forP, "for", "", "authority source, e.g. user:aneesh@acme.com (required)")
	grant.Flags().StringVar(&toAgent, "to", "", "agent name (required)")
	grant.Flags().StringSliceVar(&capStrs, "cap", nil, "capability verb:resource (repeatable, required)")
	grant.Flags().DurationVar(&ttl, "ttl", time.Hour, "writ lifetime")
	grant.Flags().IntVar(&maxDepth, "max-depth", writ.DefaultMaxDepth, "max delegation depth")
	grant.Flags().StringVar(&task, "task", "", "declared purpose of the grant (RFC-017; handed to intent checkers)")
	grant.MarkFlagRequired("for")
	grant.MarkFlagRequired("to")
	grant.MarkFlagRequired("cap")

	var childAgent, parentBlock string
	var caveatStrs []string
	var dTTL time.Duration
	delegate := &cobra.Command{
		Use:   "delegate <writ-id>",
		Short: "Append a caveat block for a child agent — authority can only narrow",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			blockID, lineage, err := e.svc.DelegateWrit(args[0], parentBlock, childAgent, caveatStrs, dTTL)
			if err != nil {
				return err
			}
			fmt.Printf("delegated to %s\n  block   %s (depth %d)\n  lineage %s\n",
				e.iss.SubjectURI(childAgent), blockID, len(lineage)-2,
				strings.Join(lineage, " -> "))
			return nil
		},
	}
	delegate.Flags().StringVar(&childAgent, "to", "", "child agent name (required)")
	delegate.Flags().StringSliceVar(&caveatStrs, "caveat", nil, "caveat verb:resource (repeatable; restrictions only)")
	delegate.Flags().DurationVar(&dTTL, "ttl", 30*time.Minute, "child block lifetime (≤ parent)")
	delegate.Flags().StringVar(&parentBlock, "parent-block", "", "parent block id (default: writ's latest block)")
	delegate.MarkFlagRequired("to")

	show := &cobra.Command{
		Use:   "show <writ-id>",
		Short: "Render the delegation tree — the lineage record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			meta, err := e.st.GetWrit(args[0])
			if err != nil {
				return err
			}
			blocks, err := e.st.Tree(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("writ %s [%s]\n  for %s\n  expires %s\n\n",
				meta.ID, meta.State, meta.ForPrincipal, meta.Exp.Format(time.RFC3339))
			children := map[string][]store.WritBlock{}
			var root store.WritBlock
			for _, b := range blocks {
				if b.ParentID == nil {
					root = b
				} else {
					children[*b.ParentID] = append(children[*b.ParentID], b)
				}
			}
			var render func(b store.WritBlock, indent string)
			render = func(b store.WritBlock, indent string) {
				mark := ""
				if b.RevokedAt != nil {
					mark = "  [REVOKED — subtree dead]"
				}
				fmt.Printf("%s%s  (block %s, exp %s)%s\n", indent, b.ToAgent, b.ID,
					b.Exp.Format("15:04:05"), mark)
				for _, c := range children[b.ID] {
					render(c, indent+"    ")
				}
			}
			render(root, "  ")
			return nil
		},
	}

	var verb, resource, atBlock string
	check := &cobra.Command{
		Use:   "check <writ-id>",
		Short: "Evaluate an action against a writ's effective authority (in-path check)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			d := e.svc.CheckAction(args[0], atBlock, verb, resource)
			if d.Effect != policy.Allow {
				fmt.Printf("DENY  %s:%s\n  reason: [%s] %s\n", verb, resource, d.Layer, d.Reason)
				return nil
			}
			fmt.Printf("ALLOW  %s:%s\n  %s\n", verb, resource, d.Reason)
			return nil
		},
	}
	check.Flags().StringVar(&verb, "verb", "call", "action verb")
	check.Flags().StringVar(&resource, "resource", "", "action resource (required)")
	check.Flags().StringVar(&atBlock, "block", "", "acting block id (default: writ's latest block)")
	check.MarkFlagRequired("resource")

	var revokeBlock string
	revoke := &cobra.Command{
		Use:   "revoke <writ-id>",
		Short: "Revoke a writ, or one block's subtree with --block",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			if revokeBlock != "" {
				if err := e.st.RevokeWritBlock(revokeBlock); err != nil {
					return err
				}
				e.st.Audit(store.AuditEvent{Event: "writ.revoke_block", WritID: args[0],
					Reason: "block=" + revokeBlock})
				fmt.Printf("block %s revoked — subtree dead on next in-path check\n", revokeBlock)
				return nil
			}
			if err := e.st.RevokeWrit(args[0]); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "writ.revoke", WritID: args[0]})
			fmt.Printf("writ %s revoked — entire delegation tree dead on next in-path check\n", args[0])
			return nil
		},
	}
	revoke.Flags().StringVar(&revokeBlock, "block", "", "revoke only this block's subtree")

	list := &cobra.Command{
		Use:   "list",
		Short: "List writs",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			writs, err := e.st.ListWrits()
			if err != nil {
				return err
			}
			rows := [][]string{{"ID", "STATE", "FOR", "EXPIRES", "TTL LEFT"}}
			for _, w := range writs {
				rows = append(rows, []string{w.ID, w.State, w.ForPrincipal,
					w.Exp.Format(time.RFC3339), ttlLeft(w.State, w.Exp)})
			}
			table(rows)
			return nil
		},
	}

	example := &cobra.Command{
		Use:   "example",
		Short: "Print common capability patterns — the verb:resource grammar by example",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(`capabilities are verb:resource patterns; for a wrapped MCP server the
resource is <namespace>/<tool>, where the namespace comes from --server-name.

  call:github/*                every tool on the github server
  call:github/get_*            read-shaped tools only
  call:fs/read_file            exactly one tool
  net:github.com/*             URL guard: navigation on github.com (RFC-013)
  net:*.internal.acme.com/*    any subdomain, any path
  admin:spawn/researcher       may spawn agents from the researcher template (RFC-012)

grant reads:                   delegate narrows (never widens):
  chancery writ grant \          chancery writ delegate <writ-id> \
    --for user:you@acme.com \      --to test-runner \
    --to deploy-bot \              --caveat "call:github/get_*"
    --cap "call:github/*" \
    --ttl 8h --task "review PR #123"

check without calling:  chancery writ check <writ-id> --resource github/get_pull_request
preflight a wrap:       chancery mcp wrap --agent <a> --writ <id> --dry-run -- <server-cmd>
`)
			return nil
		},
	}

	cmd.AddCommand(grant, delegate, show, check, revoke, list, example)
	return cmd
}

// ttlLeft humanizes a writ's remaining lifetime for `writ list` —
// "what's about to expire" shouldn't require timestamp arithmetic.
func ttlLeft(state string, exp time.Time) string {
	if state != "active" {
		return "-"
	}
	d := time.Until(exp)
	if d <= 0 {
		return "expired"
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

func serveCmd() *cobra.Command {
	var listen string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the control-plane HTTP API (RFC-008)",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			tokenHash, err := e.st.GetConfig("admin_token_hash")
			if err != nil {
				return fmt.Errorf("no admin token — re-run `chancery init` (pre-alpha state upgrade)")
			}
			srv := &api.Server{
				Svc:            &service.Service{St: e.st, Iss: e.iss},
				AdminTokenHash: tokenHash,
			}
			fmt.Printf("chancery control plane listening on %s (TLS termination is on you — bind stays local by default)\n", listen)
			return http.ListenAndServe(listen, srv.Handler())
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:7423", "listen address")
	return cmd
}

func mcpCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "mcp", Short: "Runtime enforcement for MCP servers (RFC-005)"}

	var agentName, writID, blockID, serverName string
	var secretMaps, secretFileMaps []string
	var netGuard bool
	var intentCheck, intentMode string
	var intentTimeout time.Duration
	var lease bool
	var pinTree string
	var confineOn, dryRun bool
	var egressHosts, writablePaths []string
	wrap := &cobra.Command{
		Use:   "wrap --agent <name> --writ <id> -- <server command> [args...]",
		Short: "Run an MCP server behind Chancery: per-call policy, audit, sealed secrets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()

			a, err := e.st.GetAgentByName(agentName)
			if err != nil {
				return err
			}
			if a.State != store.StateActive {
				// A refused start is still an event worth recording — a
				// revoked agent trying to open a session is exactly what an
				// operator wants to see (finding #2).
				e.st.Audit(store.AuditEvent{Event: "mcp.wrap_refused", AgentID: a.ID, WritID: writID,
					Reason: fmt.Sprintf("agent %s is %s", a.Name, a.State)})
				return fmt.Errorf("agent %s is %s: refusing to start (fail closed)", a.Name, a.State)
			}
			// Select the block that actually carries THIS agent's authority
			// (finding #1): the writ's latest block may belong to a
			// delegated sub-agent. If --block was given, verify it is the
			// agent's; otherwise find the agent's block on the writ.
			subject := e.iss.SubjectURI(a.Name)
			leaf := blockID
			if leaf == "" {
				b, err := e.st.BlockForSubject(writID, subject)
				if err != nil {
					return fmt.Errorf("%w — grant a writ to %s, or pass --block explicitly", err, a.Name)
				}
				leaf = b.ID
			} else {
				b, err := e.st.Path(leaf) // validates + loads
				if err != nil {
					return err
				}
				if b[len(b)-1].ToAgent != subject {
					return fmt.Errorf("block %s belongs to %s, not --agent %s",
						leaf, b[len(b)-1].ToAgent, a.Name)
				}
			}
			v, err := e.st.LatestVersion(a.ID)
			if err != nil {
				return err
			}
			if serverName == "" {
				serverName = filepath.Base(args[0])
			}
			// Server pinning (RFC-016): the wrap owns the spawn, so it
			// verifies WHAT it is spawning — by the strongest applicable
			// tier (T3 image digest > T2 --pin-tree > T1 binary hash).
			// First wrap records the identity; every later wrap
			// re-verifies and refuses on drift — fail closed, audited.
			// Deliberate upgrades go through `chancery mcp repin`.
			pin, pinErr := e.st.GetServerPin(serverName)
			if pinErr != nil && !errors.Is(pinErr, store.ErrNotFound) {
				return pinErr
			}
			// A tree pin follows the namespace: once pinned as a tree
			// (`mcp install` or --pin-tree), plain wraps re-verify the
			// stored tree — forgetting the flag must not silently
			// degrade the tier to a binary hash.
			if pin != nil && pin.Kind == store.PinTree && pinTree == "" {
				pinTree = pin.Path
			}
			pinKind, pinPath, pinSHA, err := resolvePinIdentity(args, pinTree)
			if err != nil {
				return fmt.Errorf("cannot resolve server identity: %w", err)
			}
			if dryRun {
				return printPreflight(e, a.Name, writID, leaf, serverName, pin, pinKind, pinSHA, confineOn)
			}
			if pin != nil {
				// The manifest describes pinned code; changing it on a
				// live pin is a deliberate, audited operator action.
				if len(egressHosts) > 0 || len(writablePaths) > 0 {
					return fmt.Errorf("%s is already pinned — manifest changes are deliberate: run `chancery mcp repin %s --egress/--writable ... -- <cmd>`",
						serverName, serverName)
				}
				if pin.Kind != pinKind || pin.SHA256 != pinSHA {
					e.st.Audit(store.AuditEvent{Event: "mcp.server_drift", AgentID: a.ID,
						WritID: writID, Resource: serverName, Decision: "DENY",
						Reason: fmt.Sprintf("pinned=%s found=%s path=%s — refuse to start; `chancery mcp repin %s -- <cmd>` after a deliberate upgrade",
							pinDescribe(pin.Kind, pin.SHA256), pinDescribe(pinKind, pinSHA), pinPath, serverName)})
					repinHint := "chancery mcp repin " + serverName
					if pinTree != "" {
						repinHint += " --pin-tree " + pinTree
					}
					return fmt.Errorf("server %q drifted from its pin (pinned %s…, found %s…): refusing to start (fail closed) — after a deliberate upgrade run: %s -- %s",
						serverName, pinDescribe(pin.Kind, pin.SHA256), pinDescribe(pinKind, pinSHA), repinHint, strings.Join(args, " "))
				}
			} else {
				if err := e.st.SetServerPin(serverName, pinKind, pinPath, pinSHA); err != nil {
					return err
				}
				if len(egressHosts) > 0 || len(writablePaths) > 0 {
					if err := e.st.SetServerManifest(serverName, egressHosts, writablePaths); err != nil {
						return err
					}
				}
				e.st.Audit(store.AuditEvent{Event: "mcp.server_pin", AgentID: a.ID,
					Resource: serverName, Reason: fmt.Sprintf("%s path=%s egress=%s writable=%s",
						pinDescribe(pinKind, pinSHA), pinPath,
						strings.Join(egressHosts, ","), strings.Join(writablePaths, ","))})
				if pin, err = e.st.GetServerPin(serverName); err != nil {
					return err
				}
			}
			// The wrapped session is a runtime instance (RFC-001):
			// `chancery instance revoke` kills it on its next call.
			inst, err := e.st.CreateInstance(a.ID, v.ID, "declared", "mcp-wrap")
			if err != nil {
				return err
			}

			// Scrubbed child env: baseline + sealed secrets only. The
			// agent-side process tree never holds a real credential.
			childEnv := []string{}
			for _, k := range []string{"PATH", "HOME", "TMPDIR", "LANG"} {
				if val := os.Getenv(k); val != "" {
					childEnv = append(childEnv, k+"="+val)
				}
			}
			if len(secretMaps) > 0 || len(secretFileMaps) > 0 {
				ss, err := seal.Open(dataDir)
				if err != nil {
					return err
				}
				for _, m := range secretMaps {
					envVar, name, ok := strings.Cut(m, "=")
					if !ok {
						return fmt.Errorf("--secret %q is not ENV_VAR=sealed-name", m)
					}
					val, err := ss.Get(name)
					if err != nil {
						return fmt.Errorf("refusing to start: %w", err)
					}
					childEnv = append(childEnv, envVar+"="+val)
				}
				// Sealed FILE injection (RFC-013): session material —
				// e.g. a browser storage-state with cookies — is
				// materialized 0600 in a private run dir the SERVER
				// reads; the agent-side context never sees it. The dir
				// is shredded when the session ends.
				if len(secretFileMaps) > 0 {
					runDir, err := os.MkdirTemp("", "chancery-run-")
					if err != nil {
						return err
					}
					defer os.RemoveAll(runDir)
					for _, m := range secretFileMaps {
						key, name, ok := strings.Cut(m, "=")
						if !ok {
							return fmt.Errorf("--secret-file %q is not NAME=sealed-name", m)
						}
						val, err := ss.Get(name)
						if err != nil {
							return fmt.Errorf("refusing to start: %w", err)
						}
						fpath := filepath.Join(runDir, key)
						if err := os.WriteFile(fpath, []byte(val), 0o600); err != nil {
							return err
						}
						childEnv = append(childEnv, key+"="+fpath)
						// Server args may reference the file as
						// chancery-file:NAME (e.g. --storage-state=chancery-file:STATE).
						for i := range args {
							args[i] = strings.ReplaceAll(args[i], "chancery-file:"+key, fpath)
						}
					}
				}
			}

			// Confinement (RFC-018): the pin's manifest becomes an OS
			// boundary — loopback-only egress through an auditing
			// allow-list proxy, read-only filesystem outside the
			// declared writable paths. Refused-and-audited when the OS
			// layer is unavailable; never silently unconfined.
			if confineOn {
				cargs, cenv, cleanup, cerr := applyConfinement(pin.Egress, pin.Writable, args, childEnv,
					func(host string) {
						e.st.Audit(store.AuditEvent{Event: "mcp.server_egress_denied",
							AgentID: a.ID, Instance: inst.ID, WritID: writID,
							Verb: "net", Resource: host, Decision: "DENY",
							Reason: fmt.Sprintf("host not in %s manifest (repin --egress to change)", serverName)})
					})
				if cerr != nil {
					e.st.Audit(store.AuditEvent{Event: "mcp.confine_refused", AgentID: a.ID,
						Instance: inst.ID, Resource: serverName, Decision: "DENY", Reason: cerr.Error()})
					return cerr
				}
				defer cleanup()
				args, childEnv = cargs, cenv
			}

			server := exec.Command(args[0], args[1:]...)
			server.Env = childEnv
			server.Stderr = os.Stderr
			serverIn, err := server.StdinPipe()
			if err != nil {
				return err
			}
			serverOut, err := server.StdoutPipe()
			if err != nil {
				return err
			}
			if err := server.Start(); err != nil {
				return err
			}

			audit := func(event, tool, decision, reason string) error {
				verb := "call"
				if event == "mcp.net" {
					verb = "net"
				}
				return e.st.Audit(store.AuditEvent{Event: event, AgentID: a.ID, Instance: inst.ID,
					WritID: writID, Verb: verb, Resource: tool, Decision: decision, Reason: reason})
			}
			audit("mcp.wrap_start", serverName, "", fmt.Sprintf("cmd=%s writ=%s", args[0], writID))

			// The decider re-reads registry state per call: revocation of
			// the agent, version, instance, writ, or any block on the
			// path takes effect on the NEXT tool call, not the next TTL.
			decide := func(resource string) policy.Decision {
				// Instance liveness is the PEP-specific gate (a wrapped
				// session is a runtime instance); the writ/policy decision
				// is the shared service-layer path.
				if _, _, _, err := e.st.CheckIssuable(inst.ID); err != nil {
					return policy.Decision{Effect: policy.Deny, Layer: "registry", Reason: err.Error()}
				}
				return e.svc.Decide(writID, leaf, "call", resource)
			}

			p := &mcp.Proxy{
				ClientIn: os.Stdin, ClientOut: os.Stdout,
				ServerIn: serverIn, ServerOut: serverOut,
				Server: serverName, Decide: decide, Audit: audit,
			}
			// URL guard (RFC-013): granting net:… on the writ IS the
			// opt-in — every url/uri argument is then checked as
			// net:<host>/<path> per call. --net-guard forces it on
			// (a writ with no net caps then denies all navigation).
			if netGuard || e.svc.GrantsVerb(writID, leaf, "net") {
				p.NetDecide = func(resource string) policy.Decision {
					if _, _, _, err := e.st.CheckIssuable(inst.ID); err != nil {
						return policy.Decision{Effect: policy.Deny, Layer: "registry", Reason: err.Error()}
					}
					return e.svc.Decide(writID, leaf, "net", resource)
				}
			}
			// Intent socket (RFC-017): an external checker gets a veto
			// after the deterministic layers allow. It receives the
			// writ's declared task and the call's arguments (transient,
			// never stored).
			if intentCheck != "" {
				if intentMode != "enforce" && intentMode != "advise" {
					return fmt.Errorf("--intent-mode must be enforce or advise, got %q", intentMode)
				}
				wmeta, err := e.st.GetWrit(writID)
				if err != nil {
					return err
				}
				checker := &mcp.IntentChecker{Cmd: intentCheck, Timeout: intentTimeout,
					Agent: a.Name, Task: wmeta.Task}
				p.Intent = checker.Decide
				p.IntentAdvise = intentMode == "advise"
			}
			// Capability leases (RFC-015): stamp each admitted call so a
			// cooperating server can verify liveness right before the
			// side effect commits (POST /v1/leases/verify).
			if lease {
				p.Lease = func(resource string) (string, error) {
					return e.svc.MintLease(writID, leaf, a.Name, resource)
				}
			}
			runErr := p.Run()
			serverIn.Close()
			waitErr := server.Wait()
			audit("mcp.server_exit", serverName, "", fmt.Sprintf("proxy=%v server=%v", runErr, waitErr))
			if waitErr != nil {
				return fmt.Errorf("mcp server exited: %w", waitErr)
			}
			return runErr
		},
	}
	wrap.Flags().StringVar(&agentName, "agent", "", "acting agent name (required)")
	wrap.Flags().StringVar(&writID, "writ", "", "writ id carrying the agent's authority (required)")
	wrap.Flags().StringVar(&blockID, "block", "", "acting writ block (default: writ's latest block)")
	wrap.Flags().StringVar(&serverName, "server-name", "", "resource namespace (default: server binary name)")
	wrap.Flags().StringSliceVar(&secretMaps, "secret", nil,
		"inject sealed secret into the SERVER env: ENV_VAR=sealed-name (repeatable)")
	wrap.Flags().StringSliceVar(&secretFileMaps, "secret-file", nil,
		"materialize sealed secret as a 0600 file for the SERVER: NAME=sealed-name; path in env NAME and as chancery-file:NAME in server args (repeatable)")
	wrap.Flags().BoolVar(&netGuard, "net-guard", false,
		"force the URL guard on (auto-enabled when the writ grants net:… capabilities)")
	wrap.Flags().StringVar(&intentCheck, "intent-check", "",
		"external intent checker: shell command (JSON on stdin) or http(s) URL (RFC-017)")
	wrap.Flags().StringVar(&intentMode, "intent-mode", "enforce",
		"intent checker mode: enforce (fail closed) or advise (log only)")
	wrap.Flags().DurationVar(&intentTimeout, "intent-timeout", time.Second,
		"per-call budget for the intent checker")
	wrap.Flags().BoolVar(&lease, "lease", false,
		"stamp admitted calls with a capability lease in params._meta (RFC-015; cooperating servers verify via POST /v1/leases/verify)")
	wrap.Flags().StringVar(&pinTree, "pin-tree", "",
		"pin the whole directory tree (RFC-016 T2): Merkle hash of every file; any change refuses to start")
	wrap.Flags().BoolVar(&confineOn, "confine", false,
		"apply the pin's confinement manifest as an OS boundary (RFC-018): egress allow-list proxy + read-only FS outside writable paths; refuses to spawn if unsupported")
	wrap.Flags().StringSliceVar(&egressHosts, "egress", nil,
		"confinement manifest, set on FIRST pin only: host the server may reach (repeatable; later changes via repin)")
	wrap.Flags().StringSliceVar(&writablePaths, "writable", nil,
		"confinement manifest, set on FIRST pin only: path the server may write (repeatable; later changes via repin)")
	wrap.Flags().BoolVar(&dryRun, "dry-run", false,
		"preflight only: print the effective authority, pin status, and manifest this wrap would enforce — spawn nothing, pin nothing")
	wrap.MarkFlagRequired("agent")
	wrap.MarkFlagRequired("writ")

	var repinTree string
	var repinEgress, repinWritable []string
	repin := &cobra.Command{
		Use:   "repin <namespace> -- <server command> [args...]",
		Short: "Re-pin a wrapped server after a deliberate upgrade (RFC-016) — explicit, audited",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			ns := args[0]
			kind, path, sha, err := resolvePinIdentity(args[1:], repinTree)
			if err != nil {
				return fmt.Errorf("cannot resolve server identity: %w", err)
			}
			old := "(none)"
			if pin, err := e.st.GetServerPin(ns); err == nil {
				old = pinDescribe(pin.Kind, pin.SHA256)
			}
			if err := e.st.SetServerPin(ns, kind, path, sha); err != nil {
				return err
			}
			// Manifest changes ride the same deliberate, audited path
			// as identity changes (RFC-018): passing the flag replaces
			// that list (an explicitly empty flag clears it); omitting
			// it leaves the stored manifest untouched.
			manifestNote := ""
			if cmd.Flags().Changed("egress") || cmd.Flags().Changed("writable") {
				pinNow, err := e.st.GetServerPin(ns)
				if err != nil {
					return err
				}
				eg, wr := pinNow.Egress, pinNow.Writable
				if cmd.Flags().Changed("egress") {
					eg = repinEgress
				}
				if cmd.Flags().Changed("writable") {
					wr = repinWritable
				}
				if err := e.st.SetServerManifest(ns, eg, wr); err != nil {
					return err
				}
				manifestNote = fmt.Sprintf(" egress=%s writable=%s", strings.Join(eg, ","), strings.Join(wr, ","))
			}
			e.st.Audit(store.AuditEvent{Event: "mcp.server_repin", Resource: ns,
				Reason: fmt.Sprintf("old=%s new=%s path=%s%s", old, pinDescribe(kind, sha), path, manifestNote)})
			fmt.Printf("repinned %s\n  path   %s\n  identity %s (was %s)%s\n", ns, path, pinDescribe(kind, sha), old, manifestNote)
			return nil
		},
	}
	repin.Flags().StringVar(&repinTree, "pin-tree", "",
		"re-pin as a directory tree (RFC-016 T2)")
	repin.Flags().StringSliceVar(&repinEgress, "egress", nil,
		"replace the confinement manifest's egress hosts (RFC-018; pass an empty value to clear)")
	repin.Flags().StringSliceVar(&repinWritable, "writable", nil,
		"replace the confinement manifest's writable paths (RFC-018; pass an empty value to clear)")

	cmd.AddCommand(wrap, repin)
	installCmd(cmd)
	return cmd
}

// printPreflight renders `mcp wrap --dry-run` (RFC-018; asked for by
// the first outside integrator): everything this wrap would enforce,
// with nothing spawned and nothing pinned.
func printPreflight(e *env, agentName, writID, leaf, serverName string,
	pin *store.ServerPin, foundKind, foundSHA string, confineOn bool) error {
	grant, caveats, err := e.svc.EffectiveAuthority(writID, leaf)
	if err != nil {
		return err
	}
	a, err := e.st.GetAgentByName(agentName)
	if err != nil {
		return err
	}
	allowlist, _ := e.st.GetAllowlist(a.ID)
	fmt.Printf("dry run — nothing spawned, nothing pinned\n")
	fmt.Printf("  agent      %s (%s)\n  writ       %s  block %s\n", agentName, a.State, writID, leaf)
	fmt.Printf("  grant      %s\n", strings.Join(grant, ", "))
	for i, cs := range caveats {
		fmt.Printf("  caveats    block %d: %s\n", i+1, strings.Join(cs, ", "))
	}
	if len(allowlist) > 0 {
		fmt.Printf("  allowlist  %s\n", strings.Join(allowlist, ", "))
	}
	fmt.Printf("  namespace  %s\n", serverName)
	switch {
	case pin == nil:
		fmt.Printf("  pin        (none — first real wrap would pin %s)\n", pinDescribe(foundKind, foundSHA))
	case pin.Kind != foundKind || pin.SHA256 != foundSHA:
		fmt.Printf("  pin        DRIFT: pinned %s, found %s — a real wrap would REFUSE to start\n",
			pinDescribe(pin.Kind, pin.SHA256), pinDescribe(foundKind, foundSHA))
	default:
		fmt.Printf("  pin        %s (matches)\n", pinDescribe(pin.Kind, pin.SHA256))
	}
	if pin != nil {
		fmt.Printf("  manifest   egress=[%s] writable=[%s] (--confine %s)\n",
			strings.Join(pin.Egress, ", "), strings.Join(pin.Writable, ", "),
			map[bool]string{true: "on", false: "off"}[confineOn])
	}
	fmt.Printf("\na tool T on this server is callable iff call:%s/T passes the authority above — per call, with fresh revocation state\n", serverName)
	return nil
}

func secretCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "secret", Short: "Manage sealed downstream credentials (RFC-003)"}

	var value, fromFile, kind string
	put := &cobra.Command{
		Use:   "put <name>",
		Short: "Seal a credential — agents never see it; rotation is re-running this",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			v := value
			if fromFile != "" {
				raw, err := os.ReadFile(fromFile)
				if err != nil {
					return err
				}
				v = strings.TrimRight(string(raw), "\n")
			}
			if v == "" {
				return fmt.Errorf("provide --value or --from-file")
			}
			ss, err := seal.Open(dataDir)
			if err != nil {
				return err
			}
			if err := ss.Put(args[0], kind, v); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "secret.put", Reason: "name=" + args[0] + " kind=" + kind})
			fmt.Printf("sealed %s (%s)\n", args[0], kind)
			return nil
		},
	}
	put.Flags().StringVar(&value, "value", "", "credential value (prefer --from-file)")
	put.Flags().StringVar(&fromFile, "from-file", "", "read value from file")
	put.Flags().StringVar(&kind, "kind", "static", "credential class")

	list := &cobra.Command{
		Use:   "list",
		Short: "List sealed credentials (names and kinds only — never values)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ss, err := seal.Open(dataDir)
			if err != nil {
				return err
			}
			metas, err := ss.List()
			if err != nil {
				return err
			}
			rows := [][]string{{"NAME", "KIND", "UPDATED"}}
			for _, m := range metas {
				rows = append(rows, []string{m.Name, m.Kind, m.UpdatedAt.Format(time.RFC3339)})
			}
			table(rows)
			return nil
		},
	}

	rm := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a sealed credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			ss, err := seal.Open(dataDir)
			if err != nil {
				return err
			}
			if err := ss.Delete(args[0]); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "secret.rm", Reason: "name=" + args[0]})
			fmt.Printf("deleted %s\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(put, list, rm)
	return cmd
}

// agentNameMap builds an agent-id -> name lookup so the audit view can
// show which agent an event belongs to (finding #3) — lifecycle events
// like agent.revoke carry an agent id but no writ/verb, so without this
// they render bare.
func agentNameMap(e *env) map[string]string {
	m := map[string]string{}
	if agents, err := e.st.ListAgents(); err == nil {
		for _, a := range agents {
			m[a.ID] = a.Name
		}
	}
	return m
}

func auditRow(ev store.AuditEvent, names map[string]string) []string {
	vr := ""
	if ev.Verb != "" {
		vr = ev.Verb + ":" + ev.Resource
	}
	return []string{ev.At.Format("15:04:05"), ev.Event, names[ev.AgentID], ev.Decision, vr, ev.WritID, ev.Reason}
}

// followAudit tails new events as they land (RFC-010 demo: ALLOW events
// scroll live, then the DENY appears the instant an agent is revoked).
// Polls the append cursor; exits cleanly on SIGINT.
func followAudit(e *env, cmd *cobra.Command) error {
	var cursor int64
	if latest, err := e.st.AuditTimeline(1); err == nil && len(latest) > 0 {
		cursor = latest[0].Seq
	}
	names := agentNameMap(e)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-sig:
			fmt.Fprintln(cmd.OutOrStdout())
			return nil
		case <-ticker.C:
			events, err := e.st.AuditSince(cursor)
			if err != nil {
				return err
			}
			for _, ev := range events {
				cursor = ev.Seq
				r := auditRow(ev, names)
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %-16s %-12s %-6s %-28s %s\n",
					r[0], r[1], r[2], r[3], r[4], r[6])
			}
		}
	}
}

func auditCmd() *cobra.Command {
	var limit int
	var asJSON, follow bool
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit timeline (metadata only, hash-chained)",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			events, err := e.st.AuditTimeline(limit)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				for _, ev := range events {
					if err := enc.Encode(ev); err != nil {
						return err
					}
				}
				return nil
			}
			names := agentNameMap(e)
			rows := [][]string{{"AT", "EVENT", "AGENT", "DECISION", "VERB:RESOURCE", "WRIT", "DETAIL"}}
			for _, ev := range events {
				rows = append(rows, auditRow(ev, names))
			}
			table(rows)
			if follow {
				return followAudit(e, cmd)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "max events")
	cmd.Flags().BoolVar(&asJSON, "json", false, "NDJSON export (SIEM bridge)")
	cmd.Flags().BoolVar(&follow, "follow", false, "stream new events as they occur (like tail -f)")

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit hash chain — detects edits, deletions, reorders",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := openEnv()
			if err != nil {
				return err
			}
			defer e.st.Close()
			n, err := e.st.VerifyAuditChain()
			if err != nil {
				return fmt.Errorf("INTEGRITY FAILURE after %d intact events: %w", n, err)
			}
			fmt.Printf("audit chain intact: %d events verified\n", n)
			return nil
		},
	}
	cmd.AddCommand(verify)
	return cmd
}
