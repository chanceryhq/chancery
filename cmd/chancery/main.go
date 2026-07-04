// chancery is the CLI for the Chancery control plane: the registry of
// agent identities (RFC-001) and writs (RFC-002).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/chanceryhq/chancery/internal/identity"
	"github.com/chanceryhq/chancery/internal/policy"
	"github.com/chanceryhq/chancery/internal/seal"
	"github.com/chanceryhq/chancery/internal/store"
	"github.com/chanceryhq/chancery/internal/writ"
)

var dataDir string

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
	return &env{st: st, iss: iss}, nil
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
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&dataDir, "data-dir", defaultDataDir(), "state directory")

	root.AddCommand(initCmd(), agentCmd(), instanceCmd(), tokenCmd(), writCmd(), auditCmd(), secretCmd())

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
			fmt.Printf("initialized trust domain %s (issuer %s) in %s\n", trustDomain, issuerURL, dataDir)
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
			a, err := e.st.CreateAgent(args[0], owner, purpose)
			if err != nil {
				return err
			}
			v, err := e.st.CreateVersion(a.ID, hashArg(prompt), hashArg(config), hashArg(tools), model)
			if err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "agent.register", AgentID: a.ID,
				Reason: fmt.Sprintf("owner=%s version=%s", owner, v.Digest())})
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
			rows := [][]string{{"NAME", "STATE", "OWNER", "PURPOSE"}}
			for _, a := range agents {
				rows = append(rows, []string{a.Name, a.State, a.Owner, a.Purpose})
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
				fmt.Printf("%s is now %s — takes effect on the next in-path check\n", args[0], target)
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

	cmd.AddCommand(register, list, describe, allow,
		state("suspend", "Suspend an agent (reversible)", store.StateSuspended),
		state("resume", "Reactivate a suspended agent", store.StateActive),
		state("revoke", "Revoke an agent identity — kills all versions and instances", store.StateRevoked))
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
			a, err := e.st.GetAgentByName(agentName)
			if err != nil {
				return err
			}
			if a.State != store.StateActive {
				return fmt.Errorf("agent %s is %s: instance refused (fail closed)", a.Name, a.State)
			}
			v, err := e.st.LatestVersion(a.ID)
			if err != nil {
				return err
			}
			in, err := e.st.CreateInstance(a.ID, v.ID, "declared", "")
			if err != nil {
				return err
			}
			tok, err := e.iss.Issue(identity.IssueParams{
				AgentName: a.Name, VersionDigest: v.Digest(), InstanceID: in.ID,
				Owner: a.Owner, AttType: "declared", TTL: ttl,
			})
			if err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "instance.start", AgentID: a.ID, Instance: in.ID})
			fmt.Printf("instance %s of %s (version %s)\nidentity document (ttl %s):\n%s\n",
				in.ID, e.iss.SubjectURI(a.Name), v.Digest(), max(ttl, identity.DefaultTTL), tok)
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

	var forP, toAgent string
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
			a, err := e.st.GetAgentByName(toAgent)
			if err != nil {
				return err
			}
			v, err := e.st.LatestVersion(a.ID)
			if err != nil {
				return err
			}
			var caps []writ.Cap
			for _, s := range capStrs {
				c, err := writ.ParseCap(s)
				if err != nil {
					return err
				}
				caps = append(caps, c)
			}
			wid := "w_" + ulid.Make().String()
			exp := time.Now().UTC().Add(ttl)
			w, err := writ.Grant(wid, forP, e.iss.SubjectURI(a.Name), v.Digest(),
				caps, maxDepth, exp, e.iss.Key(), e.iss.KeyID())
			if err != nil {
				return err
			}
			rootBlockID := "b_" + ulid.Make().String()
			if err := e.st.CreateWrit(wid, forP, a.ID, maxDepth, exp,
				rootBlockID, w.JWS[0], e.iss.SubjectURI(a.Name)); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "writ.grant", AgentID: a.ID, WritID: wid,
				Reason: fmt.Sprintf("for=%s caps=%d", forP, len(caps))})
			fmt.Printf("writ %s\n  for    %s\n  to     %s (%s)\n  block  %s\n  caps   %s\n  expires %s\n",
				wid, forP, e.iss.SubjectURI(a.Name), v.Digest(), rootBlockID,
				strings.Join(capStrs, ", "), exp.Format(time.RFC3339))
			return nil
		},
	}
	grant.Flags().StringVar(&forP, "for", "", "authority source, e.g. user:aneesh@acme.com (required)")
	grant.Flags().StringVar(&toAgent, "to", "", "agent name (required)")
	grant.Flags().StringSliceVar(&capStrs, "cap", nil, "capability verb:resource (repeatable, required)")
	grant.Flags().DurationVar(&ttl, "ttl", time.Hour, "writ lifetime")
	grant.Flags().IntVar(&maxDepth, "max-depth", writ.DefaultMaxDepth, "max delegation depth")
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
			parent := parentBlock
			if parent == "" {
				b, err := e.st.LatestBlock(args[0])
				if err != nil {
					return err
				}
				parent = b.ID
			}
			path, err := e.st.Path(parent)
			if err != nil {
				return err
			}
			var jwsPath []string
			for _, b := range path {
				jwsPath = append(jwsPath, b.JWS)
			}
			w, err := writ.Verify(jwsPath, &e.iss.Key().PublicKey, time.Now())
			if err != nil {
				return err
			}
			child, err := e.st.GetAgentByName(childAgent)
			if err != nil {
				return err
			}
			if child.State != store.StateActive {
				return fmt.Errorf("child agent %s is %s: delegation refused", child.Name, child.State)
			}
			cv, err := e.st.LatestVersion(child.ID)
			if err != nil {
				return err
			}
			var caveats []writ.Cap
			for _, s := range caveatStrs {
				c, err := writ.ParseCap(s)
				if err != nil {
					return err
				}
				caveats = append(caveats, c)
			}
			exp := time.Now().UTC().Add(dTTL)
			nw, err := writ.Delegate(w, e.iss.SubjectURI(child.Name), cv.Digest(),
				caveats, exp, e.iss.Key(), e.iss.KeyID())
			if err != nil {
				return err
			}
			blockID := "b_" + ulid.Make().String()
			newJWS := nw.JWS[len(nw.JWS)-1]
			if err := e.st.AppendWritBlock(blockID, args[0], parent, len(nw.Blocks)-1,
				newJWS, e.iss.SubjectURI(child.Name), exp); err != nil {
				return err
			}
			e.st.Audit(store.AuditEvent{Event: "writ.delegate", AgentID: child.ID, WritID: args[0],
				Reason: fmt.Sprintf("parent_block=%s caveats=%d", parent, len(caveats))})
			fmt.Printf("delegated to %s\n  block   %s (depth %d)\n  lineage %s\n",
				e.iss.SubjectURI(child.Name), blockID, len(nw.Blocks)-1,
				strings.Join(nw.Lineage(), " -> "))
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
			leaf := atBlock
			if leaf == "" {
				b, err := e.st.LatestBlock(args[0])
				if err != nil {
					return err
				}
				leaf = b.ID
			}
			deny := func(reason string) error {
				e.st.Audit(store.AuditEvent{Event: "action.check", WritID: args[0],
					Verb: verb, Resource: resource, Decision: "DENY", Reason: reason})
				fmt.Printf("DENY  %s:%s\n  reason: %s\n", verb, resource, reason)
				return nil
			}
			path, err := e.st.Path(leaf)
			if err != nil {
				return deny(err.Error())
			}
			var jwsPath []string
			for _, b := range path {
				jwsPath = append(jwsPath, b.JWS)
			}
			w, err := writ.Verify(jwsPath, &e.iss.Key().PublicKey, time.Now())
			if err != nil {
				return deny(err.Error())
			}
			// The acting principal is the leaf block's agent; its
			// allow-list joins the PDP conjunction (RFC-004).
			var allowlist []string
			leafURI := w.Blocks[len(w.Blocks)-1].To
			if name, ok := strings.CutPrefix(leafURI, "spiffe://"+e.iss.TrustDomain+"/agent/"); ok {
				if a, err := e.st.GetAgentByName(name); err == nil {
					allowlist, _ = e.st.GetAllowlist(a.ID)
				}
			}
			d := policy.Decide(w, allowlist, verb, resource)
			if d.Effect != policy.Allow {
				return deny("[" + d.Layer + "] " + d.Reason)
			}
			e.st.Audit(store.AuditEvent{Event: "action.check", WritID: args[0],
				Verb: verb, Resource: resource, Decision: "ALLOW", Reason: d.Reason})
			fmt.Printf("ALLOW  %s:%s\n  lineage: %s\n", verb, resource, strings.Join(w.Lineage(), " -> "))
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
			rows := [][]string{{"ID", "STATE", "FOR", "EXPIRES"}}
			for _, w := range writs {
				rows = append(rows, []string{w.ID, w.State, w.ForPrincipal, w.Exp.Format(time.RFC3339)})
			}
			table(rows)
			return nil
		},
	}

	cmd.AddCommand(grant, delegate, show, check, revoke, list)
	return cmd
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

func auditCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit timeline (metadata only, by construction)",
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
			rows := [][]string{{"AT", "EVENT", "DECISION", "VERB:RESOURCE", "WRIT", "DETAIL"}}
			for _, ev := range events {
				vr := ""
				if ev.Verb != "" {
					vr = ev.Verb + ":" + ev.Resource
				}
				rows = append(rows, []string{ev.At.Format("15:04:05"), ev.Event, ev.Decision, vr,
					ev.WritID, ev.Reason})
			}
			table(rows)
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "max events")
	return cmd
}
