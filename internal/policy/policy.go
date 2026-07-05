// Package policy owns the capability grammar and the layered PDP
// (RFC-004). The grammar is shared by writ grants, writ caveats, and
// agent allow-lists: one implementation, one truth. Layer 1 (the writ)
// grants; every other layer can only deny. Default-deny throughout.
package policy

import (
	"fmt"
	"strings"
)

// Verbs is the locked verb registry (RFC-004 §4, extended by RFC-012).
// call is the MVP verb; read/write/exec/net are reserved for the
// HTTP/shell/browser runtimes (RFC-005); admin governs control-plane
// self-service actions such as spawning agents (RFC-012).
var Verbs = map[string]bool{"call": true, "read": true, "write": true, "exec": true, "net": true, "admin": true}

// DenyAll is the explicit deny-all allow-list sentinel: an empty
// allow-list means "no additional restriction", never deny-all.
const DenyAll = "!none"

// Cap is a capability or caveat pattern: a verb and a resource pattern.
type Cap struct {
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
}

func (c Cap) String() string { return c.Verb + ":" + c.Resource }

// ParseCap parses and validates "verb:resource-pattern".
func ParseCap(s string) (Cap, error) {
	verb, resource, ok := strings.Cut(s, ":")
	if !ok || verb == "" || resource == "" {
		return Cap{}, fmt.Errorf("policy: capability %q is not verb:resource", s)
	}
	c := Cap{Verb: verb, Resource: resource}
	return c, c.Validate()
}

func (c Cap) Validate() error {
	if c.Verb != "*" && !Verbs[c.Verb] {
		return fmt.Errorf("policy: unknown verb %q (registry: call, read, write, exec, net, admin, *)", c.Verb)
	}
	return ValidateResourcePattern(c.Resource)
}

// ValidateResourcePattern enforces the locked grammar (RFC-004 §4):
// '/'-separated segments of [a-z0-9_.-]+; '*' only as the final
// character; no mid-pattern wildcards, no regex. Invalid patterns are
// rejected at write time, never silently at check time.
func ValidateResourcePattern(p string) error {
	if p == "*" {
		return nil
	}
	body, wild := strings.CutSuffix(p, "*")
	if strings.Contains(body, "*") {
		return fmt.Errorf("policy: pattern %q: '*' is only valid as the final character", p)
	}
	if wild && body == "" {
		return nil // bare "*" handled above; "" here is unreachable, kept for clarity
	}
	segments := strings.Split(body, "/")
	for i, seg := range segments {
		// The final segment may be empty when the pattern ends "/*"
		// (subtree match) — every other segment must be non-empty.
		if seg == "" && !(wild && i == len(segments)-1) {
			return fmt.Errorf("policy: pattern %q has an empty segment", p)
		}
		for _, r := range seg {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
				return fmt.Errorf("policy: pattern %q: segment %q contains %q (allowed: [a-z0-9_.-])", p, seg, r)
			}
		}
	}
	return nil
}

// ValidateResource checks a concrete (non-pattern) resource.
func ValidateResource(r string) error {
	if strings.Contains(r, "*") {
		return fmt.Errorf("policy: resource %q may not contain '*'", r)
	}
	return ValidateResourcePattern(r)
}

// Matches reports whether the pattern admits the concrete action.
// Semantics (RFC-004 §4): a prefix ending in "/" matches the whole
// subtree; otherwise the wildcard stays within the final segment
// ("github/get_*" matches "github/get_repo" but not "github/get_x/y").
func (c Cap) Matches(verb, resource string) bool {
	if c.Verb != "*" && c.Verb != verb {
		return false
	}
	return MatchResource(c.Resource, resource)
}

func MatchResource(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	if prefix, wild := strings.CutSuffix(pattern, "*"); wild {
		if !strings.HasPrefix(resource, prefix) {
			return false
		}
		if strings.HasSuffix(prefix, "/") {
			return true // subtree match
		}
		return !strings.Contains(resource[len(prefix):], "/")
	}
	return pattern == resource
}

// Implies reports whether c subsumes o: every action o admits, c also
// admits. Used for template ceilings (RFC-012 §4): a spawn request's
// capability must be implied by some template max-cap. Strict — when in
// doubt, false (deny).
func (c Cap) Implies(o Cap) bool {
	if c.Verb != "*" && c.Verb != o.Verb {
		return false
	}
	return PatternImplies(c.Resource, o.Resource)
}

// PatternImplies reports whether pattern a admits every resource that
// pattern b admits.
func PatternImplies(a, b string) bool {
	if a == "*" {
		return true
	}
	if b == "*" {
		return false
	}
	ap, aw := strings.CutSuffix(a, "*")
	bp, _ := strings.CutSuffix(b, "*")
	if !aw {
		// A concrete pattern implies only itself.
		return a == b
	}
	if !strings.HasPrefix(bp, ap) {
		return false
	}
	if strings.HasSuffix(ap, "/") {
		return true // subtree wildcard covers everything below the prefix
	}
	// Final-segment wildcard: b must stay within a's final segment.
	return !strings.Contains(bp[len(ap):], "/")
}

// Overlaps reports whether two patterns can admit at least one common
// action — used to refuse null-authority delegations at append time
// (RFC-002 §7). Conservative in the caller's favor: prefix-compatible
// patterns are treated as overlapping.
func (c Cap) Overlaps(o Cap) bool {
	if c.Verb != "*" && o.Verb != "*" && c.Verb != o.Verb {
		return false
	}
	cp, cw := strings.CutSuffix(c.Resource, "*")
	op, ow := strings.CutSuffix(o.Resource, "*")
	switch {
	case cw && ow:
		return strings.HasPrefix(cp, op) || strings.HasPrefix(op, cp)
	case cw:
		return strings.HasPrefix(o.Resource, cp)
	case ow:
		return strings.HasPrefix(c.Resource, op)
	default:
		return c.Resource == o.Resource
	}
}

// --- the PDP (RFC-004 §4) ---

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
	// Hold is reserved for human-approval flows (L4, v1). No MVP code
	// path produces it; the enum exists so PEPs handle it from day one.
	Hold Effect = "hold"
)

type Decision struct {
	Effect Effect
	Layer  string // which layer decided: "writ", "allowlist", "grammar"
	Reason string
}

// Authority is what grants: in practice, a verified *writ.Writ.
// Only this layer can say yes; all others can only say no.
type Authority interface {
	Check(verb, resource string) bool
	Lineage() []string
}

// Decide conjoins the layers for one concrete action. allowlist is the
// acting agent's tool allow-list: empty = no additional restriction,
// containing DenyAll = deny everything.
func Decide(auth Authority, allowlist []string, verb, resource string) Decision {
	if err := ValidateResource(resource); err != nil {
		return Decision{Deny, "grammar", err.Error()}
	}
	if !Verbs[verb] {
		return Decision{Deny, "grammar", fmt.Sprintf("unknown verb %q", verb)}
	}
	// L1 — delegated authority: the only layer that grants.
	if auth == nil || !auth.Check(verb, resource) {
		return Decision{Deny, "writ", "outside effective authority (grant ∩ caveats)"}
	}
	// L2 — per-agent allow-list: subtractive only.
	if len(allowlist) > 0 {
		ok := false
		for _, p := range allowlist {
			if p == DenyAll {
				return Decision{Deny, "allowlist", "agent allow-list is " + DenyAll}
			}
			if MatchResource(p, resource) {
				ok = true
			}
		}
		if !ok {
			return Decision{Deny, "allowlist", fmt.Sprintf("%s not in agent allow-list", resource)}
		}
	}
	// L3 (org policy / Cedar) and L4 (approvals) land in v1 behind this
	// same conjunction: they may only turn Allow into Deny or Hold.
	return Decision{Allow, "writ", "lineage " + strings.Join(auth.Lineage(), " -> ")}
}
