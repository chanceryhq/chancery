// Intent socket (RFC-017): an optional sixth decision layer consulted
// AFTER the deterministic layers pass. The checker is external —
// Chancery ships no semantic judgment. It is the only layer that sees
// tool arguments, which pass through transiently and are never stored;
// the audit records verdict and reason only. The checker can only
// narrow: its ALLOW cannot override a writ denial, because it is never
// consulted unless the writ already allowed.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/chanceryhq/chancery/internal/policy"
)

// Intent-layer names in Decision.Layer: "intent" is a checker verdict,
// "intent-error" is checker infrastructure failure (unreachable, bad
// JSON, timeout). PEPs audit them as different events — a model's DENY
// and a broken checker are different facts.
const (
	LayerIntent      = "intent"
	LayerIntentError = "intent-error"
)

// IntentChecker runs an external checker per admitted call. Cmd is
// either an http(s) URL (POST, JSON body) or a shell command (JSON on
// stdin). Both must answer {"decision":"ALLOW"|"DENY","reason":"..."}
// on stdout / in the response body within Timeout.
type IntentChecker struct {
	Cmd     string
	Timeout time.Duration
	Agent   string // acting agent name, given to the checker
	Task    string // the writ's declared task (RFC-017), given to the checker
}

type intentInput struct {
	Agent string          `json:"agent"`
	Task  string          `json:"task"`
	Tool  string          `json:"tool"`
	Args  json.RawMessage `json:"args"`
}

type intentVerdict struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// Decide consults the checker for one tool call. tool is the full
// resource ("<ns>/<name>"); args is the raw arguments object (may be
// nil). The Decision's Layer distinguishes verdicts (LayerIntent) from
// checker failure (LayerIntentError); the caller chooses what failure
// means (enforce = deny, advise = log).
func (c *IntentChecker) Decide(tool string, args map[string]json.RawMessage) policy.Decision {
	rawArgs, err := json.Marshal(args)
	if err != nil || args == nil {
		rawArgs = []byte("{}")
	}
	in, err := json.Marshal(intentInput{Agent: c.Agent, Task: c.Task, Tool: tool, Args: rawArgs})
	if err != nil {
		return policy.Decision{Effect: policy.Deny, Layer: LayerIntentError, Reason: err.Error()}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var out []byte
	if strings.HasPrefix(c.Cmd, "http://") || strings.HasPrefix(c.Cmd, "https://") {
		out, err = c.checkHTTP(ctx, in)
	} else {
		out, err = c.checkExec(ctx, in)
	}
	if err != nil {
		return policy.Decision{Effect: policy.Deny, Layer: LayerIntentError,
			Reason: "checker failed: " + err.Error()}
	}
	var v intentVerdict
	if err := json.Unmarshal(out, &v); err != nil {
		return policy.Decision{Effect: policy.Deny, Layer: LayerIntentError,
			Reason: "checker answered non-JSON"}
	}
	if v.Decision != "ALLOW" {
		reason := v.Reason
		if reason == "" {
			reason = "denied by intent checker"
		}
		return policy.Decision{Effect: policy.Deny, Layer: LayerIntent, Reason: reason}
	}
	return policy.Decision{Effect: policy.Allow, Layer: LayerIntent, Reason: v.Reason}
}

func (c *IntentChecker) checkExec(ctx context.Context, in []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", c.Cmd)
	cmd.Stdin = bytes.NewReader(in)
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("timeout after %s", c.Timeout)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *IntentChecker) checkHTTP(ctx context.Context, in []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Cmd, bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checker answered %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}
