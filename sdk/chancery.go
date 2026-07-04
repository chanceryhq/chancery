// Package sdk is the Go ergonomics layer over a Chancery control plane
// (RFC-010 item 7). It is a thin client over the HTTP API (RFC-008): it
// registers a runtime instance, obtains an identity document, and offers
// a Guard for advisory pre-flight checks.
//
// ADVISORY ONLY. This SDK runs inside the agent's own process, which is
// untrusted (RFC-009 trust boundary 1) — a prompt-injected agent can
// simply not call Guard. It exists for ergonomics and fail-fast
// developer feedback, NOT as an enforcement boundary. The enforcement
// boundary is the out-of-process proxy: run the agent's tools behind
// `chancery mcp wrap` (RFC-005). Treat Guard like a client-side form
// check, with the proxy as the server-side validation that actually
// binds.
package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client talks to a Chancery control plane over its HTTP API.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:7423
	Token   string // admin bearer token (RFC-008); document-scoped auth is v1
	HTTP    *http.Client
}

// New returns a Client with sane defaults.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("chancery: %s (%s, http %d)", e.Error, e.Code, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Instance is a live runtime instance and its identity document.
type Instance struct {
	Agent            string
	ID               string
	IdentityDocument string
	client           *Client
}

// StartInstance registers a runtime instance of an already-registered
// agent and returns its short-lived identity document (RFC-001). The
// agent, its version, owner, and writs are managed out-of-band by an
// operator; the SDK does not register agents (registration is an
// accountable human/CI act, not something an agent does to itself).
func (c *Client) StartInstance(ctx context.Context, agent string) (*Instance, error) {
	var out struct {
		Instance         string `json:"instance"`
		IdentityDocument string `json:"identity_document"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/agents/"+agent+"/instances", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &Instance{Agent: agent, ID: out.Instance,
		IdentityDocument: out.IdentityDocument, client: c}, nil
}

// Decision mirrors the control plane's evaluation of one action.
type Decision struct {
	Allowed bool
	Layer   string
	Reason  string
}

// Guard performs an ADVISORY pre-flight check of an action against a writ
// (verb defaults to "call"). A true result means the control plane would
// currently allow it; a false result is a fast local signal to skip the
// call. This is NOT enforcement — see the package doc. Enforcement is the
// proxy. Use it to fail fast and to keep the agent's own behavior honest,
// never as the thing standing between the agent and the action.
func (in *Instance) Guard(ctx context.Context, writ, verb, resource string) (Decision, error) {
	if verb == "" {
		verb = "call"
	}
	var out struct {
		Decision string `json:"decision"`
		Layer    string `json:"layer"`
		Reason   string `json:"reason"`
	}
	err := in.client.do(ctx, http.MethodPost, "/v1/writs/"+writ+"/check",
		map[string]string{"verb": verb, "resource": resource}, &out)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: out.Decision == "ALLOW", Layer: out.Layer, Reason: out.Reason}, nil
}

// Guarded runs fn only if the action is currently allowed (advisory). It
// is sugar over Guard; the same caveat applies — the real gate is the
// proxy, and fn here still runs in-process where the agent controls it.
func (in *Instance) Guarded(ctx context.Context, writ, verb, resource string, fn func() error) error {
	d, err := in.Guard(ctx, writ, verb, resource)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return fmt.Errorf("chancery: denied by %s policy: %s", d.Layer, d.Reason)
	}
	return fn()
}
