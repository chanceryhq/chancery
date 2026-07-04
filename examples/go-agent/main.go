// A minimal agent using the Chancery Go SDK: it starts a runtime
// instance, then advisory-checks each action against its writ before
// attempting it.
//
// ADVISORY: the SDK check is in-process ergonomics, not enforcement. The
// enforcement boundary is the proxy (`chancery mcp wrap`). This example
// shows the fast-fail developer pattern; in production the same agent's
// tools run behind the wrap so a bypassed check still cannot act.
//
// Setup before running:
//
//	chancery init --trust-domain acme.com
//	chancery serve &                       # control plane API on :7423
//	chancery agent register go-agent --owner user:you@acme.com \
//	    --purpose demo --prompt p --model m
//	chancery writ grant --for user:you@acme.com --to go-agent \
//	    --cap 'call:github/get_*' --ttl 1h      # note the writ id
//
//	go run . <admin-token> <writ-id>
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/chanceryhq/chancery/sdk"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: go run . <admin-token> <writ-id>")
		os.Exit(2)
	}
	token, writID := os.Args[1], os.Args[2]
	ctx := context.Background()

	client := sdk.New("http://127.0.0.1:7423", token)
	inst, err := client.StartInstance(ctx, "go-agent")
	if err != nil {
		fmt.Println("could not start instance:", err)
		os.Exit(1)
	}
	fmt.Printf("instance %s started; holding a %d-char identity document\n",
		inst.ID, len(inst.IdentityDocument))

	// The agent "wants" to do two things. One is within its writ, one is
	// not. Guarded runs the work only when the control plane allows it.
	actions := []struct {
		resource string
		work     func() error
	}{
		{"github/get_repo", func() error { fmt.Println("  → fetched repo metadata"); return nil }},
		{"github/delete_repo", func() error { fmt.Println("  → DELETED repo (should never print)"); return nil }},
	}
	for _, a := range actions {
		fmt.Printf("attempting call:%s\n", a.resource)
		if err := inst.Guarded(ctx, writID, "call", a.resource, a.work); err != nil {
			fmt.Println("  ✗", err)
		}
	}
}
