// Package confine implements manifest-bounded runtime confinement for
// wrapped MCP servers (RFC-018): the pin's manifest declares the hosts
// a server process may reach (egress) and the paths it may write
// (writable); the spawn applies it as an OS boundary.
//
// Two separate authorities by design: the writ bounds each CALL; the
// manifest bounds the PROCESS. A GitHub MCP server needs api.github.com
// even when the writ carries no net capabilities — so egress is
// operator-declared at pin time and changed only via audited repin.
//
// The failure mode is refused-and-audited, never silently-unconfined.
package confine

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// HostAllowed reports whether host (no port) matches the egress
// allow-list. Entries are exact hostnames or wildcard subdomains
// ("*.github.com" matches api.github.com but not github.com itself —
// list both if you mean both). Matching is case-insensitive. An empty
// list allows nothing.
func HostAllowed(host string, egress []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, e := range egress {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(e, "*."); ok {
			if strings.HasSuffix(host, "."+rest) {
				return true
			}
			continue
		}
		if host == e {
			return true
		}
	}
	return false
}

// EgressProxy is a loopback-only forward proxy the confined server is
// pointed at via HTTP_PROXY/HTTPS_PROXY. It admits CONNECT tunnels and
// plain proxied HTTP requests whose destination host is on the
// allow-list; everything else is refused with 403 and reported through
// OnDeny (host only — never paths, never payloads: metadata-only audit
// is structural, RFC-006).
type EgressProxy struct {
	Egress []string
	// OnDeny is called with the denied destination host. Must be safe
	// for concurrent use.
	OnDeny func(host string)

	ln   net.Listener
	once sync.Once
}

// Start begins listening on 127.0.0.1 (ephemeral port) and serving.
// Returns the proxy address for the child's proxy env vars.
func (p *EgressProxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.ln = ln
	go p.serve()
	return ln.Addr().String(), nil
}

// Close stops the listener; in-flight tunnels drain on their own.
func (p *EgressProxy) Close() {
	p.once.Do(func() {
		if p.ln != nil {
			p.ln.Close()
		}
	})
}

func (p *EgressProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *EgressProxy) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	host := req.Host
	if req.Method == http.MethodConnect {
		host = req.RequestURI
	} else if req.URL != nil && req.URL.Host != "" {
		host = req.URL.Host
	}
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	if !HostAllowed(hostOnly, p.Egress) {
		if p.OnDeny != nil {
			p.OnDeny(hostOnly)
		}
		io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\negress to "+hostOnly+" is not in this server's manifest (chancery mcp repin --egress to change it)\r\n")
		return
	}
	if req.Method == http.MethodConnect {
		p.tunnel(conn, host)
		return
	}
	p.forward(conn, req)
}

// tunnel serves an admitted CONNECT: dial the destination and splice.
func (p *EgressProxy) tunnel(conn net.Conn, hostport string) {
	dst, err := net.Dial("tcp", hostport)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer dst.Close()
	io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { io.Copy(dst, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, dst); done <- struct{}{} }()
	<-done
}

// forward serves an admitted plain-HTTP proxied request.
func (p *EgressProxy) forward(conn net.Conn, req *http.Request) {
	req.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Write(conn)
}

// ProxyEnv returns the child-environment entries that route the
// confined server's HTTP(S) traffic through the proxy at addr. Both
// case variants are set — clients disagree on which they read.
func ProxyEnv(addr string) []string {
	u := "http://" + addr
	return []string{
		"HTTP_PROXY=" + u, "http_proxy=" + u,
		"HTTPS_PROXY=" + u, "https_proxy=" + u,
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
	}
}

// SandboxProfile renders a macOS sandbox profile (sandbox-exec -p) that
// makes the manifest an OS boundary rather than a convention:
//
//   - outbound network is loopback-only, so the egress proxy is the
//     only road out (a client that ignores proxy env vars gets EPERM,
//     not a bypass);
//   - the filesystem is read-only outside the declared writable paths,
//     the OS temp dir, and /dev/null.
//
// sandbox-exec is deprecated-but-functional (Apple still runs on
// seatbelt); Linux gets the same manifest via bubblewrap. Where neither
// is available, --confine refuses to spawn: fail closed, audited.
func SandboxProfile(writable []string, tmpDir string) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")
	b.WriteString("(deny network-outbound)\n")
	b.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
	b.WriteString("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n")
	b.WriteString("(deny file-write*)\n")
	b.WriteString("(allow file-write-data (literal \"/dev/null\"))\n")
	if tmpDir != "" {
		fmt.Fprintf(&b, "(allow file-write* (subpath %q))\n", strings.TrimSuffix(tmpDir, "/"))
	}
	for _, w := range writable {
		if w == "" {
			continue
		}
		fmt.Fprintf(&b, "(allow file-write* (subpath %q))\n", strings.TrimSuffix(w, "/"))
	}
	return b.String()
}
