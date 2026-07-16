package confine

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestHostAllowed(t *testing.T) {
	cases := []struct {
		host   string
		egress []string
		want   bool
	}{
		{"api.github.com", []string{"api.github.com"}, true},
		{"API.GITHUB.COM", []string{"api.github.com"}, true},
		{"api.github.com.", []string{"api.github.com"}, true}, // trailing-dot FQDN normalizes
		{"api.github.com", []string{"github.com"}, false},     // no implicit subdomains
		{"api.github.com", []string{"*.github.com"}, true},
		{"github.com", []string{"*.github.com"}, false}, // wildcard is subdomains only
		{"evilgithub.com", []string{"*.github.com"}, false},
		{"deep.api.github.com", []string{"*.github.com"}, true},
		{"anything.example", nil, false}, // empty manifest = no network
		{"anything.example", []string{""}, false},
	}
	for _, c := range cases {
		if got := HostAllowed(c.host, c.egress); got != c.want {
			t.Errorf("HostAllowed(%q, %v) = %v, want %v", c.host, c.egress, got, c.want)
		}
	}
}

// proxyClient returns an http.Client routing through the proxy at addr.
func proxyClient(t *testing.T, addr string) *http.Client {
	t.Helper()
	pu, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

// TestEgressProxyAllowsManifestHost proves both admitted paths: a plain
// proxied HTTP request and a CONNECT tunnel (HTTPS), against a real
// local server whose host is on the allow-list.
func TestEgressProxyAllowsManifestHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain-ok")
	}))
	defer backend.Close()
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "tls-ok")
	}))
	defer tlsBackend.Close()

	p := &EgressProxy{Egress: []string{"127.0.0.1"}}
	addr, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client := proxyClient(t, addr)

	for _, tc := range []struct{ url, want string }{
		{backend.URL, "plain-ok"},
		{tlsBackend.URL, "tls-ok"},
	} {
		resp, err := client.Get(tc.url)
		if err != nil {
			t.Fatalf("GET %s via proxy: %v", tc.url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != tc.want {
			t.Fatalf("GET %s = %q, want %q", tc.url, body, tc.want)
		}
	}
}

// TestEgressProxyDeniesOffManifestHost proves the deny path: 403, the
// tunnel never opens, and OnDeny reports the host (and only the host —
// metadata-only audit is structural).
func TestEgressProxyDeniesOffManifestHost(t *testing.T) {
	var mu sync.Mutex
	var denied []string
	p := &EgressProxy{
		Egress: []string{"allowed.example"},
		OnDeny: func(host string) { mu.Lock(); denied = append(denied, host); mu.Unlock() },
	}
	addr, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client := proxyClient(t, addr)

	// Plain HTTP to a host not in the manifest: 403 from the proxy,
	// nothing dialed.
	resp, err := client.Get("http://denied.example/secret/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	// CONNECT to a denied host: the client surfaces a proxy error.
	if _, err := client.Get("https://denied2.example/x"); err == nil {
		t.Fatal("CONNECT to denied host succeeded; want refusal")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(denied) != 2 || denied[0] != "denied.example" || denied[1] != "denied2.example" {
		t.Fatalf("OnDeny got %v, want [denied.example denied2.example]", denied)
	}
	for _, d := range denied {
		if strings.Contains(d, "/") || strings.Contains(d, "?") {
			t.Fatalf("OnDeny leaked more than the host: %q", d)
		}
	}
}

func TestProxyEnvAndSandboxProfile(t *testing.T) {
	env := ProxyEnv("127.0.0.1:9999")
	joined := strings.Join(env, "\n")
	for _, want := range []string{"HTTP_PROXY=http://127.0.0.1:9999", "https_proxy=http://127.0.0.1:9999", "NO_PROXY=127.0.0.1,localhost"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ProxyEnv missing %q in:\n%s", want, joined)
		}
	}

	prof := SandboxProfile([]string{"/data/allowed"}, "/private/tmp/x")
	for _, want := range []string{
		"(deny network-outbound)",
		`(allow network-outbound (remote ip "localhost:*"))`,
		"(deny file-write*)",
		`(allow file-write* (subpath "/data/allowed"))`,
		`(allow file-write* (subpath "/private/tmp/x"))`,
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q in:\n%s", want, prof)
		}
	}
}
