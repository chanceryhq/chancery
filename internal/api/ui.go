package api

import _ "embed"

// uiHTML is the read-only dashboard (RFC-014): one dependency-free
// page, embedded so the single-static-binary invariant holds. It must
// never contain data at build or render time — data arrives only via
// authenticated /v1 calls made by the page.
//
//go:embed ui.html
var uiHTML []byte
