package seal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPutGetRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("github-token", "static", "ghp_secret123"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("github-token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ghp_secret123" {
		t.Errorf("roundtrip failed")
	}
}

func TestValuesNeverOnDiskInPlaintext(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Put("api-key", "static", "supersecretvalue"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "sealed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "supersecretvalue") {
		t.Fatal("plaintext value found on disk")
	}
}

func TestListReturnsNoValues(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Put("a", "static", "value-a")
	metas, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 || metas[0].Name != "a" || metas[0].Kind != "static" {
		t.Errorf("metadata wrong: %+v", metas)
	}
	blob, _ := json.Marshal(metas)
	if strings.Contains(string(blob), "value-a") {
		t.Fatal("List leaked a value")
	}
}

func TestWrongKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Put("a", "static", "v")
	// Replace the key: existing entries must fail authentication.
	if err := os.WriteFile(filepath.Join(dir, "seal.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Get("a"); err == nil {
		t.Fatal("entry sealed under a different key must not decrypt")
	}
}

func TestEntriesBoundToName(t *testing.T) {
	// AEAD associated data: swapping ciphertexts between names on disk
	// must fail authentication.
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Put("prod-token", "static", "prod-value")
	s.Put("dev-token", "static", "dev-value")

	path := filepath.Join(dir, "sealed.json")
	raw, _ := os.ReadFile(path)
	var m map[string]map[string]any
	json.Unmarshal(raw, &m)
	m["prod-token"], m["dev-token"] = m["dev-token"], m["prod-token"]
	swapped, _ := json.Marshal(m)
	os.WriteFile(path, swapped, 0o600)

	if _, err := s.Get("prod-token"); err == nil {
		t.Fatal("cross-name ciphertext swap must fail authentication")
	}
}

func TestDeleteAndNotFound(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Put("a", "static", "v")
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if err := s.Delete("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete: want ErrNotFound, got %v", err)
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Put("a", "static", "value")
	path := filepath.Join(dir, "sealed.json")
	raw, _ := os.ReadFile(path)
	var m map[string]entry
	json.Unmarshal(raw, &m)
	e := m["a"]
	e.Ciphertxt = "AAAA" + e.Ciphertxt[4:]
	m["a"] = e
	tampered, _ := json.Marshal(m)
	os.WriteFile(path, tampered, 0o600)
	if _, err := s.Get("a"); err == nil {
		t.Fatal("tampered ciphertext must be rejected")
	}
}
