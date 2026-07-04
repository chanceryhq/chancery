// Package seal is the broker's sealed credential store (RFC-003):
// AES-256-GCM per entry, key material in a 0600 file, values in plaintext
// only in memory during injection. Names and kinds are metadata; values
// never appear in logs, audit events, or errors.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

var ErrNotFound = errors.New("secret not found")

type entry struct {
	Kind      string    `json:"kind"`
	Nonce     string    `json:"nonce"`
	Ciphertxt string    `json:"ct"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Meta struct {
	Name      string
	Kind      string
	UpdatedAt time.Time
}

type Store struct {
	path string
	aead cipher.AEAD
}

// Open loads (or on first use creates) the seal key and the store file.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "seal.key")
	key, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("seal key at %s is malformed", keyPath)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, "sealed.json"), aead: aead}, nil
}

func (s *Store) load() (map[string]entry, error) {
	out := map[string]entry{}
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("sealed store corrupt: %w", err)
	}
	return out, nil
}

func (s *Store) save(m map[string]entry) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Put seals a credential value under name. The name is bound as AEAD
// associated data, so entries cannot be swapped between names on disk.
func (s *Store) Put(name, kind, value string) error {
	m, err := s.load()
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, []byte(value), []byte(name))
	m[name] = entry{Kind: kind, Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ciphertxt: base64.StdEncoding.EncodeToString(ct), UpdatedAt: time.Now().UTC()}
	return s.save(m)
}

// Get unseals a value. Callers hold it only for the duration of one
// injection; it must never be logged or persisted.
func (s *Store) Get(name string) (string, error) {
	m, err := s.load()
	if err != nil {
		return "", err
	}
	e, ok := m[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return "", fmt.Errorf("sealed entry %s corrupt", name)
	}
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertxt)
	if err != nil {
		return "", fmt.Errorf("sealed entry %s corrupt", name)
	}
	pt, err := s.aead.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return "", fmt.Errorf("sealed entry %s failed authentication (wrong key or tampered)", name)
	}
	return string(pt), nil
}

// List returns metadata only — no values, ever.
func (s *Store) List() ([]Meta, error) {
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []Meta
	for name, e := range m {
		out = append(out, Meta{Name: name, Kind: e.Kind, UpdatedAt: e.UpdatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) Delete(name string) error {
	m, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := m[name]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	delete(m, name)
	return s.save(m)
}
