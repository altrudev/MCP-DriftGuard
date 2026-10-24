package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

const Format = "mcpdrift-evidence-contract/v1"

type Manifest struct {
	Format    string  `json:"format"`
	Claims    []Claim `json:"claims"`
	Digest    string  `json:"digest"`
	Signature string  `json:"signature"`
}

func payload(claims []Claim) ([]byte, error) {
	if _, err := index(claims); err != nil {
		return nil, err
	}
	ordered := append([]Claim{}, claims...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	return json.Marshal(struct {
		Format string  `json:"format"`
		Claims []Claim `json:"claims"`
	}{Format, ordered})
}
func Sign(claims []Claim, key ed25519.PrivateKey) (Manifest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("Ed25519 private key required")
	}
	b, err := payload(claims)
	if err != nil {
		return Manifest{}, err
	}
	h := sha256.Sum256(b)
	return Manifest{Format, claims, hex.EncodeToString(h[:]), base64.StdEncoding.EncodeToString(ed25519.Sign(key, h[:]))}, nil
}
func (m Manifest) Verify(key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("Ed25519 public key required")
	}
	if m.Format != Format {
		return fmt.Errorf("unsupported evidence manifest format %q", m.Format)
	}
	b, err := payload(m.Claims)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != m.Digest {
		return errors.New("evidence manifest digest mismatch")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(key, h[:], sig) {
		return errors.New("evidence manifest signature invalid")
	}
	return nil
}
func Read(path string) (Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
