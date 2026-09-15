package baseline

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

type Artifact struct {
	Format        string             `json:"format"`
	CreatedAt     string             `json:"created_at"`
	Endpoint      string             `json:"endpoint"`
	Snapshot      canonical.Snapshot `json:"snapshot"`
	CanonicalHash string             `json:"canonical_hash"`
	Signature     *Signature         `json:"signature,omitempty"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

func New(snapshot canonical.Snapshot, privateKey ed25519.PrivateKey) (Artifact, error) {
	h, err := canonical.Hash(snapshot)
	if err != nil {
		return Artifact{}, err
	}
	a := Artifact{Format: "mcpdrift-baseline/v1", CreatedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: snapshot.Endpoint, Snapshot: snapshot, CanonicalHash: h}
	if len(privateKey) > 0 {
		pub := privateKey.Public().(ed25519.PublicKey)
		sig := ed25519.Sign(privateKey, []byte(h))
		a.Signature = &Signature{Algorithm: "ed25519", KeyID: keyID(pub), Value: base64.StdEncoding.EncodeToString(sig)}
	}
	return a, nil
}

func (a Artifact) Validate(publicKey ed25519.PublicKey) error {
	if a.Format != "mcpdrift-baseline/v1" {
		return fmt.Errorf("unsupported baseline format %q", a.Format)
	}
	h, err := canonical.Hash(a.Snapshot)
	if err != nil {
		return err
	}
	if h != a.CanonicalHash {
		return errors.New("baseline canonical hash mismatch")
	}
	if a.Endpoint != a.Snapshot.Endpoint {
		return errors.New("baseline endpoint does not match snapshot endpoint")
	}
	if len(publicKey) > 0 && a.Signature == nil {
		return errors.New("verification key supplied but baseline is unsigned")
	}
	if a.Signature != nil {
		if len(publicKey) == 0 {
			return errors.New("baseline is signed but no verification key was supplied")
		}
		if a.Signature.Algorithm != "ed25519" {
			return fmt.Errorf("unsupported signature algorithm %q", a.Signature.Algorithm)
		}
		if keyID(publicKey) != a.Signature.KeyID {
			return errors.New("verification key does not match baseline key id")
		}
		sig, err := base64.StdEncoding.DecodeString(a.Signature.Value)
		if err != nil {
			return fmt.Errorf("decode baseline signature: %w", err)
		}
		if !ed25519.Verify(publicKey, []byte(a.CanonicalHash), sig) {
			return errors.New("baseline signature verification failed")
		}
	}
	return nil
}

func Save(path string, a Artifact) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func Load(path string) (Artifact, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, err
	}
	var a Artifact
	if err := json.Unmarshal(b, &a); err != nil {
		return Artifact{}, err
	}
	return a, nil
}

func GenerateKeyPair(privatePath, publicPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return priv, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return pub, nil
}

func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:8])
}
