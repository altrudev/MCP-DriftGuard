package baseline

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

func TestSignedBaseline(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := New(canonical.Snapshot{Format: "mcpdrift-snapshot/v1", Endpoint: "https://x"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(pub); err != nil {
		t.Fatal(err)
	}
	a.Snapshot.Endpoint = "https://evil"
	if err := a.Validate(pub); err == nil {
		t.Fatal("tampering accepted")
	}
}

func TestVerificationKeyRejectsUnsignedBaseline(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	a, err := New(canonical.Snapshot{Format: "mcpdrift-snapshot/v1", Endpoint: "https://x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(pub); err == nil {
		t.Fatal("unsigned baseline accepted despite explicit verification key")
	}
	if err := a.Validate(nil); err != nil {
		t.Fatalf("unsigned mode should remain supported: %v", err)
	}
}

func TestSaveReplacesSymlinkWithoutTruncatingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "baseline")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	a, _ := New(canonical.Snapshot{}, nil)
	if err := Save(path, a); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "keep" {
		t.Fatal("save truncated symlink target")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.Validate(nil); err != nil {
		t.Fatal(err)
	}
}
func TestInvalidKeyLengthsReturnErrors(t *testing.T) {
	if _, err := New(canonical.Snapshot{}, ed25519.PrivateKey{1}); err == nil {
		t.Fatal("invalid private key accepted")
	}
	a, _ := New(canonical.Snapshot{}, nil)
	if err := a.Validate(ed25519.PublicKey{1}); err == nil {
		t.Fatal("invalid public key accepted")
	}
}

func TestSaveFailureCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "existing-directory")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(destination, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	a, _ := New(canonical.Snapshot{}, nil)
	if err := Save(destination, a); err == nil {
		t.Fatal("rename over directory accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("temporary file leaked")
	}
	b, err := os.ReadFile(sentinel)
	if err != nil || string(b) != "keep" {
		t.Fatal("destination damaged", err)
	}
}
