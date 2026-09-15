package baseline

import (
	"crypto/ed25519"
	"crypto/rand"
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


func TestVerificationKeyRejectsStrippedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := New(canonical.Snapshot{Format: "mcpdrift-snapshot/v1", Endpoint: "https://x"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = nil
	if err := a.Validate(pub); err == nil {
		t.Fatal("stripped signature accepted with verification key")
	}
}

func TestEndpointEnvelopeMustMatchSnapshot(t *testing.T) {
	a, err := New(canonical.Snapshot{Format: "mcpdrift-snapshot/v1", Endpoint: "https://x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.Endpoint = "https://other"
	if err := a.Validate(nil); err == nil {
		t.Fatal("mismatched outer endpoint accepted")
	}
}
