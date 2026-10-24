package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignedManifestTamperAndOrdering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	xs := []Claim{{ID: "b", Actor: "A", ReceiptMeaning: "accepted"}, {ID: "a", Actor: "B"}}
	m, e := Sign(xs, priv)
	if e != nil || m.Verify(pub) != nil {
		t.Fatal(e)
	}
	xs2 := []Claim{xs[1], xs[0]}
	n, e := Sign(xs2, priv)
	if e != nil || m.Digest != n.Digest {
		t.Fatal("unstable digest", e)
	}
	m.Claims[0].ReceiptMeaning = "executed"
	if m.Verify(pub) == nil {
		t.Fatal("tamper not rejected")
	}
	m = n
	m.Signature = ""
	if m.Verify(pub) == nil {
		t.Fatal("stripped signature accepted")
	}
	if _, e = Sign([]Claim{xs[0], xs[0]}, priv); e == nil {
		t.Fatal("duplicate allowed")
	}
}
