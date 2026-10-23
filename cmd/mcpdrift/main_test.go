package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/baseline"
	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

func TestServeRejectsMissingAndInvalidApprovalBeforeReadingStdin(t *testing.T) {
	if got := serve(nil); got != 3 {
		t.Fatalf("missing configuration: %d", got)
	}
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	if err := baseline.GenerateKeyPair(private, public); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "approved.json")
	if got := serve([]string{"--endpoint", "stdio", "--baseline", path, "--verify-key", public}); got != 4 {
		t.Fatalf("missing baseline: %d", got)
	}
	a, err := baseline.New(canonical.Snapshot{Format: "mcpdrift.snapshot/v1", Endpoint: "stdio://test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.CanonicalHash = "tampered"
	if err := baseline.Save(path, a); err != nil {
		t.Fatal(err)
	}
	if got := serve([]string{"--endpoint", "stdio", "--baseline", path, "--verify-key", public}); got != 5 {
		t.Fatalf("tampered baseline: %d", got)
	}
	// A trusted key must reject unsigned artifacts (no signature downgrade).
	a, err = baseline.New(canonical.Snapshot{Endpoint: "stdio://test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.Save(path, a); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(private)
	if got := serve([]string{"--endpoint", "stdio", "--baseline", path, "--verify-key", public}); got != 5 {
		t.Fatalf("unsigned baseline: %d", got)
	}
}

func TestServeTrustBoundary(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := baseline.GenerateKeyPair(private, public); err != nil {
		t.Fatal(err)
	}
	priv, err := baseline.LoadPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := baseline.New(canonical.Snapshot{Endpoint: "stdio://test"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, _ := baseline.New(signed.Snapshot, nil)
	wrongPriv, wrongPub := filepath.Join(dir, "wrong-private"), filepath.Join(dir, "wrong-public")
	if err := baseline.GenerateKeyPair(wrongPriv, wrongPub); err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Snapshot.Endpoint = "https://evil"
	forged := tampered
	forged.CanonicalHash, err = canonical.Hash(forged.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := signed
	sig := *signed.Signature
	sig.Value = "invalid-base64!"
	corrupt.Signature = &sig
	malformedKey := filepath.Join(dir, "malformed-key")
	if err := os.WriteFile(malformedKey, []byte("not a PEM key"), 0600); err != nil {
		t.Fatal(err)
	}
	// EOF ensures a valid startup completes without probing or a live stdin.
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old }()
	for _, tc := range []struct {
		name string
		a    baseline.Artifact
		key  string
		want int
	}{
		{"unsigned missing key", unsigned, "", 3}, {"signed missing key", signed, "", 3},
		{"unsigned trusted key", unsigned, public, 5}, {"wrong key", signed, wrongPub, 5},
		{"tamper", tampered, public, 5},
		{"rehashed tamper", forged, public, 5},
		{"corrupt signature", corrupt, public, 5},
		{"malformed key", signed, malformedKey, 4}, {"missing key file", signed, filepath.Join(dir, "missing"), 4},
		{"trusted signed", signed, public, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "baseline.json")
			if err := baseline.Save(path, tc.a); err != nil {
				t.Fatal(err)
			}
			args := []string{"--endpoint", "stdio", "--baseline", path}
			if tc.key != "" {
				args = append(args, "--verify-key", tc.key)
			}
			if got := serve(args); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
