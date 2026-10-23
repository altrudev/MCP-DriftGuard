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
	path := filepath.Join(dir, "approved.json")
	if got := serve([]string{"--endpoint", "stdio", "--baseline", path}); got != 4 {
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
	if got := serve([]string{"--endpoint", "stdio", "--baseline", path}); got != 5 {
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
	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	if err := baseline.GenerateKeyPair(private, public); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(private)
	if got := serve([]string{"--endpoint", "stdio", "--baseline", path, "--verify-key", public}); got != 5 {
		t.Fatalf("unsigned baseline: %d", got)
	}
}
