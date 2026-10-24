package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/baseline"
	"github.com/altrudev/MCP-DriftGuard/internal/evidence"
)

func TestOfflineEvidenceVerifyCLI(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := baseline.GenerateKeyPair(private, public); err != nil {
		t.Fatal(err)
	}
	key, err := baseline.LoadPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	// Independent declaration and actor keys; ledger contents cannot select keys.
	actorPrivate, actorPublic := filepath.Join(dir, "actor-private"), filepath.Join(dir, "actor-public")
	if err := baseline.GenerateKeyPair(actorPrivate, actorPublic); err != nil {
		t.Fatal(err)
	}
	actorKey, err := baseline.LoadPrivateKey(actorPrivate)
	if err != nil {
		t.Fatal(err)
	}
	m, err := evidence.Sign([]evidence.Claim{{ID: "claim", Actor: "alice"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) string {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(dir, name)
		if e = os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	manifest := write("manifest.json", m)
	trust := write("trust.json", map[string]string{"alice": actorPublic})
	o, err := evidence.SignObservation(evidence.Observation{Sequence: 1, Contract: m.Digest, Actor: "alice", Claim: "claim", Branch: "initial", ObservedAt: "2026-10-24T12:00:00Z", State: "unknown", Kind: "acknowledgement", Source: "synthetic-offline-fixture", Value: "received"}, actorKey)
	if err != nil {
		t.Fatal(err)
	}
	file := evidence.LedgerFile{Format: evidence.LedgerFormat, Observations: []evidence.Observation{o}}
	ledger := write("ledger.json", file)
	args := []string{"evidence-verify", "--manifest", manifest, "--verify-key", public, "--actor-keys", trust}
	verify := func(extra ...string) int { return run(append(append(append([]string{}, args...), extra...), ledger)) }
	if got := verify("--expected-head", o.Digest); got != 0 {
		t.Fatal(got)
	}
	if got := verify(); got != 0 {
		t.Fatal(got)
	}
	if got := verify("--expected-head", "wrong"); got != 5 {
		t.Fatal(got)
	}
	for _, tc := range []struct {
		name   string
		change func(*evidence.Observation)
	}{
		{"tamper", func(o *evidence.Observation) { o.Value = "executed" }},
		{"unsigned", func(o *evidence.Observation) { o.Signature = "" }},
		{"cross-actor", func(o *evidence.Observation) { o.Actor = "bob" }},
		{"chronology", func(o *evidence.Observation) {
			o.EventAt = "2026-10-25T12:00:00Z"
			*o, _ = evidence.SignObservation(*o, actorKey)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := o
			tc.change(&bad)
			write("ledger.json", evidence.LedgerFile{Format: evidence.LedgerFormat, Observations: []evidence.Observation{bad}})
			if got := verify(); got != 5 {
				t.Fatal(got)
			}
		})
	}
	write("ledger.json", file)
	write("trust.json", map[string]string{"alice": public})
	if got := verify(); got != 5 {
		t.Fatal("wrong actor key", got)
	}
	write("trust.json", map[string]string{"alice": actorPublic})
	m.Claims[0].Actor = "bob"
	write("manifest.json", m)
	if got := verify(); got != 5 {
		t.Fatal("tampered manifest", got)
	}
	if got := run([]string{"evidence-verify"}); got != 3 {
		t.Fatal(got)
	}
}
