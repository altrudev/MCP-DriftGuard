package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

type ledgerFixture struct {
	m    Manifest
	pub  ed25519.PublicKey
	keys map[string]ed25519.PublicKey
	priv map[string]ed25519.PrivateKey
	l    *Ledger
}

func fixture(t *testing.T) ledgerFixture {
	t.Helper()
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	f := ledgerFixture{pub: pub, keys: map[string]ed25519.PublicKey{}, priv: map[string]ed25519.PrivateKey{}}
	for _, actor := range []string{"alice", "bob"} {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		f.keys[actor] = p
		f.priv[actor] = k
	}
	var err error
	f.m, err = Sign([]Claim{{ID: "a", Actor: "alice"}, {ID: "another", Actor: "alice"}, {ID: "b", Actor: "bob"}}, private)
	if err != nil {
		t.Fatal(err)
	}
	f.l, err = NewLedger(f.m, pub, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f ledgerFixture) next(t *testing.T, actor string, change func(*Observation)) Observation {
	t.Helper()
	claim := "a"
	if actor == "bob" {
		claim = "b"
	}
	o := Observation{Sequence: len(f.l.records) + 1, Previous: f.l.Head(), Contract: f.m.Digest, Actor: actor, Claim: claim, Branch: "initial", ObservedAt: "2026-10-24T12:00:00Z", State: "unknown", Kind: "receipt", Source: "offline-fixture", Value: "accepted"}
	if change != nil {
		change(&o)
	}
	o, err := SignObservation(o, f.priv[actor])
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func mustAppend(t *testing.T, l *Ledger, o Observation) {
	t.Helper()
	if err := l.Append(o); err != nil {
		t.Fatal(err)
	}
}

func TestChronologyIsolationAndRetryHistory(t *testing.T) {
	f := fixture(t)
	first := f.next(t, "alice", nil)
	mustAppend(t, f.l, first)
	bob := f.next(t, "bob", func(o *Observation) { o.State = "observed" })
	mustAppend(t, f.l, bob)
	failure := f.next(t, "alice", func(o *Observation) { o.Kind = "error"; o.Value = "timeout"; o.ObservedAt = "2026-10-24T12:01:00Z" })
	mustAppend(t, f.l, failure)
	retry := f.next(t, "alice", func(o *Observation) {
		o.Branch = "retry-1"
		o.RetryOf = failure.Digest
		o.State = "inferred"
		o.Supports = []string{failure.Digest}
		o.ObservedAt = "2026-10-24T12:02:00Z"
		o.EventAt = "2026-10-24T11:00:00Z"
	})
	mustAppend(t, f.l, retry)
	alternate := f.next(t, "alice", func(o *Observation) {
		o.Branch = "retry-2"
		o.RetryOf = failure.Digest
		o.Kind = "acknowledgement"
		o.Value = "received"
		o.ObservedAt = "2026-10-24T12:03:00Z"
	})
	mustAppend(t, f.l, alternate)
	old := f.l.History("alice", 1)
	if len(old) != 1 || old[0].State != "unknown" || old[0].Kind != "receipt" {
		t.Fatal(old)
	}
	history := f.l.History("alice", 5)
	if len(history) != 4 || history[2].State != "inferred" || history[3].State != "unknown" || history[1].Digest != failure.Digest {
		t.Fatal(history)
	}
	if len(f.l.History("bob", 5)) != 1 || len(f.l.History("stranger", 5)) != 0 {
		t.Fatal("actor history leaked")
	}
	replay, err := VerifyLedger(f.l.File(), f.m, f.pub, f.keys, f.l.Head())
	if err != nil || len(replay.History("alice", 5)) != 4 {
		t.Fatal(err)
	}
	// Copies cannot mutate retained evidence, including nested support slices.
	history[2].Supports[0] = "forged"
	exported := f.l.File()
	exported.Observations[0].Value = "forged"
	if f.l.History("alice", 5)[2].Supports[0] != failure.Digest || f.l.History("alice", 1)[0].Value != "accepted" {
		t.Fatal("mutable history")
	}
}

func TestAppendInvariantFailuresAreAtomic(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Observation, Observation, Observation)
	}{
		{"actor-claim", func(o *Observation, a, b Observation) { o.Claim = "b" }},
		{"backdated-acquisition", func(o *Observation, a, b Observation) { o.ObservedAt = "2026-10-23T12:00:00Z" }},
		{"future-event", func(o *Observation, a, b Observation) { o.EventAt = "2026-10-25T12:00:00Z" }},
		{"bad-time", func(o *Observation, a, b Observation) { o.ObservedAt = "yesterday" }},
		{"cross-actor-support", func(o *Observation, a, b Observation) { o.Supports = []string{b.Digest} }},
		{"future-support", func(o *Observation, a, b Observation) { o.Supports = []string{"missing"} }},
		{"duplicate-support", func(o *Observation, a, b Observation) { o.Supports = []string{a.Digest, a.Digest} }},
		{"certainty-promotion", func(o *Observation, a, b Observation) { o.State = "observed"; o.Supports = []string{a.Digest} }},
		{"success-promotion", func(o *Observation, a, b Observation) { o.State = "proven" }},
		{"missing-provenance", func(o *Observation, a, b Observation) { o.Source = "" }},
		{"missing-branch", func(o *Observation, a, b Observation) { o.Branch = "" }},
		{"cross-actor-retry", func(o *Observation, a, b Observation) { o.Branch = "retry"; o.RetryOf = b.Digest }},
		{"same-branch-retry", func(o *Observation, a, b Observation) { o.RetryOf = a.Digest }},
		{"missing-retry", func(o *Observation, a, b Observation) { o.Branch = "retry"; o.RetryOf = "missing" }},
		{"chain", func(o *Observation, a, b Observation) { o.Previous = "forged" }},
		{"sequence", func(o *Observation, a, b Observation) { o.Sequence++ }},
		{"contract", func(o *Observation, a, b Observation) { o.Contract = "other" }},
		{"kind", func(o *Observation, a, b Observation) { o.Kind = "success" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t)
			a := f.next(t, "alice", nil)
			mustAppend(t, f.l, a)
			b := f.next(t, "bob", nil)
			mustAppend(t, f.l, b)
			bad := f.next(t, "alice", func(o *Observation) { tc.change(o, a, b) })
			head := f.l.Head()
			if err := f.l.Append(bad); err == nil {
				t.Fatal("accepted invalid evidence")
			}
			if f.l.Head() != head || len(f.l.File().Observations) != 2 {
				t.Fatal("failed append mutated history")
			}
			mustAppend(t, f.l, f.next(t, "alice", nil))
		})
	}
}

func TestSignedReplayBoundaryFailures(t *testing.T) {
	f := fixture(t)
	a := f.next(t, "alice", nil)
	mustAppend(t, f.l, a)
	b := f.next(t, "alice", func(o *Observation) { o.State = "inferred"; o.Supports = []string{a.Digest} })
	mustAppend(t, f.l, b)
	cases := []struct {
		name   string
		mutate func(*LedgerFile)
	}{
		{"tamper", func(f *LedgerFile) { f.Observations[0].Value = "executed" }},
		{"unsigned", func(f *LedgerFile) { f.Observations[0].Signature = "" }},
		{"malformed-signature", func(f *LedgerFile) { f.Observations[0].Signature = "!" }},
		{"deletion", func(f *LedgerFile) { f.Observations = f.Observations[1:] }},
		{"reorder", func(f *LedgerFile) { f.Observations[0], f.Observations[1] = f.Observations[1], f.Observations[0] }},
		{"duplicate", func(f *LedgerFile) { f.Observations = append(f.Observations, f.Observations[1]) }},
		{"truncation", func(f *LedgerFile) { f.Observations = f.Observations[:1] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := f.l.File()
			tc.mutate(&file)
			if _, err := VerifyLedger(file, f.m, f.pub, f.keys, f.l.Head()); err == nil {
				t.Fatal("accepted corrupted replay")
			}
		})
	}
	for _, keys := range []map[string]ed25519.PublicKey{{}, {"alice": f.keys["bob"]}} {
		if _, err := VerifyLedger(f.l.File(), f.m, f.pub, keys, ""); err == nil {
			t.Fatal("accepted untrusted actor")
		}
	}
	// Inference cannot be laundered into observation even under a valid signature.
	if err := f.l.Append(f.next(t, "alice", func(o *Observation) { o.State = "observed"; o.Supports = []string{b.Digest} })); err == nil {
		t.Fatal("inference promoted")
	}
	// The verifier owns the key snapshot.
	f.keys["alice"][0] ^= 1
	mustAppend(t, f.l, f.next(t, "alice", nil))
}

func TestBoundsAndStrictDecode(t *testing.T) {
	f := fixture(t)
	oversized := f.next(t, "alice", func(o *Observation) { o.Value = strings.Repeat("x", MaxObservationBytes) })
	if err := f.l.Append(oversized); err == nil {
		t.Fatal("oversized record accepted")
	}
	// Exercise exact count and byte boundaries without a quadratic 4096-signature setup.
	f.l.records = make([]Observation, MaxObservations)
	if err := f.l.Append(Observation{}); err == nil {
		t.Fatal("count bound ignored")
	}
	f.l.records = nil
	f.l.bytes = MaxLedgerBytes
	if err := f.l.Append(f.next(t, "alice", nil)); err == nil {
		t.Fatal("byte bound ignored")
	}
	f = fixture(t)
	mustAppend(t, f.l, f.next(t, "alice", nil))
	b, _ := json.Marshal(f.l.File())
	if _, err := DecodeLedger(strings.NewReader(string(b))); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{string(b) + " {}", `{"format":"mcpdrift-evidence-ledger/v1","unexpected":true}`, strings.Repeat(" ", MaxLedgerBytes+1), `{"format":"wrong"}`} {
		if _, err := DecodeLedger(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}

func TestRetryAncestryCannotChangeOrCrossClaims(t *testing.T) {
	f := fixture(t)
	first := f.next(t, "alice", nil)
	mustAppend(t, f.l, first)
	retry := f.next(t, "alice", func(o *Observation) { o.Branch = "retry"; o.RetryOf = first.Digest })
	mustAppend(t, f.l, retry)
	bad := f.next(t, "alice", func(o *Observation) { o.Branch = "retry" })
	if err := f.l.Append(bad); err == nil {
		t.Fatal("erased retry ancestry")
	}
	mustAppend(t, f.l, f.next(t, "alice", func(o *Observation) { o.Branch = "retry"; o.RetryOf = first.Digest; o.Kind = "error" }))
	// A claim owned by the same actor still cannot supply another claim's retry parent.
	if err := f.l.Append(f.next(t, "alice", func(o *Observation) { o.Claim = "another"; o.Branch = "alternate"; o.RetryOf = first.Digest })); err == nil {
		t.Fatal("cross-claim retry accepted")
	}
}

func TestIndependentActorClocksAndEqualAcquisitionTimes(t *testing.T) {
	f := fixture(t)
	mustAppend(t, f.l, f.next(t, "alice", nil))
	// Bob's clock need not agree with Alice's. This supplies no knowledge to Alice.
	bob := f.next(t, "bob", func(o *Observation) { o.ObservedAt = "2026-10-23T00:00:00Z"; o.State = "observed" })
	mustAppend(t, f.l, bob)
	mustAppend(t, f.l, f.next(t, "alice", nil))
	if len(f.l.History("alice", 2)) != 1 {
		t.Fatal("another actor's evidence entered Alice's history")
	}
}
