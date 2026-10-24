package evidence

import (
	"strings"
	"testing"
)

func discoveryFixture() Discovery {
	return Discovery{Method: "tools/list", RequestID: "1", RequestHash: strings.Repeat("a", 64), ResponseHash: strings.Repeat("b", 64), Endpoint: "https://fixture.invalid/mcp", StartedAt: "2026-10-24T12:00:00Z", CompletedAt: "2026-10-24T12:00:01Z", HTTPStatus: 200, Status: "response"}
}

func TestDiscoveryAuthorityRetriesAndComparison(t *testing.T) {
	f := fixture(t)
	d := discoveryFixture()
	if err := f.l.RecordDiscovery(d, "alice", "b", "first", "", f.priv["alice"]); err == nil {
		t.Fatal("cross actor claim accepted")
	}
	if f.l.Head() != "" {
		t.Fatal("failed append mutated ledger")
	}
	if err := f.l.RecordDiscovery(d, "alice", "a", "first", "", f.priv["bob"]); err == nil {
		t.Fatal("wrong signer accepted")
	}
	if err := f.l.RecordDiscovery(d, "alice", "a", "first", "", f.priv["alice"]); err != nil {
		t.Fatal(err)
	}
	first := f.l.File().Observations[0]
	d.ResponseHash = strings.Repeat("c", 64)
	if err := f.l.RecordDiscovery(d, "alice", "a", "retry", first.Digest, f.priv["alice"]); err != nil {
		t.Fatal(err)
	}
	second := f.l.File().Observations[1]
	result, err := CompareDiscovery(first, second)
	if err != nil || result.Match || len(result.Changes) != 1 || result.Changes[0].Severity != "UNKNOWN" {
		t.Fatalf("unsupported semantic claim: %+v %v", result, err)
	}
	same, err := CompareDiscovery(first, first)
	if err != nil || !same.Match {
		t.Fatal("same facts differ")
	}
	second.Discovery.RequestHash = strings.Repeat("d", 64)
	if _, err := CompareDiscovery(first, second); err == nil {
		t.Fatal("different request treated as comparable")
	}
	if len(f.l.History("bob", 10)) != 0 || len(f.l.History("alice", 1)) != 1 {
		t.Fatal("history scope failure")
	}
	for _, change := range []func(*Discovery){
		func(d *Discovery) { d.Method = "tools/call" },
		func(d *Discovery) { d.Endpoint = "https://user:secret@fixture.invalid/mcp" },
		func(d *Discovery) { d.CompletedAt = "2026-10-24T11:00:00Z" },
		func(d *Discovery) { d.ResponseHash = "" },
		func(d *Discovery) { d.Status = "executed" },
	} {
		bad := discoveryFixture()
		change(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatal("invalid discovery accepted")
		}
	}
}
