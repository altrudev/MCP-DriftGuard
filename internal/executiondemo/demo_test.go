package executiondemo

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/evidence"
)

func TestConfirmation(t *testing.T) {
	if _, e := Run(""); e == nil {
		t.Fatal("silent execution")
	}
}
func TestEndToEnd(t *testing.T) {
	a, e := run(Confirmation, &memoryHTTP{})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	var reconstructed Artifact
	if e = json.Unmarshal(raw, &reconstructed); e != nil {
		t.Fatal(e)
	}
	ledgerJSON, _ := json.Marshal(reconstructed.Ledger)
	f, e := evidence.DecodeLedger(bytes.NewReader(ledgerJSON))
	if e != nil {
		t.Fatal(e)
	}
	l, e := evidence.VerifyLedger(f, a.Manifest, a.DeclarationKey, a.ActorKeys, a.Head)
	if e != nil {
		t.Fatal(e)
	}
	phases := map[string]int{}
	original := ""
	retry := ""
	timeoutRequest := ""
	timeoutRequests := 0
	for _, o := range l.File().Observations {
		var f fact
		if e = json.Unmarshal([]byte(o.Value), &f); e != nil {
			t.Fatal(e)
		}
		phases[f.Phase]++
		if o.Actor == "observer" && o.Branch == "timeout" && f.Operation == "timeout" && f.Phase == "request_observed" {
			timeoutRequest = f.RequestHash
			timeoutRequests++
		}
		if o.Actor == "observer" && o.Branch == "first" && f.Phase == "request_observed" {
			original = f.RequestHash
		}
		if o.Actor == "observer" && o.Branch == "retry" {
			retry = o.RetryOf
			if retry == "" {
				t.Fatal("missing retry ancestry")
			}
		}
		if o.Actor == "verifier" && f.Operation == "normal" && (f.Present == nil || !*f.Present || f.RequestHash != original) {
			t.Fatal("retry changed stored correlation")
		}
		if f.Operation == "false-success" && o.Actor == "verifier" && (f.Present == nil || *f.Present) {
			t.Fatal("false success undetected")
		}
		if f.Phase == "outcome_unknown" && o.State != "unknown" {
			t.Fatal("timeout certainty")
		}
		if f.Operation == "timeout" && o.Actor == "verifier" {
			if f.Present == nil || !*f.Present {
				t.Fatal("timeout lost committed record")
			}
			if timeoutRequest == "" || f.RequestHash != timeoutRequest {
				t.Fatalf("timeout read-back request hash = %q, want %q", f.RequestHash, timeoutRequest)
			}
		}
	}
	if timeoutRequests != 1 || timeoutRequest == "" {
		t.Fatal("expected one nonempty timeout request hash")
	}
	if phases["request_observed"] != 4 || phases["response_acknowledged"] != 3 || phases["outcome_unknown"] != 1 || phases["independent_state_observed"] != 4 {
		t.Fatal(phases)
	}
	for _, o := range l.History("verifier", 100) {
		if o.Actor != "verifier" {
			t.Fatal("actor leak")
		}
	}
	// A verifier key cannot forge an observer assertion or use cross-actor support.
	o := f.Observations[0]
	o.Actor = "verifier"
	o.Signature = ""
	if _, e = evidence.VerifyLedger(evidence.LedgerFile{Format: f.Format, Observations: []evidence.Observation{o}}, a.Manifest, a.DeclarationKey, a.ActorKeys, ""); e == nil {
		t.Fatal("actor substitution")
	}
	// Tamper and valid-prefix truncation are separate threats.
	f.Observations[0].Value = "tampered"
	if _, e = evidence.VerifyLedger(f, a.Manifest, a.DeclarationKey, a.ActorKeys, a.Head); e == nil {
		t.Fatal("tamper accepted")
	}
	f = a.Ledger
	f.Observations = f.Observations[:len(f.Observations)-1]
	if _, e = evidence.VerifyLedger(f, a.Manifest, a.DeclarationKey, a.ActorKeys, a.Head); e == nil {
		t.Fatal("truncation accepted")
	}
	if _, e = evidence.VerifyLedger(f, a.Manifest, a.DeclarationKey, a.ActorKeys, ""); e != nil {
		t.Fatal("valid prefix should require external checkpoint to detect truncation", e)
	}
}
func TestProxyRejectsBeforeForwarding(t *testing.T) {
	l := &lab{} // A denied request cannot access transport or ledger.
	for _, tc := range []struct {
		body, confirm string
		status        int
	}{
		{`{}`, "", 403},
		{`{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{"name":"mock.put_record","arguments":{"operation":"normal"}}}`, Confirmation, 403},
		{`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"shell","arguments":{"operation":"normal"}}}`, Confirmation, 403},
		{`{"url":"http://169.254.169.254"}`, Confirmation, 403},
		{string(bytes.Repeat([]byte("x"), 4097)), Confirmation, 403},
	} {
		r := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(tc.body))
		r.Header.Set("X-Demo-Confirmation", tc.confirm)
		w := httptest.NewRecorder()
		l.proxy(w, r)
		if w.Code != tc.status {
			t.Fatal(w.Code)
		}
	}
}
func TestReplayAndReadOnly(t *testing.T) {
	a, e := run(Confirmation, &memoryHTTP{})
	if e != nil {
		t.Fatal(e)
	}
	ledger, e := evidence.NewLedger(a.Manifest, a.DeclarationKey, a.ActorKeys)
	if e != nil {
		t.Fatal(e)
	}
	for _, o := range a.Ledger.Observations {
		if e = ledger.Append(o); e != nil {
			t.Fatal(e)
		}
	}
	l := &lab{ledger: ledger, keys: map[string]ed25519.PrivateKey{}}
	r := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":"first","method":"tools/call","params":{"name":"mock.put_record","arguments":{"operation":"normal"}}}`))
	r.Header.Set("X-Demo-Confirmation", Confirmation)
	w := httptest.NewRecorder()
	l.proxy(w, r)
	if w.Code != http.StatusConflict {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	l.state(w, httptest.NewRequest("POST", "/records", nil))
	if w.Code != 403 {
		t.Fatal("state surface permits mutation")
	}
}
