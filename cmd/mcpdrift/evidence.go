package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/altrudev/MCP-DriftGuard/internal/baseline"
	"github.com/altrudev/MCP-DriftGuard/internal/evidence"
)

// evidenceVerify is entirely offline. Trust keys come from operator configuration,
// never from the ledger being verified.
func evidenceVerify(args []string) int {
	fs := flag.NewFlagSet("evidence-verify", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "signed declaration manifest")
	key := fs.String("verify-key", "", "trusted declaration public key PEM")
	trust := fs.String("actor-keys", "", "JSON object mapping actors to trusted public key PEM paths")
	head := fs.String("expected-head", "", "independently retained ledger checkpoint digest")
	if fs.Parse(args) != nil || fs.NArg() != 1 || *manifest == "" || *key == "" || *trust == "" {
		return 3
	}
	pub, err := baseline.LoadPublicKey(*key)
	if err != nil {
		return fail(err, 4)
	}
	m, err := evidence.Read(*manifest)
	if err != nil {
		return fail(err, 4)
	}
	// Check trust before reading attacker-supplied ledger input.
	if err = m.Verify(pub); err != nil {
		return fail(err, 5)
	}
	file, err := os.Open(*trust)
	if err != nil {
		return fail(err, 4)
	}
	raw, err := io.ReadAll(io.LimitReader(file, evidence.MaxLedgerBytes+1))
	file.Close()
	if err != nil {
		return fail(err, 4)
	}
	if len(raw) > evidence.MaxLedgerBytes {
		return fail(fmt.Errorf("actor trust configuration too large"), 4)
	}
	paths := map[string]string{}
	if err = json.Unmarshal(raw, &paths); err != nil {
		return fail(err, 4)
	}
	keys := map[string]ed25519.PublicKey{}
	for actor, path := range paths {
		k, err := baseline.LoadPublicKey(path)
		if err != nil {
			return fail(err, 4)
		}
		keys[actor] = k
	}
	input, err := os.Open(fs.Arg(0))
	if err != nil {
		return fail(err, 4)
	}
	defer input.Close()
	f, err := evidence.DecodeLedger(input)
	if err != nil {
		return fail(err, 5)
	}
	ledger, err := evidence.VerifyLedger(f, m, pub, keys, *head)
	if err != nil {
		return fail(err, 5)
	}
	result := struct {
		Scope      string `json:"scope"`
		Count      int    `json:"observations"`
		Head       string `json:"head"`
		Checkpoint bool   `json:"checkpoint_matched"`
	}{"offline signed assertions; no live MCP observation", len(f.Observations), ledger.Head(), *head != ""}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return fail(err, 4)
	}
	return 0
}
