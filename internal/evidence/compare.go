// Package evidence compares declared evidence contracts, not observed MCP tool behaviour.
// Unknown or absent evidence is never upgraded to proof by this comparison.
package evidence

import (
	"fmt"
	"sort"
)

type Claim struct {
	ID                     string `json:"id"`
	Actor                  string `json:"actor"`
	ReceiptMeaning         string `json:"receipt_meaning"`
	TimestampMeaning       string `json:"timestamp_meaning"`
	AuthorityMeaning       string `json:"authority_meaning"`
	ErrorMeaning           string `json:"error_meaning"`
	AcknowledgementMeaning string `json:"acknowledgement_meaning"`
	ProvenanceMeaning      string `json:"provenance_meaning"`
	ReconstructionMeaning  string `json:"reconstruction_meaning"`
}
type Change struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Severity string `json:"severity"`
}
type Result struct {
	Match   bool     `json:"match"`
	Changes []Change `json:"changes"`
}

// Compare fails closed for invalid/ambiguous identities. It compares explicitly
// declared contracts; neither missing declarations nor equality prove runtime integrity.
func Compare(before, after []Claim) (Result, error) {
	a, err := index(before)
	if err != nil {
		return Result{}, err
	}
	b, err := index(after)
	if err != nil {
		return Result{}, err
	}
	out := Result{Match: true, Changes: []Change{}}
	for id, old := range a {
		next, ok := b[id]
		if !ok {
			out.Changes = append(out.Changes, Change{id, "claim", old.ID, "", "HIGH"})
			continue
		}
		fields := []struct{ name, old, new string }{
			{"actor", old.Actor, next.Actor},
			{"receipt_meaning", old.ReceiptMeaning, next.ReceiptMeaning},
			{"timestamp_meaning", old.TimestampMeaning, next.TimestampMeaning},
			{"authority_meaning", old.AuthorityMeaning, next.AuthorityMeaning},
			{"error_meaning", old.ErrorMeaning, next.ErrorMeaning},
			{"acknowledgement_meaning", old.AcknowledgementMeaning, next.AcknowledgementMeaning},
			{"provenance_meaning", old.ProvenanceMeaning, next.ProvenanceMeaning},
			{"reconstruction_meaning", old.ReconstructionMeaning, next.ReconstructionMeaning},
		}
		for _, f := range fields {
			if f.old != f.new {
				out.Changes = append(out.Changes, Change{id, f.name, f.old, f.new, "HIGH"})
			}
		}
	}
	for id := range b {
		if _, ok := a[id]; !ok {
			out.Changes = append(out.Changes, Change{id, "claim", "", id, "HIGH"})
		}
	}
	sort.Slice(out.Changes, func(i, j int) bool {
		if out.Changes[i].ID == out.Changes[j].ID {
			return out.Changes[i].Field < out.Changes[j].Field
		}
		return out.Changes[i].ID < out.Changes[j].ID
	})
	out.Match = len(out.Changes) == 0
	return out, nil
}
func index(xs []Claim) (map[string]Claim, error) {
	result := make(map[string]Claim, len(xs))
	for _, x := range xs {
		if x.ID == "" || x.Actor == "" {
			return nil, fmt.Errorf("evidence claim requires nonempty ID and actor")
		}
		if _, exists := result[x.ID]; exists {
			return nil, fmt.Errorf("duplicate evidence claim ID %q", x.ID)
		}
		result[x.ID] = x
	}
	return result, nil
}
