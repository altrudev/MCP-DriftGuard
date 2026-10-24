package evidence

import "testing"

func TestAllSemanticDimensions(t *testing.T) {
	old := Claim{ID: "receipt/1", Actor: "agent-A", ReceiptMeaning: "accepted", TimestampMeaning: "issued", AuthorityMeaning: "signed", ErrorMeaning: "retryable", AcknowledgementMeaning: "received", ProvenanceMeaning: "producer", ReconstructionMeaning: "branches-preserved"}
	variations := []struct {
		name   string
		modify func(*Claim)
	}{
		{"actor", func(c *Claim) { c.Actor = "agent-B" }},
		{"receipt_meaning", func(c *Claim) { c.ReceiptMeaning = "executed" }},
		{"timestamp_meaning", func(c *Claim) { c.TimestampMeaning = "observed" }},
		{"authority_meaning", func(c *Claim) { c.AuthorityMeaning = "self-asserted" }},
		{"error_meaning", func(c *Claim) { c.ErrorMeaning = "terminal" }},
		{"acknowledgement_meaning", func(c *Claim) { c.AcknowledgementMeaning = "processed" }},
		{"provenance_meaning", func(c *Claim) { c.ProvenanceMeaning = "unknown" }},
		{"reconstruction_meaning", func(c *Claim) { c.ReconstructionMeaning = "latest-only" }},
	}
	for _, v := range variations {
		t.Run(v.name, func(t *testing.T) {
			changed := old
			v.modify(&changed)
			r, err := Compare([]Claim{old}, []Claim{changed})
			if err != nil || r.Match || len(r.Changes) != 1 || r.Changes[0].Field != v.name {
				t.Fatalf("unexpected: %+v %v", r, err)
			}
		})
	}
	r, err := Compare([]Claim{old}, []Claim{old})
	if err != nil || !r.Match {
		t.Fatal(r, err)
	}
}
func TestRejectAmbiguousAndMissingClaims(t *testing.T) {
	c := Claim{ID: "x", Actor: "a"}
	for _, tc := range []struct {
		before, after []Claim
		invalid       bool
	}{
		{[]Claim{c, c}, []Claim{c}, true},
		{[]Claim{{Actor: "a"}}, []Claim{c}, true},
		{[]Claim{c}, []Claim{}, false},
		{[]Claim{}, []Claim{c}, false},
	} {
		r, e := Compare(tc.before, tc.after)
		if tc.invalid {
			if e == nil {
				t.Fatal("accepted ambiguous claims")
			}
		} else if e != nil || r.Match {
			t.Fatalf("missing drift %v %+v", e, r)
		}
	}
}
