package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
	mdiff "github.com/altrudev/MCP-DriftGuard/internal/diff"
)

func TestSARIFOutput(t *testing.T) {
	result := mdiff.Result{
		Match: false,
		Risk:  "HIGH",
		Score: 35,
		Changes: []mdiff.Change{{
			Severity: mdiff.High,
			Category: "capability",
			Path:     "tools.export_customer_database",
			Kind:     "added",
			After:    "export_customer_database",
			Message:  "new tool exposed",
		}},
	}

	var buf bytes.Buffer
	if err := Diff(&buf, result, "sarif"); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version=%q", doc.Version)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF result count: %#v", doc.Runs)
	}
	if doc.Runs[0].Results[0].RuleID != "MCPDRIFT_CAPABILITY" {
		t.Fatalf("rule=%q", doc.Runs[0].Results[0].RuleID)
	}
	if doc.Runs[0].Results[0].Level != "error" {
		t.Fatalf("level=%q", doc.Runs[0].Results[0].Level)
	}
}

func TestSnapshotRejectsSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Snapshot(&buf, canonical.Snapshot{}, "sarif"); err == nil {
		t.Fatal("snapshot SARIF unexpectedly accepted")
	}
}
