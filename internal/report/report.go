package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
	mdiff "github.com/altrudev/MCP-DriftGuard/internal/diff"
)

func Snapshot(w io.Writer, s canonical.Snapshot, format string) error {
	if format == "json" {
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	if format == "sarif" {
		return fmt.Errorf("sarif is only supported for diff and verify results")
	}
	h, err := canonical.Hash(s)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "MCP DriftGuard\nEndpoint: %s\nServer: %s %s\nProtocol: %s\nTools: %d  Resources: %d  Prompts: %d\nFingerprint: %s\n", s.Endpoint, s.Server.Name, s.Server.Version, s.Server.ProtocolVersion, len(s.Tools), len(s.Resources), len(s.Prompts), h)
	return err
}

func Diff(w io.Writer, r mdiff.Result, format string) error {
	switch format {
	case "json":
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case "sarif":
		return writeSARIF(w, r)
	case "text":
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}

	verdict := "PASS"
	if !r.Match {
		if r.Score >= 35 {
			verdict = "FAIL"
		} else {
			verdict = "REVIEW"
		}
	}
	if _, err := fmt.Fprintf(w, "MCP DriftGuard\nVerdict: %s\nRisk: %s (%d/100)\n", verdict, r.Risk, r.Score); err != nil {
		return err
	}
	for _, c := range r.Changes {
		if _, err := fmt.Fprintf(w, "%-8s %-13s %-8s %s — %s\n", c.Severity, c.Category, c.Kind, c.Path, c.Message); err != nil {
			return err
		}
	}
	return nil
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Version        string `json:"version,omitempty"`
}

type sarifResult struct {
	RuleID     string         `json:"ruleId"`
	Level      string         `json:"level"`
	Message    sarifMessage   `json:"message"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func writeSARIF(w io.Writer, r mdiff.Result) error {
	out := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "MCP DriftGuard",
				InformationURI: "https://github.com/altrudev/MCP-DriftGuard",
				Version:        "0.1.0",
			}},
			Properties: map[string]any{"risk": r.Risk, "score": r.Score, "baselineMatch": r.Match},
		}},
	}
	for _, c := range r.Changes {
		out.Runs[0].Results = append(out.Runs[0].Results, sarifResult{
			RuleID:  "MCPDRIFT_" + strings.ToUpper(c.Category),
			Level:   sarifLevel(c.Severity),
			Message: sarifMessage{Text: c.Message + " (" + c.Path + ")"},
			Properties: map[string]any{
				"severity": c.Severity,
				"category": c.Category,
				"path":     c.Path,
				"kind":     c.Kind,
				"before":   c.Before,
				"after":    c.After,
			},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func sarifLevel(s mdiff.Severity) string {
	switch s {
	case mdiff.Critical, mdiff.High:
		return "error"
	case mdiff.Medium:
		return "warning"
	default:
		return "note"
	}
}
