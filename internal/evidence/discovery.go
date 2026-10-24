package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"
)

// Discovery is an observer's account of one discovery RPC, never tool execution.
// Hashes cover request JSON and the bounded decoded RPC response body, not headers.
type Discovery struct {
	Method       string `json:"method"`
	RequestID    string `json:"request_id"`
	RequestHash  string `json:"request_sha256"`
	ResponseHash string `json:"response_sha256,omitempty"`
	Endpoint     string `json:"endpoint"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at"`
	HTTPStatus   int    `json:"http_status"`
	Status       string `json:"status"`
	RPCCode      *int   `json:"rpc_code,omitempty"`
}

func (d Discovery) Validate() error {
	switch d.Method {
	case "server/discover", "initialize", "tools/list", "resources/list", "prompts/list":
	default:
		return errors.New("not an allowed discovery RPC")
	}
	u, err := url.Parse(d.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("discovery endpoint must be credential-free and query-free")
	}
	start, err := time.Parse(time.RFC3339Nano, d.StartedAt)
	if err != nil {
		return err
	}
	end, err := time.Parse(time.RFC3339Nano, d.CompletedAt)
	if err != nil || end.Before(start) {
		return errors.New("invalid discovery chronology")
	}
	if !validHash(d.RequestHash) || d.RequestID == "" || (d.ResponseHash != "" && !validHash(d.ResponseHash)) {
		return errors.New("invalid discovery request or response binding")
	}
	switch d.Status {
	case "transport_error", "http_error", "decode_error", "rpc_error", "response":
	default:
		return errors.New("invalid discovery outcome")
	}
	if d.HTTPStatus < 0 || d.HTTPStatus > 599 || (d.Status != "transport_error" && d.HTTPStatus < 100) {
		return errors.New("invalid HTTP status")
	}
	if (d.Status == "transport_error" && d.HTTPStatus != 0) || (d.Status == "http_error" && d.HTTPStatus >= 200 && d.HTTPStatus < 300) || ((d.Status == "response" || d.Status == "rpc_error" || d.Status == "decode_error") && (d.HTTPStatus < 200 || d.HTTPStatus >= 300)) {
		return errors.New("HTTP status inconsistent with outcome")
	}
	if (d.Status == "rpc_error") != (d.RPCCode != nil) {
		return errors.New("RPC error code inconsistent with outcome")
	}
	if (d.Status == "response" || d.Status == "rpc_error") && d.ResponseHash == "" {
		return errors.New("RPC outcome requires response hash")
	}
	return nil
}

// RecordDiscovery signs and appends without replacing any previous attempt.
// Caller selects an observer-owned claim, branch and optional retry parent.
func (l *Ledger) RecordDiscovery(d Discovery, actor, claim, branch, retry string, key ed25519.PrivateKey) error {
	if err := d.Validate(); err != nil {
		return err
	}
	kind := "receipt"
	if d.Status != "response" {
		kind = "error"
	}
	o, err := SignObservation(Observation{Sequence: len(l.records) + 1, Previous: l.Head(), Contract: l.manifest, Actor: actor, Claim: claim, Branch: branch, RetryOf: retry, ObservedAt: d.CompletedAt, State: "observed", Kind: kind, Source: d.Endpoint, Value: "discovery RPC outcome; tool execution unknown", Discovery: &d}, key)
	if err != nil {
		return err
	}
	return l.Append(o)
}

// CompareDiscovery reports only demonstrable changes in comparable observer facts.
// Different response hashes are byte drift candidates, not proof of changed tool behavior.
func CompareDiscovery(a, b Observation) (Result, error) {
	if a.Discovery == nil || b.Discovery == nil || a.Actor != b.Actor || a.Claim != b.Claim || a.Contract != b.Contract {
		return Result{}, errors.New("incomparable discovery observations")
	}
	if err := a.Discovery.Validate(); err != nil {
		return Result{}, err
	}
	if err := b.Discovery.Validate(); err != nil {
		return Result{}, err
	}
	x, y := *a.Discovery, *b.Discovery
	if x.Endpoint != y.Endpoint || x.Method != y.Method || x.RequestHash != y.RequestHash {
		return Result{}, errors.New("different endpoint, method or request; meaning unknown")
	}
	out := Result{Match: true, Changes: []Change{}}
	add := func(field, old, next, severity string) {
		if old != next {
			out.Changes = append(out.Changes, Change{a.Claim, field, old, next, severity})
		}
	}
	add("discovery_status", x.Status, y.Status, "HIGH")
	code := func(v any) string { p, _ := json.Marshal(v); return string(p) }
	add("http_status", code(x.HTTPStatus), code(y.HTTPStatus), "HIGH")
	add("rpc_code", code(x.RPCCode), code(y.RPCCode), "HIGH")
	add("response_bytes", x.ResponseHash, y.ResponseHash, "UNKNOWN")
	out.Match = len(out.Changes) == 0
	return out, nil
}

func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
