// Package executiondemo is an opt-in, in-process synthetic MCP execution laboratory.
// It cannot select remote targets or accept user tool arguments.
package executiondemo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/evidence"
)

const Confirmation = "execute-local-mock-only"

type call struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  params `json:"params"`
}
type params struct {
	Name      string    `json:"name"`
	Arguments arguments `json:"arguments"`
}
type arguments struct {
	Operation string `json:"operation"`
}
type record struct {
	Operation   string `json:"operation"`
	RequestHash string `json:"request_sha256"`
}
type fact struct {
	Phase        string `json:"phase"`
	Operation    string `json:"operation"`
	RequestHash  string `json:"request_sha256"`
	ResponseHash string `json:"response_sha256,omitempty"`
	Present      *bool  `json:"present,omitempty"`
}

// Artifact contains public trust material only. Retain Head separately to detect suffix removal.
type Artifact struct {
	Manifest       evidence.Manifest            `json:"manifest"`
	DeclarationKey ed25519.PublicKey            `json:"declaration_key"`
	ActorKeys      map[string]ed25519.PublicKey `json:"actor_keys"`
	Ledger         evidence.LedgerFile          `json:"ledger"`
	Head           string                       `json:"head"`
}
type lab struct {
	observerMu sync.Mutex
	mu         sync.Mutex
	records    map[string]record
	ledger     *evidence.Ledger
	manifest   evidence.Manifest
	keys       map[string]ed25519.PrivateKey
	client     *http.Client
	target     string
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func decode(r io.Reader, v any) error {
	b, e := io.ReadAll(io.LimitReader(r, 4097))
	if e != nil {
		return e
	}
	if len(b) > 4096 {
		return errors.New("body bound")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (l *lab) append(actor, branch, retry, state, kind string, f fact) error {
	b, _ := json.Marshal(f)
	o, e := evidence.SignObservation(evidence.Observation{Sequence: len(l.ledger.File().Observations) + 1, Previous: l.ledger.Head(), Contract: l.manifest.Digest, Actor: actor, Claim: actor, Branch: branch, RetryOf: retry, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), State: state, Kind: kind, Source: "local-mock/" + actor, Value: string(b)}, l.keys[actor])
	if e != nil {
		return e
	}
	return l.ledger.Append(o)
}
func valid(c call) bool {
	return c.JSONRPC == "2.0" && c.ID != "" && len(c.ID) <= 32 && c.Method == "tools/call" && c.Params.Name == "mock.put_record" && (c.Params.Arguments.Operation == "normal" || c.Params.Arguments.Operation == "false-success" || c.Params.Arguments.Operation == "timeout")
}
func (l *lab) mock(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.RequestURI() != "/mcp" {
		http.Error(w, "denied", 403)
		return
	}
	var c call
	if decode(r.Body, &c) != nil || !valid(c) {
		http.Error(w, "denied", 403)
		return
	}
	b, _ := json.Marshal(c)
	l.mu.Lock()
	if c.Params.Arguments.Operation != "false-success" {
		if _, exists := l.records[c.Params.Arguments.Operation]; !exists {
			l.records[c.Params.Arguments.Operation] = record{c.Params.Arguments.Operation, hash(b)}
		}
	}
	l.mu.Unlock()
	if c.Params.Arguments.Operation == "timeout" {
		select {
		case <-r.Context().Done():
		case <-time.After(1500 * time.Millisecond):
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": c.ID, "result": map[string]any{"content": []any{}, "isError": false}})
}

// state is a separate read-only surface; it never calls the proxy or tools/call.
func (l *lab) state(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.URL.Path != "/records" || r.URL.RawQuery != "" {
		http.Error(w, "denied", 403)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(w).Encode(l.records)
}
func (l *lab) proxy(w http.ResponseWriter, r *http.Request) {
	l.observerMu.Lock()
	defer l.observerMu.Unlock()
	if r.Method != "POST" || r.URL.RequestURI() != "/mcp" || r.Header.Get("X-Demo-Confirmation") != Confirmation {
		http.Error(w, "confirmation required", 403)
		return
	}
	var c call
	if decode(r.Body, &c) != nil || !valid(c) {
		http.Error(w, "unauthorized tool", 403)
		return
	}
	b, _ := json.Marshal(c)
	op := c.Params.Arguments.Operation
	// The lab serializes acquisitions; no production concurrent ledger writer is implied.
	branch := c.ID
	retry := ""
	for _, o := range l.ledger.File().Observations {
		var f fact
		_ = json.Unmarshal([]byte(o.Value), &f)
		if o.Actor == "observer" && f.Operation == op {
			retry = o.Digest
			break
		}
	}
	// Replayed IDs are rejected before forwarding. New IDs use the same operation idempotency key.
	for _, o := range l.ledger.File().Observations {
		if o.Actor == "observer" && o.Branch == branch {
			http.Error(w, "replay denied", 409)
			return
		}
	}
	f := fact{Phase: "request_observed", Operation: op, RequestHash: hash(b)}
	if l.append("observer", branch, retry, "observed", "receipt", f) != nil {
		http.Error(w, "evidence failure", 500)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", l.target+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, e := l.client.Do(req)
	if e != nil {
		f.Phase = "outcome_unknown"
		if l.append("observer", branch, retry, "unknown", "error", f) != nil {
			http.Error(w, "evidence failure", 500)
			return
		}
		http.Error(w, "outcome unknown", 504)
		return
	}
	defer resp.Body.Close()
	var result struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Result  *struct {
			Content []any `json:"content"`
			IsError bool  `json:"isError"`
		} `json:"result"`
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || len(raw) > 4096 || resp.StatusCode != 200 || decode(bytes.NewReader(raw), &result) != nil || result.ID != c.ID || result.JSONRPC != "2.0" || result.Result == nil || result.Result.IsError {
		f.Phase = "outcome_unknown"
		f.ResponseHash = hash(raw)
		if err := l.append("observer", branch, retry, "unknown", "error", f); err != nil {
			http.Error(w, "evidence failure", 500)
			return
		}
		http.Error(w, "invalid response", 502)
		return
	}
	f.Phase = "response_acknowledged"
	f.ResponseHash = hash(raw)
	if l.append("observer", branch, retry, "observed", "acknowledgement", f) != nil {
		http.Error(w, "evidence failure", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
func (l *lab) verify(endpoint, op string) error {
	resp, e := l.client.Get(endpoint + "/records")
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	records := map[string]record{}
	if resp.StatusCode != 200 {
		return errors.New("state unavailable")
	}
	if e = decode(resp.Body, &records); e != nil {
		return e
	}
	rec, present := records[op]
	return l.append("verifier", op, "", "observed", "assertion", fact{Phase: "independent_state_observed", Operation: op, RequestHash: rec.RequestHash, Present: &present})
}

// Run requires explicit confirmation before creating listeners. All destinations are
// freshly allocated loopback servers. No environment proxy, redirects or credentials.
func Run(confirmation string) (Artifact, error) { return run(confirmation, nil) }

func run(confirmation string, local *memoryHTTP) (Artifact, error) {
	if confirmation != Confirmation {
		return Artifact{}, errors.New("explicit local mock confirmation required")
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Artifact{}, e
	}
	l := &lab{records: map[string]record{}, keys: map[string]ed25519.PrivateKey{}}
	actors := map[string]ed25519.PublicKey{}
	claims := []evidence.Claim{}
	for _, actor := range []string{"observer", "verifier"} {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return Artifact{}, e
		}
		actors[actor] = p
		l.keys[actor] = k
		claims = append(claims, evidence.Claim{ID: actor, Actor: actor})
	}
	l.manifest, e = evidence.Sign(claims, priv)
	if e != nil {
		return Artifact{}, e
	}
	l.ledger, e = evidence.NewLedger(l.manifest, pub, actors)
	if e != nil {
		return Artifact{}, e
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	l.client = &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	var stateURL, proxyURL string
	if local == nil {
		mock, err := localServer(l.mock)
		if err != nil {
			return Artifact{}, err
		}
		defer mock.Close()
		l.target = mock.URL
		state, err := localServer(l.state)
		if err != nil {
			return Artifact{}, err
		}
		defer state.Close()
		stateURL = state.URL
		proxy, err := localServer(l.proxy)
		if err != nil {
			return Artifact{}, err
		}
		defer proxy.Close()
		proxyURL = proxy.URL
	} else {
		l.target = "http://mock"
		stateURL = "http://state"
		proxyURL = "http://proxy"
		local.handlers = map[string]http.HandlerFunc{"mock": l.mock, "state": l.state, "proxy": l.proxy}
		l.client.Transport = local
	}
	for _, item := range []struct{ op, id string }{{"normal", "first"}, {"normal", "retry"}, {"false-success", "false"}, {"timeout", "timeout"}} {
		c := call{"2.0", item.id, "tools/call", params{"mock.put_record", arguments{item.op}}}
		b, _ := json.Marshal(c)
		req, _ := http.NewRequest("POST", proxyURL+"/mcp", bytes.NewReader(b))
		req.Header.Set("X-Demo-Confirmation", confirmation)
		resp, e := l.client.Do(req)
		if e != nil {
			return Artifact{}, e
		}
		_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		if e != nil {
			return Artifact{}, e
		}
		if resp.StatusCode != 200 && resp.StatusCode != 504 {
			return Artifact{}, errors.New("demo proxy failed")
		}
		if e = l.verify(stateURL, item.op); e != nil {
			return Artifact{}, e
		}
	}
	return Artifact{l.manifest, pub, actors, l.ledger.File(), l.ledger.Head()}, nil
}

// memoryHTTP exercises the same HTTP handlers without sockets in restricted test environments.
// It has no network fallback and is never selected by the CLI.
type memoryHTTP struct{ handlers map[string]http.HandlerFunc }

func (m *memoryHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	h, ok := m.handlers[r.URL.Host]
	if !ok {
		return nil, errors.New("unknown local fixture")
	}
	done := make(chan *http.Response, 1)
	go func() { w := httptest.NewRecorder(); h(w, r); done <- w.Result() }()
	select {
	case resp := <-done:
		return resp, nil
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
}

func localServer(h http.HandlerFunc) (*httptest.Server, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &httptest.Server{Listener: listener, Config: &http.Server{Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 4096}}
	s.Start()
	return s, nil
}
