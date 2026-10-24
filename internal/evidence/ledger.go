package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	LedgerFormat        = "mcpdrift-evidence-ledger/v1"
	ObservationFormat   = "mcpdrift-evidence-observation/v1"
	MaxObservations     = 4096
	MaxObservationBytes = 16 * 1024
	MaxLedgerBytes      = 8 * 1024 * 1024
)

// Observation records an actor's assertion at acquisition time. State is an
// epistemic label, never a promotion of a receipt or acknowledgement to success.
type Observation struct {
	Format     string   `json:"format"`
	Sequence   int      `json:"sequence"`
	Previous   string   `json:"previous"`
	Contract   string   `json:"contract"`
	Actor      string   `json:"actor"`
	Claim      string   `json:"claim"`
	Branch     string   `json:"branch"`
	RetryOf    string   `json:"retry_of,omitempty"`
	ObservedAt string   `json:"observed_at"`
	EventAt    string   `json:"event_at,omitempty"`
	State      string   `json:"state"` // unknown, inferred, observed
	Kind       string   `json:"kind"`  // receipt, acknowledgement, error, assertion
	Source     string   `json:"source"`
	Value      string   `json:"value"`
	Supports   []string `json:"supports,omitempty"`
	Digest     string   `json:"digest"`
	Signature  string   `json:"signature"`
}

type LedgerFile struct {
	Format       string        `json:"format"`
	Observations []Observation `json:"observations"`
}

// Ledger owns all mutable data. Failed appends leave the prefix unchanged.
// It is intended for serial offline verification, not concurrent writers.
type Ledger struct {
	manifest string
	claims   map[string]Claim
	keys     map[string]ed25519.PublicKey
	records  []Observation
	bytes    int
}

func NewLedger(m Manifest, declarationKey ed25519.PublicKey, actorKeys map[string]ed25519.PublicKey) (*Ledger, error) {
	if err := m.Verify(declarationKey); err != nil {
		return nil, err
	}
	claims, err := index(m.Claims)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]ed25519.PublicKey, len(actorKeys))
	for actor, key := range actorKeys {
		if actor == "" || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid actor trust key")
		}
		keys[actor] = append(ed25519.PublicKey(nil), key...)
	}
	return &Ledger{manifest: m.Digest, claims: claims, keys: keys}, nil
}

func observationPayload(o Observation) ([]byte, error) {
	o.Digest = ""
	o.Signature = ""
	return json.Marshal(o)
}

func SignObservation(o Observation, key ed25519.PrivateKey) (Observation, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Observation{}, errors.New("Ed25519 private key required")
	}
	o.Format = ObservationFormat
	b, err := observationPayload(o)
	if err != nil {
		return Observation{}, err
	}
	h := sha256.Sum256(b)
	o.Digest = hex.EncodeToString(h[:])
	o.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, h[:]))
	return cloneObservation(o), nil
}

func cloneObservation(o Observation) Observation {
	o.Supports = append([]string(nil), o.Supports...)
	return o
}

func (l *Ledger) Head() string {
	if len(l.records) == 0 {
		return ""
	}
	return l.records[len(l.records)-1].Digest
}

func (l *Ledger) Append(o Observation) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	if len(l.records) >= MaxObservations || len(b) > MaxObservationBytes || l.bytes+len(b) > MaxLedgerBytes {
		return errors.New("evidence ledger bound exceeded; history is never evicted")
	}
	if o.Format != ObservationFormat || o.Contract != l.manifest || o.Sequence != len(l.records)+1 || o.Previous != l.Head() {
		return errors.New("invalid observation format, contract, sequence or chain")
	}
	claim, ok := l.claims[o.Claim]
	if !ok || claim.Actor != o.Actor {
		return errors.New("observation does not belong to actor's declared claim")
	}
	key, ok := l.keys[o.Actor]
	if !ok {
		return errors.New("untrusted observation actor")
	}
	payload, err := observationPayload(o)
	if err != nil {
		return err
	}
	h := sha256.Sum256(payload)
	sig, err := base64.StdEncoding.DecodeString(o.Signature)
	if err != nil || o.Digest != hex.EncodeToString(h[:]) || !ed25519.Verify(key, h[:], sig) {
		return errors.New("invalid observation signature or digest")
	}
	if o.Branch == "" || o.Source == "" {
		return errors.New("branch and provenance source required")
	}
	if o.State != "unknown" && o.State != "inferred" && o.State != "observed" {
		return errors.New("invalid epistemic state")
	}
	switch o.Kind {
	case "receipt", "acknowledgement", "error", "assertion":
	default:
		return errors.New("invalid observation kind")
	}
	observed, err := time.Parse(time.RFC3339Nano, o.ObservedAt)
	if err != nil {
		return errors.New("invalid observation time")
	}
	if o.EventAt != "" {
		event, err := time.Parse(time.RFC3339Nano, o.EventAt)
		if err != nil || event.After(observed) {
			return errors.New("event time must not exceed acquisition time")
		}
	}
	prior := make(map[string]Observation)
	var branch *Observation
	for i := range l.records {
		r := l.records[i]
		if r.Actor != o.Actor {
			continue
		}
		when, _ := time.Parse(time.RFC3339Nano, r.ObservedAt)
		if when.After(observed) {
			return errors.New("actor acquisition chronology moved backwards")
		}
		prior[r.Digest] = r
		if r.Claim == o.Claim && r.Branch == o.Branch && branch == nil {
			copy := r
			branch = &copy
		}
	}
	seen := map[string]bool{}
	for _, digest := range o.Supports {
		r, ok := prior[digest]
		if !ok || seen[digest] {
			return errors.New("support must uniquely reference earlier same-actor evidence")
		}
		seen[digest] = true
		if o.State == "observed" && r.State != "observed" {
			return errors.New("unknown or inferred support cannot establish observed certainty")
		}
	}
	if branch != nil {
		if o.RetryOf != branch.RetryOf {
			return errors.New("branch retry ancestry changed")
		}
	} else if o.RetryOf != "" {
		parent, ok := prior[o.RetryOf]
		if !ok || parent.Claim != o.Claim || parent.Branch == o.Branch {
			return errors.New("retry must reference an earlier same-actor, same-claim alternate branch")
		}
	}
	l.records = append(l.records, cloneObservation(o))
	l.bytes += len(b)
	return nil
}

// History returns only this actor's prefix, retaining every state and branch.
// Sequence is acquisition order, not event time; later evidence cannot backdate knowledge.
func (l *Ledger) History(actor string, through int) []Observation {
	result := []Observation{}
	for _, o := range l.records {
		if o.Sequence <= through && o.Actor == actor {
			result = append(result, cloneObservation(o))
		}
	}
	return result
}

func (l *Ledger) File() LedgerFile {
	result := LedgerFile{Format: LedgerFormat, Observations: make([]Observation, len(l.records))}
	for i, o := range l.records {
		result.Observations[i] = cloneObservation(o)
	}
	return result
}

// DecodeLedger rejects oversized, unknown-field and trailing JSON input before replay.
func DecodeLedger(r io.Reader) (LedgerFile, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxLedgerBytes+1))
	if err != nil {
		return LedgerFile{}, err
	}
	if len(b) > MaxLedgerBytes {
		return LedgerFile{}, errors.New("ledger input too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var f LedgerFile
	if err := d.Decode(&f); err != nil {
		return f, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return f, errors.New("trailing ledger JSON")
	}
	if f.Format != LedgerFormat || len(f.Observations) > MaxObservations {
		return f, errors.New("invalid ledger format or count")
	}
	return f, nil
}

func VerifyLedger(f LedgerFile, m Manifest, key ed25519.PublicKey, actors map[string]ed25519.PublicKey, expectedHead string) (*Ledger, error) {
	if f.Format != LedgerFormat || len(f.Observations) > MaxObservations {
		return nil, errors.New("invalid ledger format or count")
	}
	l, err := NewLedger(m, key, actors)
	if err != nil {
		return nil, err
	}
	for i, o := range f.Observations {
		if err := l.Append(o); err != nil {
			return nil, fmt.Errorf("observation %d: %w", i+1, err)
		}
	}
	if expectedHead != "" && l.Head() != expectedHead {
		return nil, errors.New("ledger does not match trusted checkpoint head")
	}
	return l, nil
}
