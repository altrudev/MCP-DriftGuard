package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

func Normalize(s Snapshot) (Snapshot, error) {
	s.ObservedAt = ""
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].Name < s.Tools[j].Name })
	sort.Slice(s.Resources, func(i, j int) bool {
		if s.Resources[i].URI == s.Resources[j].URI {
			return s.Resources[i].Name < s.Resources[j].Name
		}
		return s.Resources[i].URI < s.Resources[j].URI
	})
	sort.Slice(s.Prompts, func(i, j int) bool { return s.Prompts[i].Name < s.Prompts[j].Name })
	for i := range s.Tools {
		var err error
		s.Tools[i].InputSchema, err = normalizeJSON(s.Tools[i].InputSchema)
		if err != nil { return s, fmt.Errorf("normalize tool %q schema: %w", s.Tools[i].Name, err) }
		s.Tools[i].Annotations, err = normalizeJSON(s.Tools[i].Annotations)
		if err != nil { return s, fmt.Errorf("normalize tool %q annotations: %w", s.Tools[i].Name, err) }
	}
	for i := range s.Prompts {
		var err error
		s.Prompts[i].Arguments, err = normalizeJSON(s.Prompts[i].Arguments)
		if err != nil { return s, fmt.Errorf("normalize prompt %q arguments: %w", s.Prompts[i].Name, err) }
	}
	var err error
	s.Auth.ProtectedResourceMeta, err = normalizeJSON(s.Auth.ProtectedResourceMeta)
	if err != nil { return s, fmt.Errorf("normalize protected resource metadata: %w", err) }
	s.Auth.AuthorizationMeta, err = normalizeJSON(s.Auth.AuthorizationMeta)
	if err != nil { return s, fmt.Errorf("normalize authorization metadata: %w", err) }
	return s, nil
}

func Bytes(s Snapshot) ([]byte, error) {
	n, err := Normalize(s)
	if err != nil { return nil, err }
	return json.Marshal(n)
}

func Hash(s Snapshot) (string, error) {
	b, err := Bytes(s)
	if err != nil { return "", err }
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func normalizeJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 { return nil, nil }
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil { return nil, err }
	b, err := json.Marshal(v)
	if err != nil { return nil, err }
	return b, nil
}
