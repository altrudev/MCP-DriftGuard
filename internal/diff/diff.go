package diff

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

type Severity string

const (
	Info     Severity = "INFO"
	Low      Severity = "LOW"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

type Change struct {
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`
	Before   any      `json:"before,omitempty"`
	After    any      `json:"after,omitempty"`
	Message  string   `json:"message"`
}

type Result struct {
	Match   bool     `json:"match"`
	Risk    string   `json:"risk"`
	Score   int      `json:"score"`
	Changes []Change `json:"changes"`
}

func Compare(old, live canonical.Snapshot) Result {
	var changes []Change
	if old.Endpoint != live.Endpoint {
		changes = append(changes, Change{High, "identity", "endpoint", "changed", old.Endpoint, live.Endpoint, "MCP endpoint changed"})
	}
	if old.Server.Name != live.Server.Name {
		changes = append(changes, Change{Medium, "metadata", "server.name", "changed", old.Server.Name, live.Server.Name, "self-reported server name changed"})
	}
	if !sameStrings(old.Server.SupportedVersions, live.Server.SupportedVersions) {
		changes = append(changes, Change{Medium, "protocol", "server.supported_versions", "changed", old.Server.SupportedVersions, live.Server.SupportedVersions, "advertised protocol versions changed"})
	}
	if old.Server.ProtocolVersion != live.Server.ProtocolVersion {
		changes = append(changes, Change{Medium, "protocol", "server.protocol_version", "changed", old.Server.ProtocolVersion, live.Server.ProtocolVersion, "protocol version changed"})
	}
	if old.Auth.WWWAuthenticate != live.Auth.WWWAuthenticate {
		changes = append(changes, Change{High, "authorization", "auth.www_authenticate", "changed", old.Auth.WWWAuthenticate, live.Auth.WWWAuthenticate, "authentication challenge changed"})
	}
	if old.Auth.ResourceMetadataURL != live.Auth.ResourceMetadataURL {
		changes = append(changes, Change{High, "authorization", "auth.resource_metadata_url", "changed", old.Auth.ResourceMetadataURL, live.Auth.ResourceMetadataURL, "protected resource metadata location changed"})
	}
	if !rawEqual(old.Auth.ProtectedResourceMeta, live.Auth.ProtectedResourceMeta) {
		changes = append(changes, Change{High, "authorization", "auth.protected_resource_metadata", "changed", rawValue(old.Auth.ProtectedResourceMeta), rawValue(live.Auth.ProtectedResourceMeta), "protected resource metadata changed"})
	}
	if !rawEqual(old.Auth.AuthorizationMeta, live.Auth.AuthorizationMeta) {
		changes = append(changes, Change{High, "authorization", "auth.authorization_server_metadata", "changed", rawValue(old.Auth.AuthorizationMeta), rawValue(live.Auth.AuthorizationMeta), "authorization server metadata changed"})
	}
	if old.Transport.TLSSPKISHA256 != live.Transport.TLSSPKISHA256 && old.Transport.TLSSPKISHA256 != "" && live.Transport.TLSSPKISHA256 != "" {
		changes = append(changes, Change{High, "identity", "transport.tls_spki_sha256", "changed", old.Transport.TLSSPKISHA256, live.Transport.TLSSPKISHA256, "TLS public-key identity changed"})
	} else if old.Transport.TLSCertSHA256 != live.Transport.TLSCertSHA256 && old.Transport.TLSCertSHA256 != "" && live.Transport.TLSCertSHA256 != "" {
		changes = append(changes, Change{Low, "identity", "transport.tls_cert_sha256", "changed", old.Transport.TLSCertSHA256, live.Transport.TLSCertSHA256, "TLS certificate changed while public key remained stable"})
	}
	changes = append(changes, compareTools(old.Tools, live.Tools)...)
	changes = append(changes, compareResources(old.Resources, live.Resources)...)
	changes = append(changes, comparePrompts(old.Prompts, live.Prompts)...)
	sort.SliceStable(changes, func(i, j int) bool { return severityWeight(changes[i].Severity) > severityWeight(changes[j].Severity) })
	score := 0
	for _, c := range changes {
		score += severityWeight(c.Severity)
	}
	if score > 100 {
		score = 100
	}
	return Result{Match: len(changes) == 0, Risk: risk(score), Score: score, Changes: changes}
}

func compareTools(a, b []canonical.Tool) []Change {
	am := map[string]canonical.Tool{}
	bm := map[string]canonical.Tool{}
	for _, x := range a {
		am[x.Name] = x
	}
	for _, x := range b {
		bm[x.Name] = x
	}
	var out []Change
	for n, x := range am {
		y, ok := bm[n]
		if !ok {
			out = append(out, Change{Medium, "capability", "tools." + n, "removed", n, nil, "tool removed"})
			continue
		}
		if x.Description != y.Description {
			sev := Low
			if sensitiveDescriptionDelta(x.Description, y.Description) {
				sev = Medium
			}
			out = append(out, Change{sev, "description", "tools." + n + ".description", "changed", x.Description, y.Description, "tool description changed"})
		}
		if !rawEqual(x.InputSchema, y.InputSchema) {
			kind, sev, msg := classifySchemaChange(x.InputSchema, y.InputSchema)
			out = append(out, Change{sev, "authority", "tools." + n + ".input_schema", kind, rawValue(x.InputSchema), rawValue(y.InputSchema), msg})
		}
		if !rawEqual(x.Annotations, y.Annotations) {
			out = append(out, Change{Medium, "capability", "tools." + n + ".annotations", "changed", rawValue(x.Annotations), rawValue(y.Annotations), "tool annotations changed"})
		}
	}
	for n := range bm {
		if _, ok := am[n]; !ok {
			out = append(out, Change{High, "capability", "tools." + n, "added", nil, n, "new tool exposed"})
		}
	}
	return out
}

func classifySchemaChange(before, after json.RawMessage) (string, Severity, string) {
	var a, b map[string]any
	if json.Unmarshal(before, &a) != nil || json.Unmarshal(after, &b) != nil {
		return "changed", High, "tool input schema changed"
	}
	widen := false
	narrow := false
	ab, ap := a["additionalProperties"].(bool)
	bb, bp := b["additionalProperties"].(bool)
	if ap && bp && ab != bb {
		if !ab && bb {
			widen = true
		} else {
			narrow = true
		}
	}
	ar := stringSet(a["required"])
	br := stringSet(b["required"])
	if len(ar) > 0 || len(br) > 0 {
		if setHasRemoved(ar, br) {
			widen = true
		}
		if setHasRemoved(br, ar) {
			narrow = true
		}
	}
	ae := stringSet(a["enum"])
	be := stringSet(b["enum"])
	if len(ae) > 0 && len(be) > 0 {
		if isStrictSuperset(be, ae) {
			widen = true
		}
		if isStrictSuperset(ae, be) {
			narrow = true
		}
	}
	if widen {
		return "widened", High, "tool input schema widened accepted authority/capability"
	}
	if narrow {
		return "narrowed", Medium, "tool input schema narrowed accepted input"
	}
	return "changed", High, "tool input schema changed; direction could not be proven safely"
}

func stringSet(v any) map[string]struct{} {
	out := map[string]struct{}{}
	xs, ok := v.([]any)
	if !ok {
		return out
	}
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out[s] = struct{}{}
		}
	}
	return out
}

func setHasRemoved(old, new map[string]struct{}) bool {
	for k := range old {
		if _, ok := new[k]; !ok {
			return true
		}
	}
	return false
}

func isStrictSuperset(a, b map[string]struct{}) bool {
	if len(a) <= len(b) {
		return false
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			return false
		}
	}
	return true
}

func compareResources(a, b []canonical.Resource) []Change {
	key := func(x canonical.Resource) string {
		if x.URI != "" {
			return x.URI
		}
		return x.Name
	}
	am := map[string]canonical.Resource{}
	bm := map[string]canonical.Resource{}
	for _, x := range a {
		am[key(x)] = x
	}
	for _, x := range b {
		bm[key(x)] = x
	}
	var out []Change
	for n := range am {
		if _, ok := bm[n]; !ok {
			out = append(out, Change{Low, "capability", "resources." + n, "removed", n, nil, "resource removed"})
		}
	}
	for n := range bm {
		if _, ok := am[n]; !ok {
			out = append(out, Change{Medium, "capability", "resources." + n, "added", nil, n, "new resource exposed"})
		}
	}
	return out
}

func comparePrompts(a, b []canonical.Prompt) []Change {
	am := map[string]canonical.Prompt{}
	bm := map[string]canonical.Prompt{}
	for _, x := range a {
		am[x.Name] = x
	}
	for _, x := range b {
		bm[x.Name] = x
	}
	var out []Change
	for n, x := range am {
		if _, ok := bm[n]; !ok {
			out = append(out, Change{Low, "capability", "prompts." + n, "removed", n, nil, "prompt removed"})
		} else if !rawEqual(x.Arguments, bm[n].Arguments) || x.Description != bm[n].Description {
			out = append(out, Change{Medium, "capability", "prompts." + n, "changed", x, bm[n], "prompt definition changed"})
		}
	}
	for n := range bm {
		if _, ok := am[n]; !ok {
			out = append(out, Change{Medium, "capability", "prompts." + n, "added", nil, n, "new prompt exposed"})
		}
	}
	return out
}

func rawEqual(a, b json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b)) }

func rawValue(a json.RawMessage) any {
	if len(bytes.TrimSpace(a)) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(a, &v) == nil {
		return v
	}
	return string(a)
}

func sensitiveDescriptionDelta(a, b string) bool {
	s := strings.ToLower(a + " " + b)
	for _, w := range []string{"delete", "export", "write", "manage", "admin", "execute", "upload", "download", "credential", "database"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func severityWeight(s Severity) int {
	switch s {
	case Critical:
		return 60
	case High:
		return 35
	case Medium:
		return 15
	case Low:
		return 5
	default:
		return 1
	}
}

func risk(score int) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 35:
		return "HIGH"
	case score >= 15:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
