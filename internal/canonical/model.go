package canonical

import "encoding/json"

type Snapshot struct {
	Format       string         `json:"format"`
	ObservedAt   string         `json:"observed_at"`
	Endpoint     string         `json:"endpoint"`
	Server       Server         `json:"server"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
	Tools        []Tool         `json:"tools,omitempty"`
	Resources    []Resource     `json:"resources,omitempty"`
	Prompts      []Prompt       `json:"prompts,omitempty"`
	Auth         Auth           `json:"auth,omitempty"`
	Transport    Transport      `json:"transport"`
}

type Server struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
}

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mime_type,omitempty"`
}

type Prompt struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}

type Auth struct {
	WWWAuthenticate       string          `json:"www_authenticate,omitempty"`
	ProtectedResourceMeta json.RawMessage `json:"protected_resource_metadata,omitempty"`
	AuthorizationMeta     json.RawMessage `json:"authorization_server_metadata,omitempty"`
}

type Transport struct {
	Scheme       string `json:"scheme,omitempty"`
	Host         string `json:"host,omitempty"`
	TLSSubject   string `json:"tls_subject,omitempty"`
	TLSIssuer    string `json:"tls_issuer,omitempty"`
	TLSNotAfter  string `json:"tls_not_after,omitempty"`
	HTTPProtocol string `json:"http_protocol,omitempty"`
}
