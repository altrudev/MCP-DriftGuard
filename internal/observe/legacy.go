package observe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

type initResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

func (c *Client) inspectLegacy(ctx context.Context, endpoint string, s *canonical.Snapshot) error {
	initPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": LegacyProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "mcpdrift", "version": "0.1.0"},
		},
	}
	resp, session, proto, err := c.legacyRPC(ctx, endpoint, "", initPayload)
	if err != nil {
		return err
	}
	s.Transport.HTTPProtocol = proto
	if resp.Error != nil {
		return fmt.Errorf("initialize failed: %d %s", resp.Error.Code, resp.Error.Message)
	}

	var ir initResult
	if err := json.Unmarshal(resp.Result, &ir); err != nil {
		return fmt.Errorf("decode initialize result: %w", err)
	}
	s.Server = canonical.Server{
		Name:              ir.ServerInfo.Name,
		Version:           ir.ServerInfo.Version,
		ProtocolVersion:   ir.ProtocolVersion,
		SupportedVersions: []string{ir.ProtocolVersion},
	}
	s.Capabilities = ir.Capabilities

	if err := c.notifyLegacy(ctx, endpoint, session, map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}); err != nil {
		return fmt.Errorf("initialized notification failed: %w", err)
	}

	id := 2
	if hasCap(ir.Capabilities, "tools") {
		if err := c.paginateLegacy(ctx, endpoint, session, &id, "tools/list", func(result json.RawMessage) (string, error) {
			var v struct {
				Tools []struct {
					Name        string          `json:"name"`
					Description string          `json:"description"`
					InputSchema json.RawMessage `json:"inputSchema"`
					Annotations json.RawMessage `json:"annotations"`
				} `json:"tools"`
				NextCursor string `json:"nextCursor"`
			}
			if err := json.Unmarshal(result, &v); err != nil {
				return "", err
			}
			for _, x := range v.Tools {
				s.Tools = append(s.Tools, canonical.Tool{Name: x.Name, Description: x.Description, InputSchema: x.InputSchema, Annotations: x.Annotations})
			}
			return v.NextCursor, nil
		}); err != nil {
			return err
		}
	}
	if hasCap(ir.Capabilities, "resources") {
		if err := c.paginateLegacy(ctx, endpoint, session, &id, "resources/list", func(result json.RawMessage) (string, error) {
			var v struct {
				Resources []struct {
					URI         string `json:"uri"`
					Name        string `json:"name"`
					Description string `json:"description"`
					MIMEType    string `json:"mimeType"`
				} `json:"resources"`
				NextCursor string `json:"nextCursor"`
			}
			if err := json.Unmarshal(result, &v); err != nil {
				return "", err
			}
			for _, x := range v.Resources {
				s.Resources = append(s.Resources, canonical.Resource{URI: x.URI, Name: x.Name, Description: x.Description, MIMEType: x.MIMEType})
			}
			return v.NextCursor, nil
		}); err != nil {
			return err
		}
	}
	if hasCap(ir.Capabilities, "prompts") {
		if err := c.paginateLegacy(ctx, endpoint, session, &id, "prompts/list", func(result json.RawMessage) (string, error) {
			var v struct {
				Prompts []struct {
					Name        string          `json:"name"`
					Description string          `json:"description"`
					Arguments   json.RawMessage `json:"arguments"`
				} `json:"prompts"`
				NextCursor string `json:"nextCursor"`
			}
			if err := json.Unmarshal(result, &v); err != nil {
				return "", err
			}
			for _, x := range v.Prompts {
				s.Prompts = append(s.Prompts, canonical.Prompt{Name: x.Name, Description: x.Description, Arguments: x.Arguments})
			}
			return v.NextCursor, nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) legacyRPC(ctx context.Context, endpoint, session string, payload any) (rpcResponse, string, string, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return rpcResponse{}, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", LegacyProtocolVersion)
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}

	c.authorizeMCP(req)
	res, err := c.do(req)
	if err != nil {
		return rpcResponse{}, "", "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
		return rpcResponse{}, "", res.Proto, &httpStatusError{Status: res.StatusCode, Proto: res.Proto, Header: res.Header.Clone(), Body: string(body)}
	}
	raw, err := readRPCBody(res.Body, res.Header.Get("Content-Type"))
	if err != nil {
		return rpcResponse{}, "", res.Proto, err
	}
	var rr rpcResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return rr, "", res.Proto, err
	}
	return rr, res.Header.Get("Mcp-Session-Id"), res.Proto, nil
}

func (c *Client) notifyLegacy(ctx context.Context, endpoint, session string, payload any) error {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", LegacyProtocolVersion)
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}

	c.authorizeMCP(req)
	res, err := c.do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("initialized notification HTTP %d", res.StatusCode)
	}
	return nil
}

func (c *Client) paginateLegacy(ctx context.Context, endpoint, session string, id *int, method string, consume func(json.RawMessage) (string, error)) error {
	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		payload := map[string]any{"jsonrpc": "2.0", "id": *id, "method": method, "params": params}
		(*id)++
		r, _, _, err := c.legacyRPC(ctx, endpoint, session, payload)
		if err != nil {
			return fmt.Errorf("%s page %d: %w", method, page+1, err)
		}
		if r.Error != nil {
			return fmt.Errorf("%s page %d RPC error: %d %s", method, page+1, r.Error.Code, r.Error.Message)
		}
		next, err := consume(r.Result)
		if err != nil {
			return fmt.Errorf("decode %s page %d: %w", method, page+1, err)
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
	return fmt.Errorf("%s exceeded pagination limit", method)
}
