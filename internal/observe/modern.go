package observe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data,omitempty"`
	} `json:"error"`
}

type discoverResult struct {
	SupportedVersions []string       `json:"supportedVersions"`
	Capabilities      map[string]any `json:"capabilities"`
	Meta              map[string]any `json:"_meta,omitempty"`
}

func (c *Client) inspectModern(ctx context.Context, endpoint string, s *canonical.Snapshot) (bool, bool, error) {
	resp, proto, err := c.modernRPC(ctx, endpoint, 1, "server/discover", map[string]any{})
	if err != nil {
		var hs *httpStatusError
		if errors.As(err, &hs) && (hs.Status == http.StatusBadRequest || hs.Status == http.StatusNotFound || hs.Status == http.StatusMethodNotAllowed) {
			return false, true, nil
		}
		return false, false, err
	}
	s.Transport.HTTPProtocol = proto
	if resp.Error != nil {
		if resp.Error.Code == -32601 || resp.Error.Code == -32022 {
			return false, true, nil
		}
		return false, false, fmt.Errorf("server/discover failed: %d %s", resp.Error.Code, resp.Error.Message)
	}

	var dr discoverResult
	if err := json.Unmarshal(resp.Result, &dr); err != nil {
		return false, false, fmt.Errorf("decode server/discover result: %w", err)
	}
	if !contains(dr.SupportedVersions, ModernProtocolVersion) {
		return false, true, nil
	}

	s.Server.ProtocolVersion = ModernProtocolVersion
	s.Server.SupportedVersions = append([]string(nil), dr.SupportedVersions...)
	s.Capabilities = dr.Capabilities
	if raw, ok := dr.Meta["io.modelcontextprotocol/serverInfo"]; ok {
		b, _ := json.Marshal(raw)
		var info struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &info) == nil {
			s.Server.Name = info.Name
			s.Server.Version = info.Version
		}
	}

	id := 2
	if hasCap(dr.Capabilities, "tools") {
		if err := c.paginateModern(ctx, endpoint, &id, "tools/list", func(result json.RawMessage) (string, error) {
			var v struct {
				Tools []struct {
					Name        string
					Description string
					InputSchema json.RawMessage `json:"inputSchema"`
					Annotations json.RawMessage `json:"annotations"`
				} `json:"tools"`
				NextCursor string `json:"nextCursor"`
			}
			if err := json.Unmarshal(result, &v); err != nil { return "", err }
			for _, x := range v.Tools {
				s.Tools = append(s.Tools, canonical.Tool{Name:x.Name, Description:x.Description, InputSchema:x.InputSchema, Annotations:x.Annotations})
			}
			return v.NextCursor, nil
		}); err != nil { return false, false, err }
	}
	if hasCap(dr.Capabilities, "resources") {
		if err := c.paginateModern(ctx, endpoint, &id, "resources/list", func(result json.RawMessage) (string, error) {
			var v struct {
				Resources []struct {
					URI string `json:"uri"`
					Name string `json:"name"`
					Description string `json:"description"`
					MIMEType string `json:"mimeType"`
				} `json:"resources"`
				NextCursor string `json:"nextCursor"`
			}
			if err := json.Unmarshal(result, &v); err != nil { return "", err }
			for _, x := range v.Resources {
				s.Resources = append(s.Resources, canonical.Resource{URI:x.URI, Name:x.Name, Description:x.Description, MIMEType:x.MIMEType})
			}
			return v.NextCursor, nil
		}); err != nil { return false, false, err }
	}
	if hasCap(dr.Capabilities, "prompts") {
		if err := c.paginateModern(ctx, endpoint, &id, "prompts/list", func(result json.RawMessage) (string, error) {
			var v struct {
				Prompts []struct {
					Name string `json:"name"`
					Description string `json:"description"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"prompts"`
				NextCursor string `json:"nextCursor"`
			}
			if err := json.Unmarshal(result, &v); err != nil { return "", err }
			for _, x := range v.Prompts {
				s.Prompts = append(s.Prompts, canonical.Prompt{Name:x.Name, Description:x.Description, Arguments:x.Arguments})
			}
			return v.NextCursor, nil
		}); err != nil { return false, false, err }
	}
	return true, false, nil
}

func modernMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion": ModernProtocolVersion,
		"io.modelcontextprotocol/clientInfo": map[string]any{"name":"mcpdrift","version":"0.1.0"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
}

func (c *Client) modernRPC(ctx context.Context, endpoint string, id int, method string, params map[string]any) (rpcResponse, string, error) {
	if params == nil { params = map[string]any{} }
	params["_meta"] = modernMeta()
	payload := map[string]any{"jsonrpc":"2.0","id":id,"method":method,"params":params}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil { return rpcResponse{}, "", err }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	req.Header.Set("Mcp-Method", method)

	res, err := c.HTTP.Do(req)
	if err != nil { return rpcResponse{}, "", err }
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
		return rpcResponse{}, res.Proto, &httpStatusError{Status:res.StatusCode, Proto:res.Proto, Header:res.Header.Clone(), Body:string(body)}
	}
	raw, err := readRPCBody(res.Body, res.Header.Get("Content-Type"))
	if err != nil { return rpcResponse{}, res.Proto, err }
	var rr rpcResponse
	if err := json.Unmarshal(raw, &rr); err != nil { return rr, res.Proto, err }
	return rr, res.Proto, nil
}

func (c *Client) paginateModern(ctx context.Context, endpoint string, id *int, method string, consume func(json.RawMessage)(string,error)) error {
	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]any{}
		if cursor != "" { params["cursor"] = cursor }
		r, _, err := c.modernRPC(ctx, endpoint, *id, method, params)
		(*id)++
		if err != nil { return fmt.Errorf("%s page %d: %w", method, page+1, err) }
		if r.Error != nil { return fmt.Errorf("%s page %d RPC error: %d %s", method, page+1, r.Error.Code, r.Error.Message) }
		next, err := consume(r.Result)
		if err != nil { return fmt.Errorf("decode %s page %d: %w", method, page+1, err) }
		if next == "" { return nil }
		cursor = next
	}
	return fmt.Errorf("%s exceeded pagination limit", method)
}

func readRPCBody(r io.Reader, contentType string) ([]byte, error) {
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "data:") {
				return []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), nil
			}
		}
		if err := sc.Err(); err != nil { return nil, err }
		return nil, errors.New("SSE response contained no data event")
	}
	return io.ReadAll(io.LimitReader(r, 4<<20))
}

func hasCap(m map[string]any, k string) bool { _, ok := m[k]; return ok }
func contains(xs []string, s string) bool { for _, x := range xs { if x == s { return true } }; return false }
