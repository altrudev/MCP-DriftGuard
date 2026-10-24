package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/evidence"
)

type discoveryAppendError struct{ err error }

func (e *discoveryAppendError) Error() string {
	return "discovery evidence append failed: " + e.err.Error()
}
func (e *discoveryAppendError) Unwrap() error { return e.err }

func hashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// discoveryRPC records local acquisition, not server authority or tool execution.
func (c *Client) discoveryRPC(req *http.Request, body []byte) (rr rpcResponse, res *http.Response, err error) {
	var request struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	if err = json.Unmarshal(body, &request); err != nil {
		return
	}
	d := evidence.Discovery{Method: request.Method, RequestID: string(request.ID), RequestHash: hashBytes(body), Endpoint: req.URL.String(), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "transport_error"}
	// Validate before sending when evidence is requested; do not silently redact provenance.
	if c.DiscoverySink != nil {
		check := d
		check.CompletedAt = d.StartedAt
		if err = check.Validate(); err != nil {
			return
		}
	}
	defer func() {
		if c.DiscoverySink == nil {
			return
		}
		d.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if sinkErr := c.DiscoverySink(d); sinkErr != nil {
			err = errors.Join(err, &discoveryAppendError{sinkErr})
		}
	}()
	res, err = c.HTTP.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	d.HTTPStatus = res.StatusCode
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		raw, readErr := io.ReadAll(io.LimitReader(res.Body, 8192))
		d.ResponseHash = hashBytes(raw)
		d.Status = "http_error"
		err = errors.Join(&httpStatusError{Status: res.StatusCode, Proto: res.Proto, Header: res.Header.Clone(), Body: string(raw)}, readErr)
		return
	}
	d.Status = "decode_error"
	raw, readErr := readRPCBody(res.Body, res.Header.Get("Content-Type"))
	d.ResponseHash = hashBytes(raw)
	if readErr != nil {
		err = readErr
		return
	}
	if err = json.Unmarshal(raw, &rr); err != nil {
		return
	}
	// A syntactically valid unrelated message is not an observed RPC response.
	id, _ := json.Marshal(rr.ID)
	if rr.JSONRPC != "2.0" || string(id) != string(request.ID) || (rr.Error == nil && len(rr.Result) == 0) || (rr.Error != nil && len(rr.Result) != 0) {
		err = errors.New("invalid discovery RPC response envelope")
		return
	}
	d.Status = "response"
	if rr.Error != nil {
		d.Status = "rpc_error"
		code := rr.Error.Code
		d.RPCCode = &code
	}
	return
}
