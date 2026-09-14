package observe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

const ModernProtocolVersion = "2026-07-28"
const LegacyProtocolVersion = "2025-11-25"
const maxPages = 100

type Client struct {
	HTTP *http.Client
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type httpStatusError struct {
	Status int
	Proto  string
	Header http.Header
	Body   string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d from MCP endpoint: %s", e.Status, e.Body)
}

func (c *Client) Inspect(ctx context.Context, endpoint string) (canonical.Snapshot, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return canonical.Snapshot{}, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return canonical.Snapshot{}, errors.New("endpoint must use http or https")
	}

	s := canonical.Snapshot{
		Format:     "mcpdrift-snapshot/v1",
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		Endpoint:   endpoint,
		Transport: canonical.Transport{
			Scheme: u.Scheme,
			Host:   u.Host,
		},
	}

	modern, fallback, err := c.inspectModern(ctx, endpoint, &s)
	if err != nil {
		c.captureUnauthorized(ctx, u, &s, err)
		return s, err
	}
	if !modern && fallback {
		if err := c.inspectLegacy(ctx, endpoint, &s); err != nil {
			c.captureUnauthorized(ctx, u, &s, err)
			return s, err
		}
	}

	if err := c.discoverAuth(ctx, u, &s); err != nil {
		return s, fmt.Errorf("authorization discovery: %w", err)
	}
	if u.Scheme == "https" {
		ti, err := tlsInfo(u.Hostname(), u.Port())
		if err != nil {
			return s, fmt.Errorf("TLS identity inspection: %w", err)
		}
		s.Transport.TLSSubject = ti.subject
		s.Transport.TLSIssuer = ti.issuer
		s.Transport.TLSNotAfter = ti.notAfter
		s.Transport.TLSCertSHA256 = ti.certSHA256
		s.Transport.TLSSPKISHA256 = ti.spkiSHA256
	}
	return s, nil
}

func (c *Client) captureUnauthorized(ctx context.Context, endpoint *url.URL, s *canonical.Snapshot, err error) {
	var hs *httpStatusError
	if errors.As(err, &hs) && hs.Status == http.StatusUnauthorized {
		s.Transport.HTTPProtocol = hs.Proto
		s.Auth.WWWAuthenticate = hs.Header.Get("WWW-Authenticate")
		_ = c.discoverAuth(ctx, endpoint, s)
	}
}
