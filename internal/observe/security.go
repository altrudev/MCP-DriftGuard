package observe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

var resourceMetadataRE = regexp.MustCompile(`(?i)resource_metadata\s*=\s*"([^"]+)"`)

func (c *Client) discoverAuth(ctx context.Context, endpoint *url.URL, s *canonical.Snapshot) error {
	candidates := []string{}
	if s.Auth.WWWAuthenticate != "" {
		if m := resourceMetadataRE.FindStringSubmatch(s.Auth.WWWAuthenticate); len(m) == 2 {
			candidates = append(candidates, m[1])
		}
	}
	if len(candidates) == 0 {
		origin := endpoint.Scheme + "://" + endpoint.Host
		path := strings.TrimPrefix(endpoint.EscapedPath(), "/")
		if path != "" {
			candidates = append(candidates, origin+"/.well-known/oauth-protected-resource/"+path)
		}
		candidates = append(candidates, origin+"/.well-known/oauth-protected-resource")
	}

	var prmBody []byte
	for _, candidate := range candidates {
		mu, err := url.Parse(candidate)
		if err != nil {
			return err
		}
		if !sameOrigin(endpoint, mu) {
			return fmt.Errorf("resource metadata URL must be same-origin: %s", candidate)
		}
		body, status, err := c.getJSON(ctx, candidate)
		if err != nil {
			return err
		}
		if status == http.StatusNotFound {
			continue
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("protected resource metadata HTTP %d", status)
		}
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		s.Auth.ResourceMetadataURL = candidate
		s.Auth.ProtectedResourceMeta = append(json.RawMessage(nil), body...)
		prmBody = body
		break
	}
	if len(prmBody) == 0 {
		return nil
	}

	var prm struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(prmBody, &prm); err != nil {
		return fmt.Errorf("decode protected resource metadata: %w", err)
	}

	for _, issuer := range prm.AuthorizationServers {
		asu, err := url.Parse(issuer)
		if err != nil {
			return fmt.Errorf("authorization server URL: %w", err)
		}
		if err := validateAuthorizationServerTarget(ctx, endpoint, asu); err != nil {
			return err
		}
		for _, well := range authorizationMetadataCandidates(asu) {
			body, status, err := c.getJSON(ctx, well)
			if err != nil {
				return err
			}
			if status == http.StatusNotFound {
				continue
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("authorization server metadata HTTP %d", status)
			}
			if len(bytes.TrimSpace(body)) > 0 {
				s.Auth.AuthorizationMeta = append(json.RawMessage(nil), body...)
				return nil
			}
		}
	}
	return nil
}

func authorizationMetadataCandidates(issuer *url.URL) []string {
	origin := issuer.Scheme + "://" + issuer.Host
	path := strings.Trim(issuer.EscapedPath(), "/")
	if path == "" {
		return []string{
			origin + "/.well-known/oauth-authorization-server",
			origin + "/.well-known/openid-configuration",
		}
	}
	return []string{
		origin + "/.well-known/oauth-authorization-server/" + path,
		origin + "/.well-known/openid-configuration/" + path,
		strings.TrimRight(issuer.String(), "/") + "/.well-known/openid-configuration",
	}
}

func (c *Client) getJSON(ctx context.Context, target string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return b, res.StatusCode, err
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type certInfo struct {
	subject    string
	issuer     string
	notAfter   string
	certSHA256 string
	spkiSHA256 string
}

func tlsInfo(host, port string) (certInfo, error) {
	if port == "" {
		port = "443"
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		net.JoinHostPort(host, port),
		&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		return certInfo{}, err
	}
	defer conn.Close()
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return certInfo{}, fmt.Errorf("no peer certificate")
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	certSum := sha256.Sum256(cert.Raw)
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return certInfo{
		subject:    cert.Subject.String(),
		issuer:     cert.Issuer.String(),
		notAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
		certSHA256: "sha256:" + hex.EncodeToString(certSum[:]),
		spkiSHA256: "sha256:" + hex.EncodeToString(spkiSum[:]),
	}, nil
}


func validateAuthorizationServerTarget(ctx context.Context, endpoint, target *url.URL) error {
	if target.Hostname() == "" {
		return fmt.Errorf("authorization server URL has no host: %s", target.String())
	}
	if target.Scheme == "http" {
		if !(isLoopbackHost(endpoint.Hostname()) && isLoopbackHost(target.Hostname())) {
			return fmt.Errorf("unsafe authorization server URL: %s", target.String())
		}
		return nil
	}
	if target.Scheme != "https" {
		return fmt.Errorf("unsafe authorization server URL: %s", target.String())
	}
	if isLoopbackHost(target.Hostname()) {
		if !isLoopbackHost(endpoint.Hostname()) {
			return fmt.Errorf("authorization server loopback target rejected for non-loopback MCP endpoint: %s", target.String())
		}
		return nil
	}
	if ip := net.ParseIP(target.Hostname()); ip != nil {
		if unsafeMetadataIP(ip) {
			return fmt.Errorf("authorization server target resolves to a non-public address: %s", target.String())
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", target.Hostname())
	if err != nil {
		return fmt.Errorf("resolve authorization server host %q: %w", target.Hostname(), err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("authorization server host %q resolved to no addresses", target.Hostname())
	}
	for _, ip := range ips {
		if unsafeMetadataIP(ip) {
			return fmt.Errorf("authorization server host %q resolves to non-public address %s", target.Hostname(), ip.String())
		}
	}
	return nil
}

func unsafeMetadataIP(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		!ip.IsGlobalUnicast()
}
