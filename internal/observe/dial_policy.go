package observe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// guardedDial resolves and validates each connection target, then connects to
// the verified IP address, not the original hostname. This closes the DNS
// lookup-to-dial rebinding window for the default HTTP transport.
func guardedDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	explicit := net.ParseIP(host) != nil || strings.EqualFold(host, "localhost")
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("destination has no DNS addresses")
	}
	for _, addr := range ips {
		ip := addr.IP
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || (!explicit && (!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback())) {
			return nil, errors.New("destination DNS resolution contains a prohibited address")
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var last error
	for _, ip := range ips {
		conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, last
}

func safeHTTPTransport() *http.Transport {
	// ProxyFromEnvironment could route an approved hostname through an unverified
	// intermediary. Disable proxy auto-discovery for evidence collection.
	return &http.Transport{DialContext: guardedDial, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second}
}
