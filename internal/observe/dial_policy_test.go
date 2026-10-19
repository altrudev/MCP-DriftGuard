package observe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGuardedDialRejectsUnspecifiedAndMulticast(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:80", "[::]:80", "224.0.0.1:80", "169.254.1.1:80"} {
		conn, err := guardedDial(context.Background(), "tcp", addr)
		if conn != nil {
			conn.Close()
			t.Fatalf("connected to prohibited address %s", addr)
		}
		if err == nil {
			t.Fatalf("accepted prohibited address %s", addr)
		}
	}
}
func TestSafeTransportLoopbackAndNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	c := New()
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("HTTP client unexpectedly permits proxy routing")
	}
	res, err := c.HTTP.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatalf("unexpected status %d", res.StatusCode)
	}
}
