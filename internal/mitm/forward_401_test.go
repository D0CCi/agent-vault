package mitm

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

const upstream401Body = `{"error":"unauthorized","detail":"credentials rejected by upstream"}`

// start401Upstream answers the first request with a Content-Length-delimited
// 401. Later requests are handled by then (nil = 401 again). It returns the
// server, its bare host, and a counter of requests seen.
func start401Upstream(t *testing.T, then http.HandlerFunc) (*httptest.Server, string, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 && then != nil {
			then(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", "Basic")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, upstream401Body)
	}))
	t.Cleanup(srv.Close)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	return srv, host, &calls
}

func get401ThroughProxy(t *testing.T, cp brokercore.CredentialProvider, target string) (int, string, *recordingSink) {
	t.Helper()
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	sink := &recordingSink{}
	proxyURL, clientRoots, _ := setupProxy(t, sr, cp, func(o *Options) { o.LogSink = sink })
	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading relayed body (status %d, got %d bytes): %v", resp.StatusCode, len(body), err)
	}
	return resp.StatusCode, string(body), sink
}

// #362: a matched service with auth "passthrough" (credentials substituted
// into client-supplied headers) has no injected headers to refresh, so a 401
// must be relayed intact, not closed and forwarded with zero body bytes.
func TestMITMForward401PassthroughAuthRelaysBody(t *testing.T) {
	upstream, host, calls := start401Upstream(t, nil)
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {result: &brokercore.InjectResult{
			MatchedName: "dev-backend",
			Substitutions: []brokercore.ResolvedSubstitution{
				{Placeholder: "__USER_A__", Value: "real", In: []string{"header"}},
			},
		}},
	}}

	status, body, sink := get401ThroughProxy(t, cp, upstream.URL+"/server/0/app/userInfo")

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if body != upstream401Body {
		t.Fatalf("body = %q, want the upstream 401 body", body)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("upstream saw %d requests, want 1 (nothing to refresh, no retry)", n)
	}
	rows := sink.waitForRows(t, 1)
	if rows[0].Status != http.StatusUnauthorized || rows[0].ErrorCode != "" {
		t.Errorf("log row status=%d error_code=%q, want 401/\"\"", rows[0].Status, rows[0].ErrorCode)
	}
}

// If the credential-refresh retry itself fails, the original 401 must still
// reach the client with its body.
func TestMITMForward401RetryFailureRelaysOriginal(t *testing.T) {
	upstream, host, calls := start401Upstream(t, func(w http.ResponseWriter, _ *http.Request) {
		// Drop the connection without a response so the retry errors out.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {result: &brokercore.InjectResult{
			MatchedName: "api",
			Headers:     map[string]string{"Authorization": "Bearer token"},
		}},
	}}

	status, body, _ := get401ThroughProxy(t, cp, upstream.URL+"/v1/me")

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if body != upstream401Body {
		t.Fatalf("body = %q, want the original 401 body", body)
	}
	if n := calls.Load(); n < 2 {
		t.Errorf("upstream saw %d requests, want the retry to be attempted", n)
	}
}

// A successful retry still replaces the 401 (existing OAuth refresh path).
func TestMITMForward401RetrySuccessRelaysRetry(t *testing.T) {
	upstream, host, calls := start401Upstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "refreshed-ok")
	})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		host: {result: &brokercore.InjectResult{
			MatchedName: "api",
			Headers:     map[string]string{"Authorization": "Bearer token"},
		}},
	}}

	status, body, _ := get401ThroughProxy(t, cp, upstream.URL+"/v1/me")

	if status != http.StatusOK || body != "refreshed-ok" {
		t.Fatalf("got %d %q, want 200 \"refreshed-ok\"", status, body)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("upstream saw %d requests, want 2", n)
	}
}
