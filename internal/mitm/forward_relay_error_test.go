package mitm

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// When the upstream dies mid-body, the relay must surface it: the client
// sees a failed read (not a clean, silently truncated body) and the request
// log carries a non-empty error_code (#362 follow-up).
func TestMITMForwardUpstreamBodyFailureIsSurfaced(t *testing.T) {
	cases := []struct {
		name string
		raw  string // written verbatim before the upstream drops the connection
	}{
		{
			name: "content-length",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\npartial-body",
		},
		{
			name: "chunked",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\nc\r\npartial-body\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				_, _ = buf.WriteString(tc.raw)
				_ = buf.Flush()
				_ = conn.Close()
			}))
			defer upstream.Close()
			host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

			sr := validTokenResolver("av_sess_ok",
				&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
			cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
				host: {result: &brokercore.InjectResult{
					MatchedName: "api",
					Headers:     map[string]string{"Authorization": "Bearer token"},
				}},
			}}
			sink := &recordingSink{}
			proxyURL, clientRoots, _ := setupProxy(t, sr, cp, func(o *Options) { o.LogSink = sink })
			client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)

			resp, err := client.Get(upstream.URL + "/stream")
			if err == nil {
				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if err == nil {
				t.Fatal("client read the truncated body without error; truncation must be visible")
			}

			rows := sink.waitForRows(t, 1)
			if rows[0].ErrorCode != "upstream_body_error" {
				t.Fatalf("error_code = %q, want upstream_body_error", rows[0].ErrorCode)
			}
		})
	}
}
