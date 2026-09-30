package mitm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ratelimit"
)

func TestDenialLogAdmitThrottlesPerKey(t *testing.T) {
	var l denialLog
	t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	if ok, n := l.admit("mitm:10.0.0.1", t0); !ok || n != 0 {
		t.Fatalf("first denial: ok=%v suppressed=%d, want true/0", ok, n)
	}
	for i := 1; i <= 5; i++ {
		if ok, _ := l.admit("mitm:10.0.0.1", t0.Add(time.Duration(i)*time.Second)); ok {
			t.Fatalf("denial %d within interval should be suppressed", i)
		}
	}
	if ok, _ := l.admit("mitm:10.0.0.2", t0.Add(time.Second)); !ok {
		t.Fatal("a different key must not be throttled by another key's window")
	}
	ok, n := l.admit("mitm:10.0.0.1", t0.Add(denialLogInterval))
	if !ok || n != 5 {
		t.Fatalf("after interval: ok=%v suppressed=%d, want true/5", ok, n)
	}
	if ok, _ := l.admit("mitm:10.0.0.1", t0.Add(denialLogInterval+time.Second)); ok {
		t.Fatal("window must restart after a logged denial")
	}
}

func TestDenialLogAdmitBoundsKeys(t *testing.T) {
	var l denialLog
	t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for i := 0; i < denialLogMaxKeys; i++ {
		l.admit(fmt.Sprintf("mitm:old-%d", i), t0)
	}
	// Old entries have expired by now and are pruned to make room.
	later := t0.Add(denialLogInterval)
	if ok, _ := l.admit("mitm:new", later); !ok {
		t.Fatal("new key should be admitted")
	}
	if got := len(l.seen); got != 1 {
		t.Fatalf("len(seen) = %d, want 1 after pruning expired entries", got)
	}

	// All entries live: the map resets instead of growing past the cap.
	for i := 0; i < denialLogMaxKeys; i++ {
		l.admit(fmt.Sprintf("mitm:live-%d", i), later)
	}
	if got := len(l.seen); got > denialLogMaxKeys {
		t.Fatalf("len(seen) = %d, exceeds cap %d", got, denialLogMaxKeys)
	}
}

// syncBuffer guards the log buffer: the proxy logs from server goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Denials at the MITM pre-gate never reach the forward handler, so the log
// line is the only broker-side evidence (#381).
func TestMITMForwardAuthRateLimitDenialIsLogged(t *testing.T) {
	sr := validTokenResolver("good-token", nil)
	cp := &fakeCredProvider{}
	proxyURL, _, p := setupProxy(t, sr, cp)

	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	cfg.Tiers[ratelimit.TierAuth].Max = 1
	p.rateLimit = ratelimit.New(cfg)
	var logs syncBuffer
	p.logger = slog.New(slog.NewTextHandler(&logs, nil))
	overrideRemoteAddr(p, "10.0.0.5:12345")

	auth := base64.StdEncoding.EncodeToString([]byte("bad-token:"))
	statuses := make([]int, 0, 4)
	for i := 0; i < 4; i++ {
		conn := dialProxy(t, proxyURL)
		resp := writeRawRequestLine(t, conn,
			"GET http://example.com/x HTTP/1.1",
			map[string]string{
				"Host":                "example.com",
				"Proxy-Authorization": "Basic " + auth,
			})
		resp.Body.Close()
		conn.Close()
		statuses = append(statuses, resp.StatusCode)
	}
	if statuses[len(statuses)-1] != http.StatusTooManyRequests {
		t.Fatalf("statuses = %v, want trailing 429s once the budget is exhausted", statuses)
	}

	out := logs.String()
	if got := strings.Count(out, "mitm rate limit denied"); got != 1 {
		t.Fatalf("denial log lines = %d, want 1 (throttled per key); logs:\n%s", got, out)
	}
	for _, want := range []string{"ingress=forward", "key=mitm:10.0.0.5", "tier=", "target=example.com", "retry_after="} {
		if !strings.Contains(out, want) {
			t.Errorf("denial log missing %q; logs:\n%s", want, out)
		}
	}
	if strings.Contains(out, "bad-token") || strings.Contains(out, auth) {
		t.Errorf("denial log must not contain the presented credential; logs:\n%s", out)
	}
}
