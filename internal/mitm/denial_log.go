package mitm

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// denialLogInterval bounds how often denials for one rate-limit key are
// logged. A client hammering a closed gate would otherwise turn every 429
// into a log line, amplifying the flood into the log pipeline.
const denialLogInterval = 30 * time.Second

// denialLogMaxKeys caps the throttle map. Expired entries are pruned when
// it fills; if every entry is still live the map is reset, which at worst
// logs a few extra lines.
const denialLogMaxKeys = 4096

type denialEntry struct {
	last       time.Time
	suppressed int
}

// denialLog throttles MITM rate-limit denial logs per key. The zero value
// is ready to use.
type denialLog struct {
	mu   sync.Mutex
	seen map[string]*denialEntry
}

// admit reports whether a denial for key should be logged now and, if so,
// how many denials for key were suppressed since the last logged one.
func (l *denialLog) admit(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = make(map[string]*denialEntry)
	}
	if e, ok := l.seen[key]; ok {
		if now.Sub(e.last) < denialLogInterval {
			e.suppressed++
			return false, 0
		}
		suppressed := e.suppressed
		e.last, e.suppressed = now, 0
		return true, suppressed
	}
	if len(l.seen) >= denialLogMaxKeys {
		for k, e := range l.seen {
			if now.Sub(e.last) >= denialLogInterval {
				delete(l.seen, k)
			}
		}
		if len(l.seen) >= denialLogMaxKeys {
			clear(l.seen)
		}
	}
	l.seen[key] = &denialEntry{last: now}
	return true, 0
}

// denyAuthFlood writes the 429 for a TierAuth pre-gate denial and logs it
// (throttled per key). Denied requests never reach the forward handler, so
// without this log there is no broker-side trace of the denial at all.
func (p *Proxy) denyAuthFlood(w http.ResponseWriter, r *http.Request, ingress, key string, d ratelimit.Decision, message string) {
	if ok, suppressed := p.denials.admit(key, time.Now()); ok {
		p.logger.Warn("mitm rate limit denied",
			slog.String("ingress", ingress),
			slog.String("tier", ratelimit.TierAuth.String()),
			slog.String("key", key),
			slog.String("reason", d.Reason),
			slog.String("target", r.Host),
			slog.Duration("retry_after", d.RetryAfter),
			slog.Int("suppressed", suppressed))
	}
	ratelimit.WriteDenial(w, d, message)
}
