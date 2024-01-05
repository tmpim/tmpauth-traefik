package tmpauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	TmpAuthHost = "auth.tmpim.pw"
)

type CaddyHandleFunc func(w http.ResponseWriter, r *http.Request) (int, error)

func FromHTTPHandler(h http.Handler) CaddyHandleFunc {
	return func(w http.ResponseWriter, r *http.Request) (int, error) {
		h.ServeHTTP(w, r)
		return 0, nil
	}
}

func FromHTTPHandleFunc(h http.HandlerFunc) CaddyHandleFunc {
	return func(w http.ResponseWriter, r *http.Request) (int, error) {
		h(w, r)
		return 0, nil
	}
}

type StateIDSession struct {
	RedirectURI string
	ExpiresAt   time.Time
}

type Tmpauth struct {
	// We use a Caddy style HandleFunc for middleware.
	Next       CaddyHandleFunc
	Config     *Config
	TokenCache map[[32]byte]*CachedToken
	HttpClient *http.Client
	HMAC       hash.Hash

	stateIDCache    map[string]*StateIDSession
	stateIDMutex    sync.Mutex
	tokenCacheMutex sync.RWMutex
	hmacMutex       sync.Mutex
	janitorOnce     sync.Once

	miniServerHost string
	miniConfigID   string
	miniConfigJSON []byte
	miniClient     *http.Client

	done     chan struct{}
	doneOnce sync.Once
}

var (
	DefaultLogger = log.New(os.Stderr, "tmpauth", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	NoLogger      = log.New(io.Discard, "", 0)
)

// NewTmpauth creates a new tmpauth handler. Although this can be used as a middleware, it doesn't
// have to be. For example you can leave most Config options unset, and use ParseWrappedAuthJWT
// to validate tokens.
func NewTmpauth(cfg *Config, next CaddyHandleFunc) *Tmpauth {
	if cfg.Logger == nil {
		cfg.Logger = DefaultLogger
	}
	if cfg.BaseHTTPClient == nil {
		cfg.BaseHTTPClient = http.DefaultClient
	}

	baseTransport := cfg.BaseHTTPClient.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}

	newClient := *cfg.BaseHTTPClient
	newClient.Transport = &Transport{
		config: cfg,
		base:   baseTransport,
	}

	done := make(chan struct{})
	t := &Tmpauth{
		Next:         next,
		Config:       cfg,
		HttpClient:   &newClient,
		TokenCache:   make(map[[32]byte]*CachedToken),
		HMAC:         hmac.New(sha1.New, cfg.Secret),
		stateIDCache: make(map[string]*StateIDSession),
		done:         done,
	}

	if cfg.UseFinalizer {
		runtime.SetFinalizer(t, func(t *Tmpauth) {
			t.Shutdown()
		})
	}

	return t
}

// Shutdown signals background workers in tmpauth to stop. This is required for all use cases
// of tmpauth as it's used to stop the cache janitor.
func (t *Tmpauth) Shutdown() {
	t.doneOnce.Do(func() {
		close(t.done)
	})
}
