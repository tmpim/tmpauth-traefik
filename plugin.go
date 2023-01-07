package tmpauth_traefik

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/tmpim/tmpauth-go"
)

// Config the plugin configuration.
type Config = tmpauth.MiniConfig

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type AlwaysOnHandler struct {
	handler *tmpauth.TmpauthStdlib
	mu      sync.Mutex
}

func (a *AlwaysOnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	handler := a.handler
	a.mu.Unlock()
	if handler == nil {
		http.Error(w, "tmpauth not initialized", http.StatusInternalServerError)
		return
	}

	handler.ServeHTTP(w, r)
}

// New creates a new tmpauth plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	handler := &AlwaysOnHandler{}

	go func() {
		for {
			if config.Host == "" {
				log.Printf("tmpauth host is empty and must be set")
				time.Sleep(10 * time.Second)
				continue
			}

			ta, err := tmpauth.NewMini(*config, tmpauth.FromHTTPHandler(next))
			if err != nil {
				log.Printf("failed to initialize tmpauth mini for %q: %v", config.Host, err)
				time.Sleep(10 * time.Second)
				continue
			}

			handler.handler = ta.Stdlib()

			break
		}
	}()

	return handler, nil
}
