package tmpauth_traefik

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
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
	handler atomic.Pointer[tmpauth.TmpauthStdlib]
}

func (a *AlwaysOnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := a.handler.Load()
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

			ta, err := tmpauth.NewMini(config, tmpauth.FromHTTPHandler(next))
			if err != nil {
				log.Printf("failed to initialize tmpauth mini for %q: %v", config.Host, err)
				time.Sleep(10 * time.Second)
				continue
			}

			handler.handler.Store(ta.Stdlib())

			break
		}
	}()

	return handler, nil
}
