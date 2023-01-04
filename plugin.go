package tmpauth_traefik

import (
	"context"
	"net/http"

	"github.com/tmpim/tmpauth-go"
)

// Config the plugin configuration.
type Config = tmpauth.UnserializableConfig

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return new(Config)
}

// New creates a new tmpauth plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	parsedCfg, err := config.Parse()
	if err != nil {
		return nil, err
	}

	tmpauth := tmpauth.NewTmpauth(parsedCfg, tmpauth.FromHTTPHandler(next))

	return tmpauth.Stdlib(), nil
}
