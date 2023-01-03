package tmpauthplugin

import (
	"context"
	"fmt"
	"net/http"

	"github.com/tmpim/tmpauth-go"
)

// Config the plugin configuration.
type Config = tmpauth.UnserializableConfig

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return new(Config)
}

type Tmpauth struct {
	next http.Handler
}

// New created a new Tmpauth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	parsedCfg, err := config.Parse()
	if err != nil {
		return nil, err
	}

	tmpauth := tmpauth.NewTmpauth(parsedCfg, tmpauth.FromHTTPHandler(next))

	return tmpauth.Stdlib(), nil
}
