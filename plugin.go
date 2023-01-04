package tmpauth_traefik

import (
	"context"
	"net/http"

	"github.com/tmpim/tmpauth-go"
)

// Config the plugin configuration.
type Config struct {
	PublicKey             string                           `json:"publicKey"`
	Token                 string                           `json:"secret"`
	AllowedUsers          []string                         `json:"allowedUsers"`
	IDFormats             []string                         `json:"idFormats"`
	Except                []string                         `json:"except"`
	Include               []string                         `json:"include"`
	Headers               map[string]*tmpauth.HeaderOption `json:"headers"`
	Redirect              string                           `json:"redirect"`
	Host                  string                           `json:"host"`
	Debug                 bool                             `json:"debug"`
	CaseSensitiveMatching bool                             `json:"caseSensitiveMatching"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return new(Config)
}

// New creates a new tmpauth plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	parsedCfg, err := (*tmpauth.UnserializableConfig)(config).Parse()
	if err != nil {
		return nil, err
	}

	tmpauth := tmpauth.NewTmpauth(parsedCfg, tmpauth.FromHTTPHandler(next))

	return tmpauth.Stdlib(), nil
}
