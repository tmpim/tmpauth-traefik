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
	return &Config{
		PublicKey: "BN/PHEYgs0meH878gqpWl81WD3zEJ+ubih3RVYwFxaYXxHF+5tgDaJ/M++CRjur8vtXxoJnPETM8WRIc3CO0LyM=",
		Token:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdXRoLnRtcGltLnB3OnNlcnZlcjprZXk6ZmUyNzhhMmIwODY1NWM5YjYzNjQzZjI0N2E3NGFkMDciLCJpc3MiOiJhdXRoLnRtcGltLnB3OmNlbnRyYWwiLCJzZWNyZXQiOiJ6d2Q5TUpDVy9CbWdBcjNjeE0wbE1CU2tkaVVUa0JhUmNXZFp3ZkJPeGZRPSIsImlhdCI6MTY3MjczNTAxMSwic3ViIjoiZmUyNzhhMmIwODY1NWM5YjYzNjQzZjI0N2E3NGFkMDcifQ.RIpQebD1IgC7m7vtLzp_dDxNN0y6WSpU68PxlNBL9Ru7eFiP7hAbUwxX8X7B0PJv1MuRbJxrXpa2cwVChwIZfA",
	}
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
