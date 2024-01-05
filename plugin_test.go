package tmpauth_traefik

import (
	"context"
	"testing"
)

func TestPlugin(t *testing.T) {
	_, err := New(context.Background(), nil, &Config{
		PublicKey: "BN/PHEYgs0meH878gqpWl81WD3zEJ+ubih3RVYwFxaYXxHF+5tgDaJ/M++CRjur8vtXxoJnPETM8WRIc3CO0LyM=",
		Secret:    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdXRoLnRtcGltLnB3OnNlcnZlcjprZXk6ZmUyNzhhMmIwODY1NWM5YjYzNjQzZjI0N2E3NGFkMDciLCJpc3MiOiJhdXRoLnRtcGltLnB3OmNlbnRyYWwiLCJzZWNyZXQiOiJ6d2Q5TUpDVy9CbWdBcjNjeE0wbE1CU2tkaVVUa0JhUmNXZFp3ZkJPeGZRPSIsImlhdCI6MTY3MjczNTAxMSwic3ViIjoiZmUyNzhhMmIwODY1NWM5YjYzNjQzZjI0N2E3NGFkMDcifQ.RIpQebD1IgC7m7vtLzp_dDxNN0y6WSpU68PxlNBL9Ru7eFiP7hAbUwxX8X7B0PJv1MuRbJxrXpa2cwVChwIZfA",
	}, "tmpauth_traefik_test")
	if err != nil {
		t.Fatal(err)
	}
}
