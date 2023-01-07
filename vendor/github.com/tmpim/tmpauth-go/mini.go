package tmpauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type MiniConfig struct {
	PublicKey             string                   `json:"publicKey"`
	Token                 string                   `json:"secret"`
	AllowedUsers          []string                 `json:"allowedUsers"`
	IDFormats             []string                 `json:"idFormats"`
	Except                []string                 `json:"except"`
	Include               []string                 `json:"include"`
	Headers               map[string]*HeaderOption `json:"headers"`
	Redirect              string                   `json:"redirect"`
	Host                  string                   `json:"host"`
	Debug                 bool                     `json:"debug"`
	CaseSensitiveMatching bool                     `json:"caseSensitiveMatching"`
	MiniServerHost        string                   `json:"miniServerHost,omitempty"`
}

type RemoteConfig struct {
	ConfigID string
	ClientID string
	Secret   []byte
}

func NewMini(config *MiniConfig, next CaddyHandleFunc) (*Tmpauth, error) {
	var lastErr error
	var remoteConfig RemoteConfig
	miniServerHost := config.MiniServerHost
	config.MiniServerHost = ""

	if miniServerHost == "" {
		return nil, fmt.Errorf("miniServerHost is empty and must be set")
	}

	tmpauthConfig, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodPut, miniServerHost+"/config", bytes.NewReader(tmpauthConfig))
		if err != nil {
			return nil, err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(3 * time.Second)
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			time.Sleep(3 * time.Second)
			continue
		}

		lastErr = json.NewDecoder(resp.Body).Decode(&remoteConfig)
		if lastErr != nil {
			time.Sleep(3 * time.Second)
			continue
		}

		break
	}

	if lastErr != nil {
		return nil, lastErr
	}

	log.Println("registered mini client with config ID:", remoteConfig.ConfigID)

	return &Tmpauth{
		Next: next,
		Config: &Config{
			Secret:                remoteConfig.Secret,
			ClientID:              remoteConfig.ClientID,
			Token:                 config.Token,
			AllowedUsers:          config.AllowedUsers,
			IDFormats:             config.IDFormats,
			Except:                config.Except,
			Include:               config.Include,
			Headers:               config.Headers,
			Redirect:              config.Redirect,
			Debug:                 config.Debug,
			CaseSensitiveMatching: config.CaseSensitiveMatching,
			Logger:                DefaultLogger,
		},
		TokenCache: make(map[[32]byte]*CachedToken),
		HttpClient: nil, // unused in mini mode

		stateIDCache:    make(map[string]*StateIDSession),
		stateIDMutex:    sync.Mutex{},
		tokenCacheMutex: sync.RWMutex{},
		hmacMutex:       sync.Mutex{},
		janitorOnce:     sync.Once{},

		miniServerHost: miniServerHost,
		miniConfigID:   remoteConfig.ConfigID,
		miniClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},

		done:     make(chan struct{}),
		doneOnce: sync.Once{},
	}, nil
}
