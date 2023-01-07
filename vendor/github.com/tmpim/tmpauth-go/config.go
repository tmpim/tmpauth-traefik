package tmpauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type Config struct {
	PublicKey *ecdsa.PublicKey
	ClientID  string
	Secret    []byte
	Token     string

	Redirect              string
	AllowedUsers          []string
	IDFormats             []string
	Except                []string
	Include               []string
	Headers               map[string]*HeaderOption
	Host                  *url.URL
	CaseSensitiveMatching bool

	// Advanced settings, default zero values are sane.
	Debug          bool
	BaseHTTPClient *http.Client
	Logger         *log.Logger // If nil, DefaultLogger is used. Set to NoLogger to disable logging.
	UseFinalizer   bool        // Use the finalizer to clean up background workers.
}

// UnserializableConfig is a convenience struct for unmarshalling config from JSON like formats
// and validating them into a Config.
type UnserializableConfig struct {
	PublicKey             string                   `json:"publicKey"`
	Secret                string                   `json:"secret"`
	AllowedUsers          []string                 `json:"allowedUsers"`
	IDFormats             []string                 `json:"idFormats"`
	Except                []string                 `json:"except"`
	Include               []string                 `json:"include"`
	Headers               map[string]*HeaderOption `json:"headers"`
	Redirect              string                   `json:"redirect"`
	Host                  string                   `json:"host"`
	Debug                 bool                     `json:"debug"`
	CaseSensitiveMatching bool                     `json:"caseSensitiveMatching"`
}

type configClaims struct {
	Secret   string `json:"secret"`
	clientID []byte `json:"-"`
	jwt.StandardClaims
}

func (c *configClaims) Valid() error {
	if c.Subject == "" {
		return fmt.Errorf("tmpauth: subject cannot be empty")
	}

	if !c.VerifyIssuer(TmpAuthHost+":central", true) {
		return fmt.Errorf("tmpauth: issuer invalid, got: %v", c.Issuer)
	}

	if !c.VerifyAudience(TmpAuthHost+":server:key:"+c.Subject, true) {
		return fmt.Errorf("tmpauth: audience invalid, got: %v", c.Audience)
	}

	return nil
}

func (c *UnserializableConfig) Parse() (*Config, error) {
	if len(c.PublicKey) == 0 || len(c.Secret) == 0 {
		return nil, fmt.Errorf("tmpauth: both public_key and secret must be specified")
	}

	pubKeyData, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("tmpauth: invalid public_key: %w", err)
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyData)
	if x == nil {
		return nil, fmt.Errorf("tmpauth: invalid public_key")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	token, err := jwt.ParseWithClaims(c.Secret, &configClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("tmpauth: invalid secret signing method: %v", token.Header["alg"])
		}

		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("tmpauth: invalid secret: %w", err)
	}

	claims := token.Claims.(*configClaims)

	if len(c.Except) != 0 && len(c.Include) != 0 {
		return nil, fmt.Errorf("tmpauth: both exclude and include cannot be specified at the same time")
	}

	if claims.Secret == "" {
		return nil, fmt.Errorf("tmpauth: secret cannot be empty")
	}

	var u *url.URL
	if c.Host != "" {
		if !strings.HasPrefix(c.Host, "http://") && !strings.HasPrefix(c.Host, "https://") {
			c.Host = "https://" + c.Host
		}

		u, err = url.Parse(c.Host)
		if err != nil {
			return nil, fmt.Errorf("tmpauth: failed to parse host : %w", err)
		}

		u.Scheme = "https"
		u.RawPath = ""
		u.Path = strings.TrimSuffix(u.Path, "/")
	}

	if u == nil {
		u = &url.URL{}
	}

	return &Config{
		PublicKey:             pubKey,
		ClientID:              claims.Subject,
		Token:                 c.Secret,
		Secret:                []byte(claims.Secret),
		Redirect:              c.Redirect,
		Include:               c.Include,
		Except:                c.Except,
		AllowedUsers:          c.AllowedUsers,
		IDFormats:             c.IDFormats,
		Headers:               c.Headers,
		Host:                  u,
		Debug:                 c.Debug,
		CaseSensitiveMatching: c.CaseSensitiveMatching,
	}, nil
}
