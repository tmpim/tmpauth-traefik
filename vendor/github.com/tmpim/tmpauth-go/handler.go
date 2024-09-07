package tmpauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Path represents a URI path.
type Path string

// Matches checks to see if base matches p. The correct
// usage of this method sets p as the request path, and
// base as a Casketfile (user-defined) rule path.
//
// Path matching will probably not always be a direct
// comparison; this method assures that paths can be
// easily and consistently matched.
//
// Multiple slashes are collapsed/merged.
// Lifted from https://github.com/tmpim/casket/blob/v1.2.11/caskethttp/httpserver/path.go
// This code sample may be considered to be licensed under the Apache License 2.0
// which can be found at https://github.com/tmpim/casket/blob/master/LICENSE.txt
func (t *Tmpauth) Matches(urlPath, base string) bool {
	if base == "/" || base == "" {
		return true
	}

	// sanitize the paths for comparison, very important
	// (slightly lossy if the base path requires multiple
	// consecutive forward slashes, since those will be merged)
	pHasTrailingSlash := strings.HasSuffix(string(urlPath), "/")
	baseHasTrailingSlash := strings.HasSuffix(base, "/")
	urlPath = path.Clean(string(urlPath))
	base = path.Clean(base)
	if pHasTrailingSlash {
		urlPath += "/"
	}
	if baseHasTrailingSlash {
		base += "/"
	}

	if t.Config.CaseSensitiveMatching {
		return strings.HasPrefix(string(urlPath), base)
	}
	return strings.HasPrefix(strings.ToLower(string(urlPath)), strings.ToLower(base))
}

type StatusResponse struct {
	Tmpauth        bool            `json:"tmpauth"`
	ClientID       string          `json:"clientID"`
	IsLoggedIn     bool            `json:"isLoggedIn"`
	UserDescriptor json.RawMessage `json:"loggedInUser,omitempty"`
}

func (t *Tmpauth) serveStatus(w http.ResponseWriter, token *CachedToken) (int, error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := &StatusResponse{
		Tmpauth:    true,
		ClientID:   t.Config.ClientID,
		IsLoggedIn: token != nil,
	}

	if token != nil {
		resp.UserDescriptor = json.RawMessage(token.UserDescriptor)
	}

	json.NewEncoder(w).Encode(resp)

	return 0, nil
}

func (t *Tmpauth) janitor() {
	t.DebugLog("token cache janitor started")

	ticker := time.NewTicker(2 * time.Minute)
	for {
		select {
		case <-t.done:
			t.DebugLog("stopping token cache janitor")
			ticker.Stop()
			return
		case <-ticker.C:
			t.DebugLog("running token cache janitor")

			t.tokenCacheMutex.Lock()

			now := time.Now()
			for k, v := range t.TokenCache {
				if now.After(v.RevalidateAt) {
					delete(t.TokenCache, k)
				}
			}

			t.tokenCacheMutex.Unlock()

			t.stateIDMutex.Lock()

			now = time.Now()
			for k, v := range t.stateIDCache {
				if now.After(v.ExpiresAt) {
					delete(t.stateIDCache, k)
				}
			}

			t.stateIDMutex.Unlock()
		}
	}
}

func (t *Tmpauth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if len(t.Config.Headers) > 0 {
		for header := range t.Config.Headers {
			r.Header.Del(header)
		}
	}

	statusRequested := false
	whomstRequested := false

	if t.Matches(r.URL.Path, "/.well-known/tmpauth/") {
		if t.miniServerHost != "" {
			u, err := url.Parse(t.miniServerHost)
			if err != nil {
				return http.StatusInternalServerError, fmt.Errorf("parse mini server host: %w", err)
			}

			u.Path = r.URL.Path
			u.RawQuery = r.URL.RawQuery

			req, err := http.NewRequest(r.Method, u.String(), r.Body)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			req.Header = r.Header
			req.Header.Set(ConfigIDHeader, t.miniConfigID)

			t.DebugLog(fmt.Sprintf("proxying request to mini server: %s", u.String()))

			resp, err := t.miniClient(req, 0)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			defer resp.Body.Close()

			for k, v := range resp.Header {
				w.Header()[k] = v
			}

			w.WriteHeader(resp.StatusCode)

			_, err = io.Copy(w, resp.Body)

			return 0, err
		}

		switch strings.TrimPrefix(r.URL.Path, "/.well-known/tmpauth/") {
		case "callback":
			return t.authCallback(w, r)
		case "status":
			statusRequested = true
			break
		case "whomst":
			whomstRequested = true
			break
		default:
			return http.StatusBadRequest, fmt.Errorf("tmpauth: no such path")
		}
	}

	// determine if auth is required
	authRequired := true

	// If the URL path is weird, it signals a possible attack attempt.
	// always require authentication in such a condition.
	if path.Clean(r.URL.Path) == r.URL.Path {
		if len(t.Config.Except) > 0 {
			for _, exempt := range t.Config.Except {
				if t.Matches(r.URL.Path, exempt) {
					authRequired = false
					break
				}
			}
		} else if len(t.Config.Include) > 0 {
			found := false
			for _, included := range t.Config.Include {
				if t.Matches(r.URL.Path, included) {
					found = true
					break
				}
			}
			if !found {
				authRequired = false
			}
		}
	} else {
		t.DebugLog(fmt.Sprintf("url path is suspicious, authentication being mandated: %v != %v",
			path.Clean(r.URL.Path), r.URL.Path))
	}

	t.DebugLog(fmt.Sprintf("auth requirement for %q: %v", r.URL.Path, authRequired))

	cachedToken, err := t.authFromCookie(r)
	if err != nil {
		t.DebugLog(fmt.Sprintf("failed to get JWT token: %v", err))

		if _, err := r.Cookie(t.CookieName()); err != http.ErrNoCookie {
			t.DebugLog("cookie exists and deemed to be invalid, requesting client to delete cookie")

			http.SetCookie(w, &http.Cookie{
				Name:     t.CookieName(),
				Value:    "",
				MaxAge:   -1,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}

		// Not authed, return an empty status or whomst response if requested
		if statusRequested {
			return t.serveStatus(w, nil)
		} else if whomstRequested {
			return t.serveWhomst(w, nil)
		}

		// Begin auth flow
		if authRequired {
			return t.StartAuth(w, r)
		}
	} else if len(t.Config.Headers) > 0 {
		err := t.SetHeaders(cachedToken, r.Header)
		if err != nil {
			t.DebugLog(fmt.Sprintf("failed to set headers: %v", err))
			return http.StatusPreconditionRequired, fmt.Errorf("tmpauth: missing required header value")
		}
	}

	// Token is available (authenticated, but not necessarily allowed), serve the status response if requested
	if statusRequested {
		return t.serveStatus(w, cachedToken)
	}

	userAuthorized := false
	if len(t.Config.AllowedUsers) > 0 {
		t.DebugLog(fmt.Sprintf("checking if user is allowed on allowed users list: %v", cachedToken.UserIDs))
		userIDs := make(map[string]bool)
		for _, userID := range cachedToken.UserIDs {
			userIDs[userID] = true
		}

		for _, allowedUser := range t.Config.AllowedUsers {
			if userIDs[allowedUser] {
				userAuthorized = true
				break
			}
		}
	} else {
		userAuthorized = true
	}

	if !userAuthorized {
		t.DebugLog("user not on allowed users list")
		return http.StatusForbidden, fmt.Errorf("tmpauth: user not in allowed list")
	}

	// Now serve the whomst response if requested (authenticated and authorized)
	if whomstRequested {
		return t.serveWhomst(w, cachedToken)
	}

	return t.Next(w, r)
}

func (t *Tmpauth) StartAuth(w http.ResponseWriter, r *http.Request) (int, error) {
	if t.miniServerHost != "" {
		req, err := http.NewRequest(http.MethodGet, t.miniServerHost+"/start-auth", nil)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("invalid mini server request: %w", err)
		}

		req.Header.Set(ConfigIDHeader, t.miniConfigID)
		req.Header.Set(RequestURIHeader, r.RequestURI)
		req.Header.Set(HostHeader, r.Host)
		req.Header.Set("Content-Type", "application/jwt")

		resp, err := t.miniClient(req, 0)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("StartAuth on mini server: %w", err)
		}
		defer resp.Body.Close()

		for k, v := range resp.Header {
			w.Header()[k] = v
		}

		w.WriteHeader(resp.StatusCode)

		_, err = io.Copy(w, resp.Body)

		return 0, err
	}

	now := time.Now()
	expiry := time.Now().Add(5 * time.Minute)
	tokenID := generateTokenID()

	host := t.Config.Host

	if host.Host == "" {
		var err error
		host, err = url.Parse("https://" + r.Header.Get("Host"))
		if err != nil {
			t.DebugLog(fmt.Sprintf("could not determine host: %v", err))
			return http.StatusInternalServerError, errors.New("tmpauth: could not determine host")
		}
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &stateClaims{
		CallbackURL: "https://" + host.Host + host.Path + "/.well-known/tmpauth/callback",
		StandardClaims: jwt.StandardClaims{
			Id:        tokenID,
			Issuer:    TmpAuthHost + ":server:" + t.Config.ClientID,
			Audience:  TmpAuthHost + ":central:state",
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
			ExpiresAt: expiry.Unix(),
		},
	}).SignedString(t.Config.Secret)
	if err != nil {
		t.DebugLog(fmt.Sprintf("failed to sign state token: %v", err))
		return http.StatusInternalServerError, errors.New("tmpauth: failed to start authentication")
	}

	requestURI := r.URL.RequestURI()

	t.stateIDMutex.Lock()
	t.stateIDCache[tokenID] = &StateIDSession{
		RedirectURI: requestURI,
		ExpiresAt:   time.Now().Add(time.Minute * 5),
	}
	t.stateIDMutex.Unlock()

	// store request URIs in cookies sometimes in case this is a distributed
	// casket instance or something and it'll still work in most cases
	if len(requestURI) <= 128 {
		http.SetCookie(w, &http.Cookie{
			Name:     t.StateIDCookieName(tokenID),
			Value:    url.QueryEscape(requestURI),
			Expires:  expiry,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:     t.StateIDCookieName(tokenID),
			Value:    "ok",
			Expires:  expiry,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	queryParams := url.Values{
		"state":     []string{token},
		"client_id": []string{t.Config.ClientID},
		"method":    []string{"tmpauth"},
	}

	http.Redirect(w, r, "https://"+TmpAuthHost+"/auth?"+queryParams.Encode(), http.StatusSeeOther)

	return 0, nil
}

// authFromCookie attempts to get the auth token from the cookie or the X-Tmpauth-Token header, and returns the
// cachedToken (if it was successfully parsed), and any error.
func (t *Tmpauth) authFromCookie(r *http.Request) (*CachedToken, error) {
	token := r.Header.Get("X-Tmpauth-Token")
	if token != "" {
		return t.ParseWrappedAuthJWT(token)
	}

	cookie, err := r.Cookie(t.CookieName())
	if err != nil {
		return nil, err
	}

	return t.ParseWrappedAuthJWT(cookie.Value)
}

// serveWhomst returns the entire whomst database if the user is logged in.
func (t *Tmpauth) serveWhomst(w http.ResponseWriter, token *CachedToken) (int, error) {
	// If the user is not logged in, return an error
	if token == nil {
		return http.StatusUnauthorized, fmt.Errorf("tmpauth: must be logged in to retrieve whomst database")
	}

	whomstData, err := t.Whomst(token)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("tmpauth: failed to retrieve whomst data: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(whomstData)

	return 0, nil
}

func (t *Tmpauth) Whomst(token *CachedToken) (map[string]json.RawMessage, error) {
	var resp *http.Response
	var respErr error

	if t.miniServerHost != "" {
		req, err := http.NewRequest(http.MethodGet, t.miniServerHost+"/tmpauth/whomst", nil)
		if err != nil {
			return nil, fmt.Errorf("invalid mini server request: %w", err)
		}

		req.Header.Set(TokenHeader, token.InnerToken)

		resp, respErr = t.miniClient(req, 0)
	} else {
		resp, respErr = t.HttpClient.Get("https://" + TmpAuthHost + "/whomst/tmpauth/db?token=" +
			url.QueryEscape(token.InnerToken))
	}
	if respErr != nil {
		return nil, respErr
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tmpauth: status code %d", resp.StatusCode)
	}

	var whomst map[string]json.RawMessage
	err := json.NewDecoder(resp.Body).Decode(&whomst)
	if err != nil {
		return nil, err
	}

	return whomst, nil
}

// Stdlib returns a http.Handler compatible version of the Tmpauth middleware.
func (t *Tmpauth) Stdlib() *TmpauthStdlib {
	return &TmpauthStdlib{tmpauth: t}
}

type TmpauthStdlib struct {
	tmpauth *Tmpauth
}

func (t *TmpauthStdlib) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code, err := t.tmpauth.ServeHTTP(w, r)
	if err != nil {
		if code == 0 {
			code = http.StatusInternalServerError
		}
		w.WriteHeader(code)
		t.tmpauth.DebugLog(fmt.Sprintf("tmpauth error: %+v", err))
	}
}
