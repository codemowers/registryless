package identity

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/codemowers/registryless/internal/auth"
	"github.com/codemowers/registryless/internal/ui"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Web struct {
	Vault                                       *Vault
	BaseURL, RegistryHost                       string
	UsernameClaim, UsernamePrefix, GroupsPrefix string
	PasswordTTL                                 time.Duration
	OAuth                                       oauth2.Config
	Verifier                                    *oidc.IDTokenVerifier
	HTTPClient                                  *http.Client
	work                                        chan struct{}
}

type cookieData struct {
	Kind      string    `json:"kind"`
	Expires   int64     `json:"expires"`
	State     string    `json:"state,omitempty"`
	Verifier  string    `json:"verifier,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
	CSRF      string    `json:"csrf,omitempty"`
	Principal Principal `json:"principal,omitempty"`
}

func NewWeb(ctx context.Context, v *Vault, baseURL, issuer, id, secret, claim, userPrefix, groupPrefix string, ttl time.Duration) (*Web, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("OIDC base URL must be an HTTPS origin")
	}
	i, err := url.Parse(issuer)
	if err != nil || i.Scheme != "https" || i.Host == "" {
		return nil, fmt.Errorf("OIDC issuer must use HTTPS")
	}
	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok {
		client = http.DefaultClient
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &Web{Vault: v, BaseURL: baseURL, RegistryHost: u.Host, UsernameClaim: claim, UsernamePrefix: userPrefix, GroupsPrefix: groupPrefix, PasswordTTL: ttl,
		OAuth:    oauth2.Config{ClientID: id, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: baseURL + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "groups"}},
		Verifier: provider.Verifier(&oidc.Config{ClientID: id}), HTTPClient: client, work: make(chan struct{}, 2)}, nil
}

func (w *Web) seal(c cookieData) string {
	b, _ := json.Marshal(c)
	body := base64.RawURLEncoding.EncodeToString(b)
	return body + "." + auth.MAC(w.Vault.SessionKey, "browser-cookie", []byte(body))
}
func (w *Web) open(value, kind string) (cookieData, error) {
	var c cookieData
	body, signature, ok := strings.Cut(value, ".")
	if !ok || !auth.Verify(w.Vault.SessionKey, "browser-cookie", []byte(body), signature) {
		return c, fmt.Errorf("invalid session")
	}
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Kind != kind || c.Expires < time.Now().Unix() {
		return c, fmt.Errorf("session expired")
	}
	return c, nil
}
func (w *Web) setCookie(rw http.ResponseWriter, name string, c cookieData) {
	http.SetCookie(rw, &http.Cookie{Name: name, Value: w.seal(c), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(time.Until(time.Unix(c.Expires, 0)).Seconds())})
}
func clearCookie(rw http.ResponseWriter, name string) {
	http.SetCookie(rw, &http.Cookie{Name: name, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func (w *Web) session(r *http.Request) (cookieData, error) {
	c, err := r.Cookie("__Host-registryless-session")
	if err != nil {
		return cookieData{}, err
	}
	return w.open(c.Value, "session")
}

func (w *Web) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	// no-referrer makes browsers serialize Origin as null on form POSTs,
	// conflicting with the same-origin validation on credential resets.
	rw.Header().Set("Referrer-Policy", "same-origin")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.URL.Path {
	case "/auth/login":
		if r.Method != "GET" {
			rw.WriteHeader(405)
			return
		}
		c := cookieData{Kind: "login", Expires: time.Now().Add(10 * time.Minute).Unix(), State: randomToken(), Verifier: oauth2.GenerateVerifier(), Nonce: randomToken()}
		w.setCookie(rw, "__Host-registryless-login", c)
		http.Redirect(rw, r, w.OAuth.AuthCodeURL(c.State, oauth2.S256ChallengeOption(c.Verifier), oidc.Nonce(c.Nonce)), http.StatusFound)
	case "/auth/callback":
		w.callback(rw, r)
	case "/credentials/reset":
		w.reset(rw, r)
	case "/":
		if r.Method != "GET" {
			rw.WriteHeader(405)
			return
		}
		c, err := w.session(r)
		if err != nil {
			w.page(rw, pageData{})
			return
		}
		w.page(rw, pageData{Name: c.Principal.DisplayName, CSRF: c.CSRF})
	default:
		http.NotFound(rw, r)
	}
}

func (w *Web) callback(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		rw.WriteHeader(405)
		return
	}
	cookie, err := r.Cookie("__Host-registryless-login")
	if err != nil {
		http.Error(rw, "Sign-in session missing. Start again.", 400)
		return
	}
	c, err := w.open(cookie.Value, "login")
	clearCookie(rw, "__Host-registryless-login")
	if err != nil || !hmac.Equal([]byte(c.State), []byte(r.URL.Query().Get("state"))) || r.URL.Query().Get("code") == "" {
		http.Error(rw, "Invalid sign-in response. Start again.", 400)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, w.HTTPClient), 15*time.Second)
	defer cancel()
	token, err := w.OAuth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(c.Verifier))
	if err != nil {
		http.Error(rw, "Sign-in exchange failed. Start again.", 502)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(rw, "Provider returned no identity.", 502)
		return
	}
	id, err := w.Verifier.Verify(ctx, raw)
	if err != nil || id.Nonce != c.Nonce {
		http.Error(rw, "Provider identity verification failed.", 401)
		return
	}
	var claims map[string]json.RawMessage
	if err := id.Claims(&claims); err != nil {
		http.Error(rw, "Invalid identity claims.", 401)
		return
	}
	readString := func(key string) string { var value string; _ = json.Unmarshal(claims[key], &value); return value }
	username := readString(w.UsernameClaim)
	if username == "" {
		http.Error(rw, "The identity provider did not supply the configured Kubernetes username claim.", 403)
		return
	}
	var groups []string
	if value, ok := claims["groups"]; ok {
		if err := json.Unmarshal(value, &groups); err != nil {
			http.Error(rw, "Invalid identity groups.", 403)
			return
		}
	}
	for i := range groups {
		groups[i] = w.GroupsPrefix + groups[i]
	}
	groups = append(groups, "system:authenticated")
	display := readString("name")
	if display == "" {
		display = username
	}
	p := Principal{Issuer: id.Issuer, Subject: id.Subject, Username: w.UsernamePrefix + username, DisplayName: display, Groups: groups}
	session := cookieData{Kind: "session", Expires: min(time.Now().Add(time.Hour).Unix(), id.Expiry.Unix()), CSRF: randomToken(), Principal: p}
	if len(w.seal(session)) > 3800 {
		http.Error(rw, "Identity groups exceed the session limit.", 403)
		return
	}
	w.setCookie(rw, "__Host-registryless-session", session)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *Web) reset(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		rw.WriteHeader(405)
		return
	}
	c, err := w.session(r)
	if err != nil {
		http.Error(rw, "Sign in again.", 401)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != w.BaseURL {
		http.Error(rw, "Invalid request origin.", 403)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !hmac.Equal([]byte(c.CSRF), []byte(r.PostForm.Get("csrf"))) {
		http.Error(rw, "Invalid request token.", 403)
		return
	}
	now := time.Now()
	ttl := w.PasswordTTL
	if choice := r.PostForm.Get("lifetime"); choice != "" {
		var err error
		ttl, err = credentialLifetime(choice, now)
		if err != nil {
			http.Error(rw, "Invalid credential lifetime.", 400)
			return
		}
	}
	select {
	case w.work <- struct{}{}:
		defer func() { <-w.work }()
	default:
		http.Error(rw, "Credential reset is busy. Try again.", 429)
		return
	}
	password, err := w.Vault.Rotate(r.Context(), c.Principal, ttl)
	if err != nil {
		http.Error(rw, "Could not save credentials. Try again.", 503)
		return
	}
	// Tokens and generated usernames use a shell-safe alphabet. The configured
	// hostname is shell-quoted as well; no identity-provider text enters the command.
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	command := "printf '%s' " + quote(password) + " | docker login " + quote(w.RegistryHost) + " --username " + quote(c.Principal.DockerUsername()) + " --password-stdin"
	w.page(rw, pageData{Name: c.Principal.DisplayName, CSRF: c.CSRF, Command: command, Expires: time.Now().Add(ttl).Format(time.RFC1123)})
}

type lifetimeOption struct {
	Value, Label string
	Selected     bool
}

var lifetimeOptions = []lifetimeOption{
	{Value: "1h", Label: "1 hour"},
	{Value: "24h", Label: "24 hours"},
	{Value: "72h", Label: "72 hours"},
	{Value: "1w", Label: "1 week"},
	{Value: "2w", Label: "2 weeks"},
	{Value: "1mo", Label: "1 month"},
	{Value: "3mo", Label: "3 months"},
	{Value: "6mo", Label: "6 months"},
}

func credentialLifetime(value string, now time.Time) (time.Duration, error) {
	switch value {
	case "1h":
		return time.Hour, nil
	case "24h":
		return 24 * time.Hour, nil
	case "72h":
		return 72 * time.Hour, nil
	case "1w":
		return 7 * 24 * time.Hour, nil
	case "2w":
		return 14 * 24 * time.Hour, nil
	case "1mo", "3mo", "6mo":
		months := map[string]int{"1mo": 1, "3mo": 3, "6mo": 6}[value]
		return now.AddDate(0, months, 0).Sub(now), nil
	default:
		return 0, fmt.Errorf("unsupported credential lifetime")
	}
}

type pageData struct {
	Name, CSRF, Command, Expires string
	Lifetimes                    []lifetimeOption
}

var page = template.Must(template.New("credentials").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Registryless</title><style>body{font:17px system-ui;max-width:760px;margin:8vh auto;padding:24px;color:#17212b;background:#f6f8fa}h1{font-size:38px}button,a{font:inherit}button{padding:12px 18px;cursor:pointer}pre{padding:20px;background:#17212b;color:#f0f5fa;white-space:pre-wrap;overflow-wrap:anywhere;border-radius:8px}small{color:#52616d}</style><h1>Push directly to your cluster.</h1><p>Registryless brings your Skaffold images straight to Kubernetes nodes.</p>{{if .Name}}<p>Signed in as <strong>{{.Name}}</strong>.</p><form action="/credentials/reset" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="lifetime">Expires in</label> <select id="lifetime" name="lifetime">{{range .Lifetimes}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select> <button type="submit">Reset Docker credentials</button></form><p>Resetting replaces your previous Docker password. Namespace access follows your Kubernetes permissions.</p>{{if .Command}}<h2>Your new Docker login</h2><p>Copy this command into your terminal. This password is shown only here.</p><pre>{{.Command}}</pre><small>Expires {{.Expires}}. The command contains a credential; your shell may save it in history.</small>{{end}}{{else}}<p><a href="/auth/login">Sign in to manage Docker credentials</a></p>{{end}}` + ui.Footer + `</html>`))

func (w *Web) page(rw http.ResponseWriter, data pageData) {
	data.Lifetimes = slices.Clone(lifetimeOptions)
	selected := false
	now := time.Now()
	for i := range data.Lifetimes {
		ttl, _ := credentialLifetime(data.Lifetimes[i].Value, now)
		if ttl == w.PasswordTTL {
			data.Lifetimes[i].Selected = true
			selected = true
		}
	}
	if !selected {
		data.Lifetimes = append([]lifetimeOption{{Label: "Default (" + w.PasswordTTL.String() + ")", Selected: true}}, data.Lifetimes...)
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(rw, data)
}
