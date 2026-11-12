package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type loginState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"expires"`
}

type adminSession struct {
	Subject string `json:"subject"`
	Group   string `json:"group"`
	Expires int64  `json:"expires"`
}

func (a *app) oidcContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, a.upstream.client)
}

func (a *app) initOIDC() error {
	provider, err := oidc.NewProvider(a.oidcContext(context.Background()), a.config.OIDCIssuer)
	if err != nil {
		return fmt.Errorf("discover Authentik OIDC provider: %w", err)
	}
	a.oauth = &oauth2.Config{
		ClientID: a.config.OIDCClientID, ClientSecret: a.config.OIDCClientSecret,
		Endpoint: provider.Endpoint(), RedirectURL: a.config.BaseURL + "/auth/callback",
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	a.verifier = provider.Verifier(&oidc.Config{
		ClientID: a.config.OIDCClientID, SupportedSigningAlgs: []string{oidc.RS256},
	})
	return nil
}

func (a *app) cookieName(purpose string) string {
	if strings.HasPrefix(a.config.BaseURL, "https://") {
		return "__Host-ms-invite-" + purpose
	}
	return "ms-invite-" + purpose
}

func (a *app) signCookie(purpose string, value any) string {
	data, _ := json.Marshal(value)
	payload := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, []byte(a.config.AdminToken))
	mac.Write([]byte(purpose + ":" + payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *app) readCookie(r *http.Request, purpose string, value any) error {
	cookie, err := r.Cookie(a.cookieName(purpose))
	if err != nil {
		return err
	}
	payload, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok || len(cookie.Value) > 4096 {
		return errors.New("invalid cookie")
	}
	mac := hmac.New(sha256.New, []byte(a.config.AdminToken))
	mac.Write([]byte(purpose + ":" + payload))
	got, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("invalid cookie signature")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func (a *app) setCookie(w http.ResponseWriter, purpose, value string, age int) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(purpose), Value: value, Path: "/", MaxAge: age,
		HttpOnly: true, Secure: strings.HasPrefix(a.config.BaseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *app) adminSession(r *http.Request) bool {
	var session adminSession
	return a.readCookie(r, "session", &session) == nil && session.Subject != "" &&
		session.Group == a.config.OIDCAdminGroup && time.Now().Unix() < session.Expires
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	transaction := loginState{State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(10 * time.Minute).Unix()}
	a.setCookie(w, "login", a.signCookie("login", transaction), 600)
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(transaction.Verifier)), http.StatusSeeOther)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	var transaction loginState
	if a.readCookie(r, "login", &transaction) != nil || transaction.State == "" ||
		!hmac.Equal([]byte(transaction.State), []byte(r.URL.Query().Get("state"))) || time.Now().Unix() >= transaction.Expires {
		http.Error(w, "login expired or invalid; start again at /admin", http.StatusBadRequest)
		return
	}
	a.setCookie(w, "login", "", -1)
	if r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
		http.Error(w, "Authentik login was not completed", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(a.oidcContext(r.Context()), 30*time.Second)
	defer cancel()
	token, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(transaction.Verifier))
	if err != nil {
		http.Error(w, "could not complete Authentik login", http.StatusBadGateway)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Authentik did not return an ID token", http.StatusBadGateway)
		return
	}
	id, err := a.verifier.Verify(ctx, raw)
	if err != nil || id.Subject == "" || !hmac.Equal([]byte(id.Nonce), []byte(transaction.Nonce)) {
		http.Error(w, "invalid Authentik ID token", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Groups          []string `json:"groups"`
		AuthorizedParty string   `json:"azp"`
	}
	if err := id.Claims(&claims); err != nil ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != a.config.OIDCClientID) ||
		(len(id.Audience) > 1 && claims.AuthorizedParty == "") ||
		!slices.Contains(claims.Groups, a.config.OIDCAdminGroup) {
		http.Error(w, "your Authentik account is not in the required admin group", http.StatusForbidden)
		return
	}
	expires := time.Now().Add(time.Hour)
	if id.Expiry.Before(expires) {
		expires = id.Expiry
	}
	session := adminSession{Subject: id.Subject, Group: a.config.OIDCAdminGroup, Expires: expires.Unix()}
	a.setCookie(w, "session", a.signCookie("session", session), max(1, int(time.Until(expires).Seconds())))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	a.setCookie(w, "session", "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
