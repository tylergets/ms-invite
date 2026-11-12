package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestOIDCLogin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want int
	}{
		{"success", 303}, {"non-admin", 403}, {"wrong-nonce", 401},
		{"wrong-audience", 401}, {"expired", 401}, {"wrong-issuer", 401}, {"bad-signature", 401}, {"wrong-state", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var issuer, nonce, verifier string
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
				case "/keys":
					json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
				case "/token":
					r.ParseForm()
					if r.Form.Get("code_verifier") != verifier || verifier == "" {
						t.Error("PKCE verifier missing")
					}
					if r.Form.Get("redirect_uri") != "https://invite.example.com/auth/callback" {
						t.Error("wrong redirect URI")
					}
					claims := map[string]any{"iss": issuer, "sub": "admin-user", "aud": "client-id", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce, "groups": []string{"media-admins"}}
					switch tc.name {
					case "non-admin":
						claims["groups"] = []string{"media-users"}
					case "wrong-nonce":
						claims["nonce"] = "wrong"
					case "wrong-audience":
						claims["aud"] = "another-client"
					case "expired":
						claims["exp"] = time.Now().Add(-time.Hour).Unix()
					case "wrong-issuer":
						claims["iss"] = "https://another.example"
					}
					payload, _ := json.Marshal(claims)
					unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
					hash := sha256.Sum256([]byte(unsigned))
					signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					if tc.name == "bad-signature" {
						signature[0] ^= 1
					}
					json.NewEncoder(w).Encode(map[string]any{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600, "id_token": unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)})
				default:
					t.Errorf("unexpected OIDC request: %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer provider.Close()
			issuer = provider.URL
			a, _ := testApp(t)
			a.config.OIDCIssuer, a.config.OIDCClientID, a.config.OIDCClientSecret = issuer, "client-id", "client-secret"
			if err := a.initOIDC(); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			a.handler().ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
			if w.Code != 303 {
				t.Fatalf("login: %d", w.Code)
			}
			location, _ := url.Parse(w.Header().Get("Location"))
			cookie := w.Result().Cookies()[0]
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("unsafe login cookie")
			}
			read := httptest.NewRequest("GET", "/", nil)
			read.AddCookie(cookie)
			var transaction loginState
			if err := a.readCookie(read, "login", &transaction); err != nil {
				t.Fatal(err)
			}
			nonce, verifier = transaction.Nonce, transaction.Verifier
			challenge := sha256.Sum256([]byte(verifier))
			if location.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(challenge[:]) || location.Query().Get("nonce") != nonce {
				t.Fatal("missing PKCE or nonce")
			}
			state := transaction.State
			if tc.name == "wrong-state" {
				state = "attacker"
			}
			r := httptest.NewRequest("GET", "/auth/callback?code=test-code&state="+url.QueryEscape(state), nil)
			r.AddCookie(cookie)
			w = httptest.NewRecorder()
			a.handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("callback got %d want %d: %s", w.Code, tc.want, w.Body.String())
			}
			valid := false
			for _, c := range w.Result().Cookies() {
				if c.Name != a.cookieName("session") {
					continue
				}
				req := httptest.NewRequest("GET", "/admin", nil)
				req.AddCookie(c)
				valid = a.adminSession(req)
			}
			if valid != (tc.name == "success") {
				t.Fatal("unexpected session authorization")
			}
		})
	}
}

func TestSessionTamperingExpiryAndPurpose(t *testing.T) {
	a, _ := testApp(t)
	for _, tc := range []struct {
		name, purpose, group string
		expiry               time.Time
		tamper               bool
	}{
		{"expired", "session", "media-admins", time.Now().Add(-time.Second), false},
		{"wrong group", "session", "media-users", time.Now().Add(time.Hour), false},
		{"wrong purpose", "login", "media-admins", time.Now().Add(time.Hour), false},
		{"tampered", "session", "media-admins", time.Now().Add(time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := a.signCookie(tc.purpose, adminSession{Subject: "admin", Group: tc.group, Expires: tc.expiry.Unix()})
			if tc.tamper {
				value = strings.Replace(value, ".", "x.", 1)
			}
			r := httptest.NewRequest("GET", "/admin", nil)
			r.AddCookie(&http.Cookie{Name: a.cookieName("session"), Value: value})
			if a.adminSession(r) {
				t.Fatal("invalid session authorized")
			}
		})
	}
}
