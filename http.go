package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

//go:embed web/*
var assets embed.FS

var pages = template.Must(template.ParseFS(assets, "web/*.html"))

type app struct {
	config      config
	store       *store
	upstream    *upstream
	provisionMu sync.Mutex // One signup at a time; also serializes revocation.
	oauth       *oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

func newApp(c config, s *store) *app {
	return &app{config: c, store: s, upstream: newUpstream(c)}
}

func (a *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		render(w, "message.html", pageData{Title: "You're invited", Message: "Ask your media server administrator for an invite link."})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, r *http.Request) {
		data, _ := assets.ReadFile("web/style.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(data)
	})
	mux.HandleFunc("GET /invite/{token}", a.invitePage)
	mux.HandleFunc("POST /invite/{token}", a.accept)
	mux.HandleFunc("GET /admin", a.admin(false, a.adminPage))
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("POST /auth/logout", a.admin(false, a.logout))
	mux.HandleFunc("POST /admin/invites", a.admin(false, a.createInvite))
	mux.HandleFunc("POST /admin/invites/{id}/revoke", a.admin(false, a.revokeInvite))
	mux.HandleFunc("GET /api/invites", a.admin(true, a.listInvites))
	mux.HandleFunc("POST /api/invites", a.admin(true, a.createInvite))
	mux.HandleFunc("POST /api/invites/{id}/revoke", a.admin(true, a.revokeInvite))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		mux.ServeHTTP(w, r)
	})
}

type pageData struct {
	Title, Message, Error, Link string
	Invite                      invite
	Invites                     []invite
}

func render(w http.ResponseWriter, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render failed", "error", err)
	}
}

func (a *app) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == a.config.BaseURL
}

func (a *app) admin(api bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string
		if api {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				token = ""
			}
		}
		got, want := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(a.config.AdminToken))
		if api && subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !api && !a.adminSession(r) {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		if r.Method == "POST" && (!api || r.Header.Get("Origin") != "") && !a.sameOrigin(r) {
			http.Error(w, "invalid request origin", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (a *app) adminPage(w http.ResponseWriter, r *http.Request) {
	render(w, "admin.html", pageData{Title: "Invitations", Invites: a.store.list()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func (a *app) listInvites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.list())
}

func (a *app) createInvite(w http.ResponseWriter, r *http.Request) {
	input := struct {
		Label          string `json:"label"`
		ExpiresInHours int    `json:"expires_in_hours"`
	}{ExpiresInHours: 168}
	api := strings.HasPrefix(r.URL.Path, "/api/")
	if api {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil {
			http.Error(w, "expected JSON with label and expires_in_hours", http.StatusBadRequest)
			return
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			http.Error(w, "expected a single JSON object", http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		input.Label = r.PostForm.Get("label")
		hours, err := strconv.Atoi(r.PostForm.Get("expires_in_hours"))
		if err != nil {
			http.Error(w, "choose an invitation expiry", http.StatusBadRequest)
			return
		}
		input.ExpiresInHours = hours
	}
	input.Label = strings.TrimSpace(input.Label)
	if len(input.Label) > 120 || input.ExpiresInHours < 0 || input.ExpiresInHours > 8760 {
		http.Error(w, "label must be at most 120 bytes; expiry must be 0 (never) or 1–8760 hours", http.StatusBadRequest)
		return
	}
	i, token, err := a.store.create(input.Label, time.Duration(input.ExpiresInHours)*time.Hour)
	if err != nil {
		slog.Error("create invite failed", "error", err)
		http.Error(w, "could not save invite", http.StatusInternalServerError)
		return
	}
	link := a.config.BaseURL + "/invite/" + token
	if api {
		writeJSON(w, http.StatusCreated, struct {
			Invite invite `json:"invite"`
			URL    string `json:"url"`
		}{i, link})
		return
	}
	render(w, "admin.html", pageData{Title: "Invitation created", Link: link, Invites: a.store.list()})
}

func (a *app) revokeInvite(w http.ResponseWriter, r *http.Request) {
	if !a.provisionMu.TryLock() {
		http.Error(w, "a signup is in progress; try again shortly", http.StatusConflict)
		return
	}
	defer a.provisionMu.Unlock()
	if err := a.store.revoke(r.PathValue("id")); err != nil {
		http.Error(w, "could not revoke invite", http.StatusConflict)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *app) invitePage(w http.ResponseWriter, r *http.Request) {
	i, err := a.store.get(r.PathValue("token"))
	if err != nil {
		http.Error(w, "invite unavailable", http.StatusGone)
		return
	}
	if i.Creating != "" {
		render(w, "message.html", pageData{Title: "Signup needs a review", Message: errAttention.Error()})
		return
	}
	render(w, "invite.html", pageData{Title: "Create your account", Invite: i})
}

func (a *app) accept(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !a.provisionMu.TryLock() {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "another signup is in progress; please try again shortly", http.StatusServiceUnavailable)
		return
	}
	defer a.provisionMu.Unlock()
	token := r.PathValue("token")
	i, err := a.store.get(token)
	if err != nil {
		http.Error(w, "invite unavailable", http.StatusGone)
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	email := strings.TrimSpace(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")
	err = validateSignup(username, email, password)
	if err == nil && password != r.PostForm.Get("password_confirm") {
		err = errors.New("passwords do not match")
	}
	if err == nil {
		err = a.provision(token, username, email, password)
	}
	if err != nil {
		i.Username, i.Email = username, email
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		render(w, "invite.html", pageData{Title: "Check your details", Error: err.Error(), Invite: i})
		return
	}
	// A refresh cannot resubmit credentials or reuse the capability.
	render(w, "message.html", pageData{Title: "Your account is ready.", Message: "Your Jellyfin and Authentik accounts are ready. Sign in with the username and password you just chose."})
}
