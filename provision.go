package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	errUsernameTaken = errors.New("that username is already taken; choose another")
	errAttention     = errors.New("this signup needs administrator attention; please contact the person who invited you")
	usernamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,31}$`)
)

func validateSignup(username, email, password string) error {
	if !usernamePattern.MatchString(username) {
		return errors.New("use 3–32 lowercase letters, numbers, dots, underscores, or hyphens for your username; start with a letter or number")
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 {
		return errors.New("enter a valid email address")
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 128 || strings.TrimSpace(password) != password || strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("use a password of at least 12 characters and at most 128 bytes, without leading or trailing whitespace")
	}
	return nil
}

// Call while holding app.provisionMu. Each non-idempotent create is preceded by
// a durable intent marker. An interrupted/ambiguous create is never retried or
// reconciled by username: that could take over an unrelated existing account.
func (a *app) provision(token, username, email, password string) error {
	i, err := a.store.get(token)
	if err != nil {
		return err
	}
	if i.Creating != "" {
		return errAttention
	}
	if i.Username != "" && (i.Username != username || i.Email != email) {
		return errors.New("this invite has already started signup; use the original username and email")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	save := func() error { return a.store.put(token, i) }
	fail := func(err error) error {
		i.LastError = err.Error()
		if saveErr := save(); saveErr != nil {
			slog.Error("could not save signup failure", "invite_id", i.ID, "error", saveErr)
		}
		slog.Error("signup failed", "invite_id", i.ID, "error", err)
		if i.Creating != "" {
			return errAttention
		}
		return errors.New("signup could not finish; please try again with the same username and email, or contact your administrator")
	}
	if i.Status == "open" {
		if err := a.upstream.available(ctx, username); err != nil {
			if errors.Is(err, errUsernameTaken) {
				return err
			}
			return fail(err)
		}
		i.Username, i.Email, i.Status = username, email, "pending"
		if err := save(); err != nil {
			return fail(err)
		}
	}
	if i.AuthentikID == 0 {
		i.Creating = "authentik"
		if err := save(); err != nil {
			return fail(err)
		}
		id, err := a.upstream.createAuthentik(ctx, i)
		if err != nil {
			return fail(err)
		}
		i.AuthentikID, i.Creating = id, ""
		if err := save(); err != nil {
			return fail(err)
		}
	}
	akPath := fmt.Sprintf("/core/users/%d/", i.AuthentikID)
	// Disable first on every retry, since a prior activation may have succeeded.
	if err := a.upstream.call(ctx, "authentik", "PATCH", akPath, map[string]bool{"is_active": false}, nil); err != nil {
		return fail(err)
	}
	if err := a.upstream.call(ctx, "authentik", "POST", akPath+"set_password/", map[string]string{"password": password}, nil); err != nil {
		return fail(err)
	}
	if i.JellyfinID == "" {
		i.Creating = "jellyfin"
		if err := save(); err != nil {
			return fail(err)
		}
		id, err := a.upstream.createJellyfin(ctx, i)
		if err != nil {
			return fail(err)
		}
		i.JellyfinID, i.Creating = id, ""
		if err := save(); err != nil {
			return fail(err)
		}
	}
	if err := a.upstream.jellyfinPolicy(ctx, i.JellyfinID, true); err != nil {
		return fail(err)
	}
	if err := a.upstream.call(ctx, "jellyfin", "POST", "/Users/"+url.PathEscape(i.JellyfinID)+"/Password", map[string]any{"NewPw": password, "ResetPassword": false}, nil); err != nil {
		return fail(err)
	}
	if err := a.upstream.jellyfinPolicy(ctx, i.JellyfinID, false); err != nil {
		return fail(err)
	}
	if err := a.upstream.call(ctx, "authentik", "PATCH", akPath, map[string]bool{"is_active": true}, nil); err != nil {
		return fail(err)
	}
	i.Status, i.LastError = "used", ""
	if err := save(); err != nil {
		return fail(err)
	}
	slog.Info("signup completed", "invite_id", i.ID)
	return nil
}
