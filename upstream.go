package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type upstream struct {
	config config
	client *http.Client
}

func newUpstream(c config) *upstream {
	return &upstream{config: c, client: &http.Client{
		Timeout: 15 * time.Second,
		// Never forward an API credential to a redirect target.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Errors deliberately exclude bodies (which can echo credentials or user input).
func (u *upstream) call(ctx context.Context, system, method, path string, body, result any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	base := u.config.AuthentikURL + "/api/v3"
	if system == "jellyfin" {
		base = u.config.JellyfinURL
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: invalid request", system)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if system == "jellyfin" {
		req.Header.Set("Authorization", fmt.Sprintf("MediaBrowser Token=%q", u.config.JellyfinKey))
	} else {
		req.Header.Set("Authorization", "Bearer "+u.config.AuthentikToken)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: request failed or timed out", system)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s %s returned HTTP %d", system, method, strings.Split(path, "?")[0], resp.StatusCode)
	}
	if result != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(result); err != nil {
			return fmt.Errorf("%s: invalid API response", system)
		}
	}
	return nil
}

func (u *upstream) available(ctx context.Context, username string) error {
	if u.config.AuthentikEnabled {
		var ak struct {
			Results []struct {
				Username string `json:"username"`
			} `json:"results"`
		}
		if err := u.call(ctx, "authentik", "GET", "/core/users/?username="+url.QueryEscape(username), nil, &ak); err != nil {
			return err
		}
		if len(ak.Results) > 0 {
			return errUsernameTaken
		}
	}
	if u.config.JellyfinEnabled {
		var jf []struct{ Name string }
		if err := u.call(ctx, "jellyfin", "GET", "/Users", nil, &jf); err != nil {
			return err
		}
		for _, user := range jf {
			if strings.EqualFold(user.Name, username) {
				return errUsernameTaken
			}
		}
	}
	return nil
}

func (u *upstream) createAuthentik(ctx context.Context, inviteID string, i signupAttempt) (int, error) {
	var result struct {
		PK int `json:"pk"`
	}
	groups := u.config.AuthentikGroups
	if groups == nil {
		groups = []string{}
	}
	err := u.call(ctx, "authentik", "POST", "/core/users/", map[string]any{
		"username": i.Username, "name": i.Username, "email": i.Email,
		"is_active": false, "path": u.config.AuthentikPath, "groups": groups,
		"type": "internal", "attributes": map[string]string{"ms_invite_id": inviteID, "ms_invite_signup_id": i.ID},
	}, &result)
	if err == nil && result.PK <= 0 {
		err = fmt.Errorf("authentik: missing user ID")
	}
	return result.PK, err
}

func (u *upstream) createJellyfin(ctx context.Context, i signupAttempt) (string, error) {
	// A random bootstrap password ensures a half-created account cannot be used.
	password, err := randomToken(32)
	if err != nil {
		return "", err
	}
	var result struct {
		ID string `json:"Id"`
	}
	err = u.call(ctx, "jellyfin", "POST", "/Users/New", map[string]string{"Name": i.Username, "Password": password}, &result)
	if err == nil && (result.ID == "" || strings.ContainsAny(result.ID, "/?#")) {
		err = fmt.Errorf("jellyfin: missing or invalid user ID")
	}
	return result.ID, err
}

func (u *upstream) jellyfinPolicy(ctx context.Context, id string, disabled bool) error {
	var result struct{ Policy map[string]any }
	path := "/Users/" + url.PathEscape(id)
	if err := u.call(ctx, "jellyfin", "GET", path, nil, &result); err != nil {
		return err
	}
	if result.Policy == nil {
		return fmt.Errorf("jellyfin: missing user policy")
	}
	for key, value := range map[string]bool{
		"IsAdministrator": false, "IsHidden": true, "IsDisabled": disabled,
		"EnableContentDeletion": false, "EnableContentDownloading": false,
		"EnableAllFolders": u.config.JellyfinLibraryIDs == nil, "EnableRemoteAccess": true, "EnableMediaPlayback": true,
		"EnableLiveTvAccess": u.config.JellyfinLiveTV, "EnableLiveTvManagement": false,
	} {
		result.Policy[key] = value
	}
	result.Policy["EnableContentDeletionFromFolders"] = []string{}
	result.Policy["EnabledFolders"] = append([]string{}, u.config.JellyfinLibraryIDs...)
	return u.call(ctx, "jellyfin", "POST", path+"/Policy", result.Policy, nil)
}
