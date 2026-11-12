package main

import (
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestProvisioningServiceSelection(t *testing.T) {
	for _, tc := range []struct {
		name                string
		jellyfin, authentik bool
	}{
		{"jellyfin only", true, false},
		{"authentik only", false, true},
		{"both", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f := testApp(t)
			a.config.JellyfinEnabled = tc.jellyfin
			a.config.AuthentikEnabled = tc.authentik
			a.upstream.config = a.config
			token := reusableInvite(t, a)
			page := httptest.NewRecorder()
			a.handler().ServeHTTP(page, httptest.NewRequest("GET", "/invite/"+token, nil))
			if strings.Contains(page.Body.String(), "Jellyfin") != tc.jellyfin || strings.Contains(page.Body.String(), "Authentik") != tc.authentik {
				t.Fatal("signup page does not match enabled services")
			}
			w := signup(a, token)
			if w.Code != 200 {
				t.Fatalf("signup failed: %s", w.Body.String())
			}
			i, _ := a.store.get(token)
			if (i.Signups[0].JellyfinID != "") != tc.jellyfin || (i.Signups[0].AuthentikID != 0) != tc.authentik || i.Uses() != 1 {
				t.Fatalf("wrong accounts provisioned: %+v", i.Signups)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, call := range f.calls {
				if (!tc.jellyfin && strings.Contains(call, "/jellyfin/")) || (!tc.authentik && strings.Contains(call, "/auth/")) {
					t.Fatalf("disabled service was contacted: %s", call)
				}
			}
			if !tc.authentik && strings.Contains(w.Body.String(), "Authentik") {
				t.Fatal("success page claimed an Authentik account was created")
			}
			if !tc.jellyfin && strings.Contains(w.Body.String(), "Jellyfin") {
				t.Fatal("success page claimed a Jellyfin account was created")
			}
		})
	}
}

func TestJellyfinDefaultAccessPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		libraries []string
		liveTV    bool
	}{
		{"movies and TV only", []string{"movies-id", "shows-id"}, false},
		{"no libraries", []string{}, false},
		{"all libraries and live TV", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f := testApp(t)
			a.config.JellyfinLibraryIDs = tc.libraries
			a.config.JellyfinLiveTV = tc.liveTV
			a.upstream.config = a.config
			if w := signup(a, newInvite(t, a)); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			p := f.jfPolicy
			if p["EnableAllFolders"] != (tc.libraries == nil) || p["EnableLiveTvAccess"] != tc.liveTV || p["EnableLiveTvManagement"] != false {
				t.Fatalf("incorrect access policy: %+v", p)
			}
			want := []any{}
			for _, id := range tc.libraries {
				want = append(want, id)
			}
			if !reflect.DeepEqual(p["EnabledFolders"], want) {
				t.Fatalf("wrong libraries: %+v", p["EnabledFolders"])
			}
		})
	}
}

func TestServiceChangeDoesNotCompletePartialSignup(t *testing.T) {
	a, f := testApp(t)
	token := reusableInvite(t, a)
	f.fail = "POST /jellyfin/Users/New"
	if w := signup(a, token); w.Code != 400 {
		t.Fatal("expected interrupted signup")
	}
	a.config.AuthentikEnabled = false
	a.upstream.config = a.config
	f.mu.Lock()
	calls := len(f.calls)
	f.mu.Unlock()
	if w := signup(a, token); w.Code != 400 || !strings.Contains(w.Body.String(), "available services changed") {
		t.Fatal("service change silently changed an incomplete signup")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != calls {
		t.Fatal("service change contacted upstreams for old signup")
	}
}

func baseConfigEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"BASE_URL": "https://invite.example.com", "ADMIN_TOKEN": strings.Repeat("a", 32),
		"AUTHENTIK_OIDC_ISSUER":    "https://auth.example.com/application/o/invite/",
		"AUTHENTIK_OIDC_CLIENT_ID": "invite", "AUTHENTIK_OIDC_CLIENT_SECRET": "oidc-secret",
		"JELLYFIN_URL": "http://localhost:8096", "JELLYFIN_API_KEY": "jf-key",
		"AUTHENTIK_URL": "http://localhost:9000", "AUTHENTIK_TOKEN": "ak-key",
		"JELLYFIN_ENABLED": "true", "AUTHENTIK_ENABLED": "true",
		"JELLYFIN_ALLOWED_LIBRARY_IDS": "null", "JELLYFIN_ALLOW_LIVE_TV": "false",
		"ADMIN_TOKEN_FILE": "", "AUTHENTIK_OIDC_CLIENT_SECRET_FILE": "",
		"JELLYFIN_API_KEY_FILE": "", "AUTHENTIK_TOKEN_FILE": "",
	} {
		t.Setenv(k, v)
	}
}

func TestDisabledServicesDoNotRequireAPICredentials(t *testing.T) {
	for _, disabled := range []string{"AUTHENTIK", "JELLYFIN"} {
		t.Run(disabled, func(t *testing.T) {
			baseConfigEnv(t)
			t.Setenv(disabled+"_ENABLED", "false")
			t.Setenv(disabled+"_URL", "")
			t.Setenv(disabled+"_TOKEN", "")
			t.Setenv(disabled+"_API_KEY", "")
			if _, err := loadConfig(); err != nil {
				t.Fatal(err)
			}
			t.Setenv("AUTHENTIK_OIDC_CLIENT_SECRET", "")
			if _, err := loadConfig(); err == nil {
				t.Fatal("admin OIDC secret was not required")
			}
		})
	}
}

func TestInvalidProvisioningConfiguration(t *testing.T) {
	for _, values := range []map[string]string{
		{"AUTHENTIK_ENABLED": "false", "JELLYFIN_ENABLED": "false"},
		{"JELLYFIN_ENABLED": "invalid"},
		{"JELLYFIN_ALLOW_LIVE_TV": "invalid"},
		{"JELLYFIN_ALLOWED_LIBRARY_IDS": "movies,shows"},
		{"JELLYFIN_ALLOWED_LIBRARY_IDS": "[\"\"]"},
	} {
		t.Run("invalid", func(t *testing.T) {
			baseConfigEnv(t)
			for k, v := range values {
				t.Setenv(k, v)
			}
			if _, err := loadConfig(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestCrawlerDirectives(t *testing.T) {
	a, _ := testApp(t)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, httptest.NewRequest("GET", "/robots.txt", nil))
	if w.Code != 200 || w.Body.String() != "User-agent: *\nDisallow: /\n" {
		t.Fatal("missing robots.txt")
	}
	w = httptest.NewRecorder()
	a.handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Header().Get("X-Robots-Tag"), "noindex") || !strings.Contains(w.Body.String(), `name="robots" content="noindex, nofollow, noarchive"`) {
		t.Fatal("missing indexing directives")
	}
}
