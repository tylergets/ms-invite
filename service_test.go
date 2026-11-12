package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *store {
	t.Helper()
	s, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.close() })
	return s
}

type fakeMedia struct {
	mu                     sync.Mutex
	akCreated, jfCreated   int
	akPassword, jfPassword string
	akActive, jfDisabled   bool
	fail, taken            string
	server                 *httptest.Server
	akNames                map[string]int
	jfNames                map[string]string
	akPasswords            map[string]string
	jfPasswords            map[string]string
	calls                  []string
	jfPolicy               map[string]any
}

func testApp(t *testing.T) (*app, *fakeMedia) {
	t.Helper()
	f := &fakeMedia{
		akNames: map[string]int{}, jfNames: map[string]string{},
		akPasswords: map[string]string{}, jfPasswords: map[string]string{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/auth/") {
			if r.Header.Get("Authorization") != "Bearer ak-key" {
				t.Error("missing Authentik credential")
			}
		} else if r.Header.Get("Authorization") != `MediaBrowser Token="jf-key"` {
			t.Error("missing Jellyfin credential")
		}
		key := r.Method + " " + r.URL.Path
		f.calls = append(f.calls, key)
		if f.fail == key {
			f.fail = ""
			http.Error(w, "upstream failed", 503)
			return
		}
		akID := strings.Split(strings.TrimPrefix(r.URL.Path, "/auth/api/v3/core/users/"), "/")[0]
		jfID := strings.Split(strings.TrimPrefix(r.URL.Path, "/jellyfin/Users/"), "/")[0]
		if strings.HasPrefix(r.URL.Path, "/auth/api/v3/core/users/") && akID != "" {
			key = strings.Replace(key, "/users/"+akID, "/users/42", 1)
		}
		if strings.HasPrefix(r.URL.Path, "/jellyfin/Users/") && jfID != "New" {
			key = strings.Replace(key, "/Users/"+jfID, "/Users/jf-user-id", 1)
		}
		var body map[string]any
		if r.Method != "GET" {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("invalid body: %v", err)
			}
		}
		switch key {
		case "GET /auth/api/v3/core/users/":
			if f.taken == "authentik" || f.akNames[r.URL.Query().Get("username")] != 0 {
				io.WriteString(w, `{"results":[{"username":"alice"}]}`)
			} else {
				io.WriteString(w, `{"results":[]}`)
			}
		case "GET /jellyfin/Users":
			if f.taken == "jellyfin" {
				io.WriteString(w, `[{"Name":"ALICE"}]`)
			} else {
				users := []map[string]string{}
				for name := range f.jfNames {
					users = append(users, map[string]string{"Name": name})
				}
				json.NewEncoder(w).Encode(users)
			}
		case "POST /auth/api/v3/core/users/":
			f.akCreated++
			if body["is_active"] != false || body["username"] == "" {
				t.Error("incorrect Authentik create")
			}
			id := 41 + f.akCreated
			f.akNames[body["username"].(string)] = id
			json.NewEncoder(w).Encode(map[string]int{"pk": id})
		case "PATCH /auth/api/v3/core/users/42/":
			f.akActive = body["is_active"].(bool)
			io.WriteString(w, `{}`)
		case "POST /auth/api/v3/core/users/42/set_password/":
			f.akPassword = body["password"].(string)
			f.akPasswords[akID] = f.akPassword
			w.WriteHeader(204)
		case "POST /jellyfin/Users/New":
			f.jfCreated++
			if len(body["Password"].(string)) < 32 {
				t.Error("missing bootstrap password")
			}
			id := "jf-user-id"
			if f.jfCreated > 1 {
				id = fmt.Sprintf("jf-user-id-%d", f.jfCreated)
			}
			f.jfNames[body["Name"].(string)] = id
			json.NewEncoder(w).Encode(map[string]string{"Id": id})
		case "GET /jellyfin/Users/jf-user-id":
			io.WriteString(w, `{"Policy":{"EnableAudioPlaybackTranscoding":true}}`)
		case "POST /jellyfin/Users/jf-user-id/Policy":
			f.jfPolicy = body
			f.jfDisabled = body["IsDisabled"].(bool)
			if body["IsAdministrator"] != false || body["EnableContentDeletion"] != false || body["EnableAudioPlaybackTranscoding"] != true {
				t.Error("unsafe or lost policy")
			}
			w.WriteHeader(204)
		case "POST /jellyfin/Users/jf-user-id/Password":
			f.jfPassword = body["NewPw"].(string)
			f.jfPasswords[jfID] = f.jfPassword
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected upstream request: %s", key)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.server.Close)
	c := config{SiteName: "Ragtag Club", JellyfinEnabled: true, AuthentikEnabled: true, BaseURL: "https://invite.example.com", AdminToken: strings.Repeat("a", 32),
		JellyfinURL: f.server.URL + "/jellyfin", JellyfinKey: "jf-key", AuthentikURL: f.server.URL + "/auth", AuthentikToken: "ak-key",
		AuthentikPath: "users/media", OIDCAdminGroup: "media-admins"}
	return newApp(c, testStore(t)), f
}

func newInvite(t *testing.T, a *app) string {
	t.Helper()
	_, token, err := a.store.create("Test invite", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signup(a *app, token string) *httptest.ResponseRecorder {
	return signupWithKey(a, token, "test-browser", "alice", "alice@example.com")
}

func signupWithKey(a *app, token, key, username, email string) *httptest.ResponseRecorder {
	form := url.Values{"username": {username}, "email": {email}, "password": {"a good password 123"}, "password_confirm": {"a good password 123"}}
	r := httptest.NewRequest("POST", "/invite/"+token, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", a.config.BaseURL)
	i, _ := a.store.get(token)
	purpose := "signup-" + i.ID
	r.AddCookie(&http.Cookie{Name: a.cookieName(purpose), Value: a.signCookie(purpose, signupSession{Key: key, Expires: time.Now().Add(time.Hour).Unix()})})
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	return w
}

func TestSignupSingleUse(t *testing.T) {
	a, f := testApp(t)
	token := newInvite(t, a)
	w := signup(a, token)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "accounts are ready") {
		t.Fatalf("signup: %d %s", w.Code, w.Body.String())
	}
	if w = signup(a, token); w.Code != 410 {
		t.Fatalf("replayed signup: %d", w.Code)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.akCreated != 1 || f.jfCreated != 1 || f.akPassword != f.jfPassword || !f.akActive || f.jfDisabled {
		t.Fatalf("incorrect final state: %+v", f)
	}
	data, err := os.ReadFile(filepath.Join(a.store.dir, "invites.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) || strings.Contains(string(data), f.akPassword) {
		t.Fatal("capability or password persisted")
	}
}

func TestRetryKnownPartialAccounts(t *testing.T) {
	a, f := testApp(t)
	token := newInvite(t, a)
	f.fail = "POST /jellyfin/Users/jf-user-id/Password"
	if w := signup(a, token); w.Code != 400 {
		t.Fatalf("expected retryable failure, got %d", w.Code)
	}
	i, err := a.store.get(token)
	if err != nil || len(i.Signups) != 1 || i.Signups[0].JellyfinID == "" || i.Signups[0].AuthentikID == 0 || i.Signups[0].Creating != "" {
		t.Fatalf("partial state lost: %+v, %v", i, err)
	}
	// Also exercise a process restart between attempts.
	dir := a.store.dir
	a.store.close()
	a.store, err = openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.store.close() })
	if w := signup(a, token); w.Code != 200 {
		t.Fatalf("retry failed: %s", w.Body.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.akCreated != 1 || f.jfCreated != 1 {
		t.Fatal("retry created duplicate accounts")
	}
}

func TestAmbiguousCreateRequiresAttention(t *testing.T) {
	a, f := testApp(t)
	token := newInvite(t, a)
	f.fail = "POST /jellyfin/Users/New"
	if w := signup(a, token); !strings.Contains(w.Body.String(), "administrator attention") {
		t.Fatal(w.Body.String())
	}
	i, err := a.store.get(token)
	if err != nil || len(i.Signups) != 1 || i.Signups[0].Creating != "jellyfin" {
		t.Fatalf("missing intent: %+v %v", i, err)
	}
	if w := signup(a, token); w.Code != 400 {
		t.Fatal("ambiguous create retried")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.jfCreated != 0 {
		t.Fatal("created after ambiguous failure")
	}
}

func TestExistingAccountsAreNeverAdopted(t *testing.T) {
	for _, system := range []string{"authentik", "jellyfin"} {
		t.Run(system, func(t *testing.T) {
			a, f := testApp(t)
			f.taken = system
			if w := signup(a, newInvite(t, a)); w.Code != 400 || !strings.Contains(w.Body.String(), "already taken") {
				t.Fatal(w.Body.String())
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.akCreated != 0 || f.jfCreated != 0 || f.akPassword != "" || f.jfPassword != "" {
				t.Fatal("existing account modified")
			}
		})
	}
}

func TestStoreExpiryRevocationAndLock(t *testing.T) {
	s := testStore(t)
	if second, err := openStore(s.dir); err == nil {
		second.close()
		t.Fatal("second process acquired ledger")
	}
	_, expired, err := s.create("expired", -time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.get(expired); err == nil {
		t.Fatal("expired invite accepted")
	}
	i, token, err := s.create("revoked", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.revoke(i.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.get(token); err == nil {
		t.Fatal("revoked invite accepted")
	}
}

func TestAdminAuthorizationAndCSRF(t *testing.T) {
	a, _ := testApp(t)
	for _, tc := range []struct {
		name, path, origin, bearer string
		session                    bool
		want                       int
	}{
		{"api unauthenticated", "/api/invites", "", "", false, 401},
		{"api token", "/api/invites", "", a.config.AdminToken, false, 201},
		{"api cross origin", "/api/invites", "https://evil.example", a.config.AdminToken, false, 403},
		{"browser no session", "/admin/invites", a.config.BaseURL, a.config.AdminToken, false, 303},
		{"browser no origin", "/admin/invites", "", "", true, 403},
		{"browser null origin", "/admin/invites", "null", "", true, 403},
		{"browser cross origin", "/admin/invites", "https://evil.example", "", true, 403},
		{"browser authenticated", "/admin/invites", a.config.BaseURL, "", true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"label":"hello","expires_in_hours":24}`
			if tc.session {
				body = "label=hello&expires_in_hours=24"
			}
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(body))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Authorization", "Bearer "+tc.bearer)
			if tc.session {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.AddCookie(&http.Cookie{Name: a.cookieName("session"), Value: a.signCookie("session", adminSession{Subject: "admin", Group: a.config.OIDCAdminGroup, Expires: time.Now().Add(time.Hour).Unix()})})
			}
			w := httptest.NewRecorder()
			a.handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestConcurrentSignupRejected(t *testing.T) {
	a, _ := testApp(t)
	token := newInvite(t, a)
	a.provisionMu.Lock()
	defer a.provisionMu.Unlock()
	if w := signup(a, token); w.Code != 503 {
		t.Fatalf("concurrent signup: %d", w.Code)
	}
}

func TestPasswordValidation(t *testing.T) {
	for _, password := range []string{"short", " padded password ", "password\nwith newline", strings.Repeat("x", 129)} {
		if err := validateSignup("alice", "alice@example.com", password); err == nil {
			t.Fatalf("accepted %q", password)
		}
	}
}

func TestNonExpiringInvitesPersistAndRemainSingleUse(t *testing.T) {
	a, _ := testApp(t)
	i, token, err := a.store.create("No deadline", 0, false)
	if err != nil || i.ExpiresAt != nil || i.expired(time.Now().AddDate(100, 0, 0)) {
		t.Fatalf("non-expiring invite: %+v, %v", i, err)
	}
	dir := a.store.dir
	a.store.close()
	a.store, err = openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.store.close() })
	if restored, err := a.store.get(token); err != nil || restored.ExpiresAt != nil {
		t.Fatalf("non-expiring invite lost on restart: %+v, %v", restored, err)
	}
	if rows := a.store.list(); len(rows) != 1 || rows[0].Status != "open" {
		t.Fatalf("non-expiring invite listed as expired: %+v", rows)
	}
	page := httptest.NewRecorder()
	a.handler().ServeHTTP(page, httptest.NewRequest("GET", "/invite/"+token, nil))
	if page.Code != 200 || !strings.Contains(page.Body.String(), "does not expire") || !strings.Contains(page.Body.String(), "</html>") {
		t.Fatal("non-expiring signup page did not render")
	}
	if w := signup(a, token); w.Code != 200 {
		t.Fatalf("non-expiring signup failed: %d %s", w.Code, w.Body.String())
	}
	if w := signup(a, token); w.Code != 410 {
		t.Fatalf("non-expiring invitation reused: %d", w.Code)
	}
	if err := a.store.revoke(i.ID); err == nil {
		t.Fatal("accepted invitation was revoked")
	}

	i, token, err = a.store.create("Revoke without a deadline", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/admin/invites/"+i.ID+"/revoke", nil)
	r.Header.Set("Origin", a.config.BaseURL)
	r.AddCookie(&http.Cookie{Name: a.cookieName("session"), Value: a.signCookie("session", adminSession{Subject: "admin", Group: a.config.OIDCAdminGroup, Expires: time.Now().Add(time.Hour).Unix()})})
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("browser revoke failed: %d", w.Code)
	}
	if w := signup(a, token); w.Code != 410 {
		t.Fatalf("revoked non-expiring invitation accepted: %d", w.Code)
	}
}

func TestInvitationExpiryInput(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		browser    bool
		want       int
		hours      int
	}{
		{"default", `{}`, false, 201, 168},
		{"never", `{"expires_in_hours":0}`, false, 201, 0},
		{"timed", `{"expires_in_hours":24}`, false, 201, 24},
		{"negative", `{"expires_in_hours":-1}`, false, 400, 0},
		{"too long", `{"expires_in_hours":8761}`, false, 400, 0},
		{"browser never", "expires_in_hours=0", true, 200, 0},
		{"browser malformed", "expires_in_hours=invalid", true, 400, 0},
		{"browser missing", "label=Missing", true, 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := testApp(t)
			path := "/api/invites"
			if tc.browser {
				path = "/admin/invites"
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer "+a.config.AdminToken)
			if tc.browser {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Origin", a.config.BaseURL)
				r.AddCookie(&http.Cookie{Name: a.cookieName("session"), Value: a.signCookie("session", adminSession{Subject: "admin", Group: a.config.OIDCAdminGroup, Expires: time.Now().Add(time.Hour).Unix()})})
			}
			w := httptest.NewRecorder()
			a.handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			rows := a.store.list()
			if tc.want == 400 {
				if len(rows) != 0 {
					t.Fatal("invalid expiry created an invitation")
				}
				return
			}
			if len(rows) != 1 {
				t.Fatalf("expected one invitation, got %d", len(rows))
			}
			if tc.hours == 0 {
				if rows[0].ExpiresAt != nil {
					t.Fatal("never-expiring invitation has an expiry")
				}
			} else if rows[0].ExpiresAt == nil || rows[0].ExpiresAt.Sub(rows[0].CreatedAt) != time.Duration(tc.hours)*time.Hour {
				t.Fatal("incorrect expiry duration")
			}
			if tc.browser && (!strings.Contains(w.Body.String(), "Revoke link") || !strings.Contains(w.Body.String(), "</html>")) {
				t.Fatal("admin page did not render invitation actions")
			}
		})
	}
}

func TestAdminHidesRevokedInvitations(t *testing.T) {
	a, _ := testApp(t)
	if _, _, err := a.store.create("Visible invitation", 0, true); err != nil {
		t.Fatal(err)
	}
	revoked, _, err := a.store.create("Revoked invitation hidden", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.revoke(revoked.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin", "/admin/invites"} {
		method, body := "GET", ""
		if path == "/admin/invites" {
			method, body = "POST", "label=Another+invitation&expires_in_hours=0&reusable=true"
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Origin", a.config.BaseURL)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: a.cookieName("session"), Value: a.signCookie("session", adminSession{Subject: "admin", Group: a.config.OIDCAdminGroup, Expires: time.Now().Add(time.Hour).Unix()})})
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), revoked.Label) || !strings.Contains(w.Body.String(), "Visible invitation") {
			t.Fatalf("incorrect admin list at %s: %s", path, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), ">Ragtag Club</a>") || strings.Contains(w.Body.String(), "<footer") {
			t.Fatal("admin branding is missing or a footer was rendered")
		}
	}
	r := httptest.NewRequest("GET", "/api/invites", nil)
	r.Header.Set("Authorization", "Bearer "+a.config.AdminToken)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), revoked.Label) {
		t.Fatal("revoked history was removed from the API")
	}
}

func TestPublicPagesHaveNoAdminChrome(t *testing.T) {
	a, _ := testApp(t)
	token := newInvite(t, a)
	for _, tc := range []struct {
		path   string
		status int
		text   string
	}{
		{"/", 200, "No invite found"},
		{"/invite/invalid", 410, "No invite found"},
		{"/invite/" + token, 200, "Create your account"},
	} {
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		body := w.Body.String()
		if w.Code != tc.status || !strings.Contains(body, tc.text) || !strings.Contains(body, "</html>") {
			t.Fatalf("unexpected public page at %s: %d %s", tc.path, w.Code, body)
		}
		if strings.Contains(body, "<header") || strings.Contains(body, "<footer") {
			t.Fatalf("public page includes admin chrome: %s", tc.path)
		}
	}
}
