package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reusableInvite(t *testing.T, a *app) string {
	t.Helper()
	_, token, err := a.store.create("Shared link", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestReusableInviteIndependentAccountsAndReplay(t *testing.T) {
	a, f := testApp(t)
	token := reusableInvite(t, a)
	for _, name := range []string{"alice", "bob"} {
		if w := signupWithKey(a, token, name+"-browser", name, name+"@example.com"); w.Code != 200 {
			t.Fatalf("%s signup: %d %s", name, w.Code, w.Body.String())
		}
	}
	i, err := a.store.get(token)
	if err != nil || !i.Reusable || i.Status != "open" || i.Uses() != 2 || len(i.Signups) != 2 {
		t.Fatalf("reusable invitation closed or lost history: %+v %v", i, err)
	}
	if i.Signups[0].AuthentikID == i.Signups[1].AuthentikID || i.Signups[0].JellyfinID == i.Signups[1].JellyfinID {
		t.Fatal("recipients share accounts")
	}
	f.mu.Lock()
	f.akPasswords["42"] = "changed after signup"
	f.jfPasswords["jf-user-id"] = "changed after signup"
	f.mu.Unlock()
	for _, key := range []string{"alice-browser", "another-browser"} {
		if w := signupWithKey(a, token, key, "alice", "alice@example.com"); w.Code != 400 {
			t.Fatalf("completed account signup replayed: %d", w.Code)
		}
	}
	f.mu.Lock()
	if f.akCreated != 2 || f.jfCreated != 2 || f.akPasswords["42"] != "changed after signup" || f.jfPasswords["jf-user-id"] != "changed after signup" {
		t.Error("replay modified existing accounts")
	}
	f.mu.Unlock()
	if err := a.store.revoke(i.ID); err != nil {
		t.Fatal(err)
	}
	if w := signupWithKey(a, token, "charlie-browser", "charlie", "charlie@example.com"); w.Code != 410 {
		t.Fatalf("revoked shared link accepted: %d", w.Code)
	}
	if rows := a.store.list(); rows[0].Uses() != 2 || rows[0].Status != "revoked" {
		t.Fatal("revocation lost signup history")
	}
}

func TestReusablePartialSignupIsolationAndRestart(t *testing.T) {
	a, f := testApp(t)
	token := reusableInvite(t, a)
	f.fail = "POST /jellyfin/Users/jf-user-id/Password"
	if w := signup(a, token); w.Code != 400 {
		t.Fatalf("expected partial signup: %d", w.Code)
	}
	// A new browser sees neither the other recipient's form data nor their
	// recovery capability, and cannot take over the partially created user.
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, httptest.NewRequest("GET", "/invite/"+token, nil))
	if strings.Contains(w.Body.String(), "alice@example.com") || strings.Contains(w.Body.String(), `value="alice"`) {
		t.Fatal("shared invitation exposed another recipient's form")
	}
	if w := signupWithKey(a, token, "attacker", "alice", "alice@example.com"); w.Code != 400 {
		t.Fatal("another browser adopted an incomplete account")
	}
	if w := signupWithKey(a, token, "bob-browser", "bob", "bob@example.com"); w.Code != 200 {
		t.Fatalf("partial signup blocked another recipient: %s", w.Body.String())
	}
	dir := a.store.dir
	a.store.close()
	var err error
	a.store, err = openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.store.close() })
	if w := signup(a, token); w.Code != 200 {
		t.Fatalf("original browser could not resume: %s", w.Body.String())
	}
	i, _ := a.store.get(token)
	if i.Uses() != 2 || len(i.Signups) != 2 {
		t.Fatal("restart lost isolated signup history")
	}
	f.mu.Lock()
	if f.akCreated != 2 || f.jfCreated != 2 {
		t.Error("retry created duplicate accounts")
	}
	f.mu.Unlock()
	past := time.Now().Add(-time.Second)
	i.ExpiresAt = &past
	if err := a.store.put(token, i); err != nil {
		t.Fatal(err)
	}
	if w := signupWithKey(a, token, "charlie", "charlie", "charlie@example.com"); w.Code != 410 {
		t.Fatal("expired reusable link accepted")
	}
}

func TestAmbiguousSignupDoesNotBlockSharedLink(t *testing.T) {
	a, f := testApp(t)
	token := reusableInvite(t, a)
	f.fail = "POST /jellyfin/Users/New"
	if w := signup(a, token); w.Code != 400 {
		t.Fatal("expected ambiguous create")
	}
	if w := signupWithKey(a, token, "bob", "bob", "bob@example.com"); w.Code != 200 {
		t.Fatalf("ambiguous create blocked another recipient: %s", w.Body.String())
	}
	i, err := a.store.get(token)
	if err != nil || !i.NeedsAttention() || i.Uses() != 1 || i.Signups[0].Creating != "jellyfin" {
		t.Fatal("ambiguous signup state was lost")
	}
	if w := signup(a, token); w.Code != 400 || !strings.Contains(w.Body.String(), "administrator attention") {
		t.Fatal("ambiguous signup was retried")
	}
}

func TestSignupBrowserSessions(t *testing.T) {
	a, _ := testApp(t)
	token := reusableInvite(t, a)
	i, _ := a.store.get(token)
	keys := []string{}
	for range 2 {
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, httptest.NewRequest("GET", "/invite/"+token, nil))
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure {
			t.Fatal("missing protected signup cookie")
		}
		r := httptest.NewRequest("GET", "/invite/"+token, nil)
		r.AddCookie(cookies[0])
		keys = append(keys, a.signupKey(r, i))
	}
	if keys[0] == "" || keys[0] == keys[1] {
		t.Fatal("visitors share recovery keys")
	}
	r := httptest.NewRequest("POST", "/invite/"+token, strings.NewReader("username=alice"))
	r.Header.Set("Origin", a.config.BaseURL)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: a.cookieName("signup-" + i.ID), Value: "tampered"})
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 400 || len(a.store.list()[0].Signups) != 0 {
		t.Fatal("invalid signup cookie accepted")
	}
}

func TestLegacyInviteMigration(t *testing.T) {
	dir := t.TempDir()
	data := map[string]any{}
	for _, status := range []string{"open", "pending", "used", "revoked"} {
		row := map[string]any{"id": status, "status": status, "created_at": time.Now().UTC(), "expires_at": nil}
		if status != "open" {
			row["username"] = "alice"
			row["email"] = "alice@example.com"
			row["authentik_id"] = 42
			row["jellyfin_id"] = "jf-user-id"
		}
		data[digest(status)] = row
	}
	encoded, _ := json.Marshal(data)
	if err := os.WriteFile(filepath.Join(dir, "invites.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	for _, i := range s.list() {
		if i.Reusable {
			t.Fatal("legacy link silently became reusable")
		}
		if i.Status != "open" && (len(i.Signups) != 1 || i.Signups[0].AuthentikID != 42 || i.Signups[0].JellyfinID != "jf-user-id") {
			t.Fatalf("legacy recovery state lost: %+v", i)
		}
	}
	for _, token := range []string{"used", "revoked"} {
		if _, err := s.get(token); err == nil {
			t.Fatal("migration reopened a closed link")
		}
	}
}

func TestReusableCreationAndBrowserReopen(t *testing.T) {
	a, _ := testApp(t)
	r := httptest.NewRequest("POST", "/api/invites", strings.NewReader(`{"label":"Family","expires_in_hours":0,"reusable":true}`))
	r.Header.Set("Authorization", "Bearer "+a.config.AdminToken)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	var created struct {
		Invite invite `json:"invite"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || w.Code != 201 || !created.Invite.Reusable {
		t.Fatalf("reusable API creation failed: %s", w.Body.String())
	}
	u, _ := url.Parse(created.URL)
	var previousCookie *http.Cookie
	for _, name := range []string{"alice", "bob"} {
		r = httptest.NewRequest("GET", u.Path, nil)
		if previousCookie != nil {
			// Even if a client kept the previous cookie, opening the link again
			// after completion must issue a fresh recovery key.
			r.AddCookie(previousCookie)
		}
		w = httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || (previousCookie != nil && cookies[0].Value == previousCookie.Value) {
			t.Fatal("reopening reusable link did not start a new signup")
		}
		previousCookie = cookies[0]
		form := url.Values{"username": {name}, "email": {name + "@example.com"}, "password": {"a good password 123"}, "password_confirm": {"a good password 123"}}
		r = httptest.NewRequest("POST", u.Path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", a.config.BaseURL)
		r.AddCookie(previousCookie)
		w = httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "accounts are ready") {
			t.Fatalf("browser signup failed: %d %s", w.Code, w.Body.String())
		}
	}
	if a.store.list()[0].Uses() != 2 {
		t.Fatal("reusable browser signups not recorded")
	}
	for _, value := range []string{"true", "invalid"} {
		r = httptest.NewRequest("POST", "/admin/invites", strings.NewReader("label=Browser&expires_in_hours=0&reusable="+value))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", a.config.BaseURL)
		r.AddCookie(&http.Cookie{Name: a.cookieName("session"), Value: a.signCookie("session", adminSession{Subject: "admin", Group: a.config.OIDCAdminGroup, Expires: time.Now().Add(time.Hour).Unix()})})
		w = httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if value == "true" && (w.Code != 200 || !strings.Contains(w.Body.String(), "Reusable") || !strings.Contains(w.Body.String(), "</html>")) {
			t.Fatal("browser could not create reusable invitation")
		}
		if value == "invalid" && w.Code != 400 {
			t.Fatal("invalid usage accepted")
		}
	}
}
