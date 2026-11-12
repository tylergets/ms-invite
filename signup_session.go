package main

import (
	"net/http"
	"time"
)

// A shared invitation authorizes account creation, not access to another
// recipient's incomplete signup. Each browser gets a separate recovery key.
type signupSession struct {
	Key     string `json:"key"`
	Expires int64  `json:"expires"`
}

func (a *app) signupKey(r *http.Request, i invite) string {
	var session signupSession
	if a.readCookie(r, "signup-"+i.ID, &session) != nil || session.Key == "" || session.Expires <= time.Now().Unix() {
		return ""
	}
	return session.Key
}

func (a *app) newSignupSession(w http.ResponseWriter, i invite) (string, error) {
	key, err := randomToken(32)
	if err != nil {
		return "", err
	}
	const age = 30 * 24 * 60 * 60
	session := signupSession{Key: key, Expires: time.Now().Add(age * time.Second).Unix()}
	purpose := "signup-" + i.ID
	a.setCookie(w, purpose, a.signCookie(purpose, session), age)
	return key, nil
}
