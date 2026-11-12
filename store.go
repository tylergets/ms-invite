package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

var errUnavailable = errors.New("invite is expired, revoked, or already used")

type invite struct {
	ID        string          `json:"id"`
	Label     string          `json:"label"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt *time.Time      `json:"expires_at"`
	Status    string          `json:"status"`
	Reusable  bool            `json:"reusable"`
	Signups   []signupAttempt `json:"signups"`
}

type signupAttempt struct {
	Services    []string   `json:"services"`
	ID          string     `json:"id"`
	SessionHash string     `json:"session_hash,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Status      string     `json:"status"`
	Username    string     `json:"username,omitempty"`
	Email       string     `json:"email,omitempty"`
	AuthentikID int        `json:"authentik_id,omitempty"`
	JellyfinID  string     `json:"jellyfin_id,omitempty"`
	Creating    string     `json:"creating,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

func (i invite) Uses() int {
	n := 0
	for _, signup := range i.Signups {
		if signup.Status == "used" {
			n++
		}
	}
	return n
}

func (i invite) NeedsAttention() bool {
	for _, signup := range i.Signups {
		if signup.Creating != "" {
			return true
		}
	}
	return false
}

func (i invite) clone() invite {
	i.Signups = append([]signupAttempt{}, i.Signups...)
	return i
}

// The small invite ledger is replaced atomically and fsynced on every transition.
// Its keys are SHA-256 digests; the original invite capabilities are never stored.
type store struct {
	mu   sync.Mutex
	dir  string
	lock *os.File
	rows map[string]invite
	err  error // Stop mutations after an uncertain disk commit.
}

func (i invite) expired(now time.Time) bool {
	return i.ExpiresAt != nil && !now.Before(*i.ExpiresAt)
}

func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("state directory already in use: %w", err)
	}
	s := &store{dir: dir, lock: f, rows: map[string]invite{}}
	data, err := os.ReadFile(filepath.Join(dir, "invites.json"))
	if err == nil {
		err = json.Unmarshal(data, &s.rows)
		if s.rows == nil && err == nil {
			err = errors.New("invalid invite ledger")
		}
		if err == nil {
			// Older ledgers stored a single signup directly on the invitation.
			// Preserve those links as single-use, including incomplete signups.
			var legacy map[string]signupAttempt
			if err = json.Unmarshal(data, &legacy); err == nil {
				for key, old := range legacy {
					i := s.rows[key]
					if len(i.Signups) == 0 && old.Username != "" {
						if old.Status != "used" {
							old.Status = "pending"
						}
						i.Signups = []signupAttempt{old}
					}
					for n := range i.Signups {
						if len(i.Signups[n].Services) == 0 {
							i.Signups[n].Services = []string{"authentik", "jellyfin"}
						}
					}
					s.rows[key] = i
				}
			}
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *store) close() error { return s.lock.Close() }

func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func digest(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *store) commit(change func(map[string]invite) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	rows := make(map[string]invite, len(s.rows))
	for key, row := range s.rows {
		rows[key] = row.clone()
	}
	if err := change(rows); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	if err = atomicWrite(s.dir, data); err != nil {
		s.err = fmt.Errorf("state commit failed; restart after fixing storage: %w", err)
		return s.err
	}
	s.rows = rows
	return nil
}

func atomicWrite(dir string, data []byte) error {
	f, err := os.CreateTemp(dir, ".invites-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "invites.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *store) create(label string, ttl time.Duration, reusable bool) (invite, string, error) {
	token, err := randomToken(32)
	if err != nil {
		return invite{}, "", err
	}
	id, err := randomToken(12)
	if err != nil {
		return invite{}, "", err
	}
	now := time.Now().UTC()
	i := invite{ID: id, Label: label, CreatedAt: now, Status: "open", Reusable: reusable, Signups: []signupAttempt{}}
	if ttl != 0 {
		expires := now.Add(ttl)
		i.ExpiresAt = &expires
	}
	err = s.commit(func(rows map[string]invite) error { rows[digest(token)] = i; return nil })
	return i, token, err
}

func (s *store) get(token string) (invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return invite{}, s.err
	}
	i, ok := s.rows[digest(token)]
	if !ok || (i.Status != "open" && i.Status != "pending") || i.expired(time.Now()) {
		return invite{}, errUnavailable
	}
	return i.clone(), nil
}

func (s *store) put(token string, i invite) error {
	return s.commit(func(rows map[string]invite) error { rows[digest(token)] = i.clone(); return nil })
}

func (s *store) list() []invite {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]invite, 0, len(s.rows))
	for _, i := range s.rows {
		if (i.Status == "open" || i.Status == "pending") && i.expired(time.Now()) {
			i.Status = "expired"
		}
		rows = append(rows, i.clone())
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].CreatedAt.After(rows[b].CreatedAt) })
	return rows
}

func (s *store) revoke(id string) error {
	return s.commit(func(rows map[string]invite) error {
		for key, i := range rows {
			if i.ID == id {
				i.Status = "revoked"
				rows[key] = i
				return nil
			}
		}
		return errors.New("invite not found")
	})
}
