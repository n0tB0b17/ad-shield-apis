package auth

import (
	"sync"
	"time"
)

type SessionState int

const (
	SessionStateActive SessionState = iota
	SessionStateExpired
	SessionStateInvalid
)

type Session struct {
	ID           string
	Username     string
	DN           string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	State        SessionState
	Permissions  []string
	Metadata     map[string]string
	mutex        sync.RWMutex
}

func NewSession(username, dn string, duration time.Duration) *Session {
	now := time.Now()
	return &Session{
		ID:           generateSession(),
		Username:     username,
		DN:           dn,
		CreatedAt:    now,
		ExpiresAt:    now.Add(duration),
		LastActivity: now,
		State:        SessionStateActive,
		Permissions:  []string{},
		Metadata:     make(map[string]string),
	}
}

func generateSession() string {
	return "session-" + time.Now().Format("20060102150405.000")
}

func (s *Session) IsValid() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.State == SessionStateActive && time.Now().Before(s.ExpiresAt)
}

func (s *Session) UpdateActivity() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.LastActivity = time.Now()
}

func (s *Session) Invalidate() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.State = SessionStateInvalid
}

func (s *Session) AddPermission(permission string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, p := range s.Permissions {
		if p == permission {
			return
		}
	}

	s.Permissions = append(s.Permissions, permission)
}

func (s *Session) HasPermission(permission string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, p := range s.Permissions {
		if p == permission {
			return true
		}
	}

	return false
}

func (s *Session) SetMetadata(key, value string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Metadata[key] = value
}

func (s *Session) GetMetadata(key string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	meta, doesExist := s.Metadata[key]
	return meta, doesExist
}

func (s *Session) GetState() SessionState {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if time.Now().After(s.ExpiresAt) {
		return SessionStateExpired
	}

	return s.State
}
func (s *Session) Extend(duration time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.ExpiresAt = time.Now().Add(duration)
}
