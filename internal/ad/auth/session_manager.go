package auth

import (
	"fmt"
	"sync"
	"time"
)

type SessionManager struct {
	sessions     map[string]*Session
	mu           sync.RWMutex
	defaultTTL   time.Duration
	cleanupTimer *time.Timer
}

func NewSessionManager(defaultTTL time.Duration) *SessionManager {
	manager := &SessionManager{
		sessions:   make(map[string]*Session),
		defaultTTL: defaultTTL,
	}

	manager.startCleanup()
	return manager
}

func (sm *SessionManager) startCleanup() {
	sm.cleanupTimer = time.AfterFunc(5*time.Minute, func() {
		sm.cleanup()
		sm.startCleanup()
	})
}

func (sm *SessionManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	count := 0

	for id, session := range sm.sessions {
		if now.After(session.ExpiresAt) || session.State == SessionStateInvalid {
			delete(sm.sessions, id)
			count++
		}
	}

	if count > 0 {
		fmt.Printf("cleaned up: %d expired \n", count)
	}
}

func (sm *SessionManager) CreateSession(username, dn string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session := NewSession(username, dn, sm.defaultTTL)
	sm.sessions[session.ID] = session

	fmt.Printf("New session created, ID: %s and username: %s \n", session.ID, session.Username)
	return session
}

func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, doesExist := sm.sessions[id]
	if !doesExist {
		return nil, false
	}

	if session.GetState() != SessionStateActive {
		return session, false // session not active
	}
	return session, true
}

func (sm *SessionManager) InvalidSession(id string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, doesExist := sm.sessions[id]
	if !doesExist {
		return false
	}

	session.Invalidate()
	fmt.Printf("session invalidated, for user: %s and session-id: %s \n", session.Username, session.ID)
	return true
}

func (sm *SessionManager) InvalidUserSession(username string) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	count := 0
	for _, session := range sm.sessions {
		if session.Username == username && session.State == SessionStateActive {
			session.Invalidate()
			count++
		}
	}

	if count > 0 {
		fmt.Printf("Session has been invalidated for user: %s \n.", username)
	}

	return count
}

func (sm *SessionManager) GetActiveSession() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0

	for _, session := range sm.sessions {
		if session.GetState() == SessionStateActive {
			count++
		}
	}

	return count
}

func (sm *SessionManager) GetSessionForUser(username string) []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var sessions []*Session
	for _, session := range sm.sessions {
		if session.Username == username && session.GetState() == SessionStateActive {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

func (sm *SessionManager) Close() {
	if sm.cleanupTimer != nil {
		sm.cleanupTimer.Stop()
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, session := range sm.sessions {
		session.Invalidate()
	}

	fmt.Printf("Total of: %d session has been invalidated \n", len(sm.sessions))
}
