package connection

import (
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type PooledConnection struct {
	conn       *ldap.Conn
	state      ConnectionState
	boundDN    string
	boundCreds string
	lastUsed   time.Time
	createdAt  time.Time
	isBound    bool
}

func (p *PooledConnection) Bind(username, password string) error {
	if p.isBound && p.boundDN == username && p.boundCreds == password {
		fmt.Printf("Connection already bound with username: %s \n", username)
		return nil
	}

	err := p.conn.Bind(username, password)
	if err != nil {
		return fmt.Errorf("error while binding user: %v", err)
	}

	p.isBound = true
	p.boundDN = username
	p.boundCreds = password

	fmt.Printf("Successfully binded user: %s to LDAP server \n", username)
	return nil
}

func (p *PooledConnection) Search(search *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if p.state != ConnectionStateInUse {
		return nil, fmt.Errorf("connection not available")
	}

	if !p.isBound {
		return nil, fmt.Errorf("user not authenticated")
	}

	return p.conn.Search(search)
}

func (p *PooledConnection) Add(add *ldap.AddRequest) error {
	if p.state != ConnectionStateInUse {
		return fmt.Errorf("connection not available")
	}

	if !p.isBound {
		return fmt.Errorf("user not authenticated")
	}

	return p.conn.Add(add)
}

func (p *PooledConnection) Modify(modify *ldap.ModifyRequest) error {
	if p.state != ConnectionStateInUse {
		return fmt.Errorf("connection not available")
	}

	if !p.isBound {
		return fmt.Errorf("user not authenticated")
	}

	return p.conn.Modify(modify)
}

func (p *PooledConnection) Delete(delete *ldap.DelRequest) error {
	if p.state != ConnectionStateInUse {
		return fmt.Errorf("connection not available")
	}

	if !p.isBound {
		return fmt.Errorf("user not authenticated")
	}

	return p.conn.Del(delete)
}

func (p *PooledConnection) IsConnected() bool {
	return p.state != ConnectionStateClosed
}

func (p *PooledConnection) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"state":     p.state,
		"age":       time.Since(p.createdAt).String(),
		"boundDN":   p.boundDN,
		"isBound":   p.isBound,
		"lastUsed":  p.lastUsed,
		"createdAt": p.createdAt,
	}
}
