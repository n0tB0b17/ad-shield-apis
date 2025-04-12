package connection

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type Manager struct {
	pool         *ConnectionPool
	cfg          *ConnConfig
	statLock     sync.RWMutex
	connStats    map[string]int
	lastPingTime time.Time
	isHealthy    bool
}

func GetConnectionManager(config *ConnConfig) *Manager {
	if err := config.Validate(); err != nil {
		return nil
	}

	pool := NewConnectionPool(config)
	manager := &Manager{
		pool:      pool,
		cfg:       config,
		isHealthy: false,
		connStats: make(map[string]int),
	}

	if err := manager.CheckHealth(); err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return manager
}

func (m *Manager) CheckHealth() error {
	pooledConn, err := m.pool.Get()
	if err != nil {
		m.isHealthy = false
		m.updateStats("health_check_failed", 1)
		return fmt.Errorf("health-check failed while accessing connection from pool, %v", err)
	}

	defer m.pool.Release(pooledConn)

	if err := pooledConn.conn.UnauthenticatedBind(""); err != nil {
		m.isHealthy = false
		m.updateStats("health_check_failed", 1)
		return fmt.Errorf("health-check failed while unauthenticated bind, %v", err)
	}

	m.isHealthy = true
	m.lastPingTime = time.Now()

	m.updateStats("health_check_success", 1)
	return nil
}

func (m *Manager) GetConnection(username, password string) (*PooledConnection, error) {
	pooledConn, err := m.pool.Get()
	if err != nil {
		m.updateStats("pooled_connection_get_failed", 1)
		return nil, fmt.Errorf("unable to access pooled connection: %v", err)
	}

	if err := pooledConn.Bind(username, password); err != nil {
		m.pool.Release(pooledConn)
		m.updateStats("pooled_connection_bind_failed", 1)
		return nil, fmt.Errorf("unable to bind user with connection: %v", err)
	}

	m.updateStats("pooled_connection_bind_success", 1)
	return pooledConn, nil
}

func (m *Manager) ReleaseConnection(conn *PooledConnection) {
	m.pool.Release(conn)
	m.updateStats("pooled_connection_released", 1)
}

func (m *Manager) Close() {
	fmt.Println("Closing pooled connections")
	m.pool.Close()
}

func (m *Manager) IsHealthy() bool {
	return m.isHealthy
}

func (m *Manager) GetStats() map[string]interface{} {
	m.statLock.Lock()
	defer m.statLock.Unlock()

	stats := make(map[string]interface{})
	for k, v := range m.connStats {
		stats[k] = v
	}

	stats["healthy"] = m.isHealthy
	stats["last_ping"] = m.lastPingTime
	return stats
}

func (m *Manager) Search(username, password string, searchReq *ldap.SearchRequest) (*ldap.SearchResult, error) {
	pooledConn, err := m.GetConnection(username, password)
	if err != nil {
		return nil, fmt.Errorf("error while getting connection while making Search request | error: %v", err)
	}

	defer m.ReleaseConnection(pooledConn)

	resp, err := pooledConn.Search(searchReq)
	if err != nil {
		m.updateStats("search_failed", 1)
		return nil, fmt.Errorf("error while executing search request: %v", err)
	}

	m.updateStats("search_success", 1)
	fmt.Printf("search success, total number of entries: %d \n", len(resp.Entries))
	return resp, nil
}

func (m *Manager) Add(username, password string, addReq *ldap.AddRequest) error {
	pooledConn, err := m.GetConnection(username, password)
	if err != nil {
		return fmt.Errorf("error while getting connection while making Add request | error: %v", err)
	}
	defer m.ReleaseConnection(pooledConn)

	if err := pooledConn.Add(addReq); err != nil {
		m.updateStats("add_failed", 1)
		return fmt.Errorf("error while making add request: %v", err)
	}

	m.updateStats("add_success", 1)
	return nil
}

func (m *Manager) Modify(username, password string, modifyReq *ldap.ModifyRequest) error {
	pooledConn, err := m.GetConnection(username, password)
	if err != nil {
		return fmt.Errorf("error while getting connection while making Modify request | error: %v", err)
	}
	defer m.ReleaseConnection(pooledConn)

	if err := pooledConn.Modify(modifyReq); err != nil {
		m.updateStats("modify_failed", 1)
		return fmt.Errorf("error while making modify request: %v", err)
	}

	m.updateStats("modify_success", 1)
	return nil
}
func (m *Manager) Delete(username, password string, deleteReq *ldap.DelRequest) error {
	pooledConn, err := m.GetConnection(username, password)
	if err != nil {
		return fmt.Errorf("error while getting connection while making Delete request | error: %v", err)
	}
	defer m.ReleaseConnection(pooledConn)

	if err := pooledConn.Delete(deleteReq); err != nil {
		m.updateStats("delete_failed", 1)
		return fmt.Errorf("error while making delete request: %v", err)
	}

	m.updateStats("delete_success", 1)
	return nil
}

func (m *Manager) updateStats(stat string, value int) {
	m.statLock.Lock()
	defer m.statLock.Unlock()

	m.connStats[stat] += value
}
