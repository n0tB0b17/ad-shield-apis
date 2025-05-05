package connection

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ConnectionState int

const (
	ConnectionStateIdle ConnectionState = iota
	ConnectionStateInUse
	ConnectionStateClosed
)

type ConnectionPool struct {
	config      *ConnConfig
	connections []*PooledConnection
	mu          sync.Mutex
}

func NewConnectionPool(config *ConnConfig) *ConnectionPool {
	return &ConnectionPool{
		config:      config,
		connections: make([]*PooledConnection, 0, config.MaxConnection),
	}
}

func (p *ConnectionPool) Get() (*PooledConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, connection := range p.connections {
		if connection.state == ConnectionStateIdle {
			if time.Since(connection.lastUsed) > p.config.IdleTimeout {
				fmt.Println("connection expired, closing and removing")
				_ = connection.conn.Close()
				connection.state = ConnectionStateClosed
				continue
			}

			connection.state = ConnectionStateInUse
			connection.lastUsed = time.Now()

			fmt.Println("Reusing existing connection from pool")
			return connection, nil
		}
	}

	// todo: check if port is open or closed
	if len(p.connections) < p.config.MaxConnection {
		fmt.Println("creating new connection")
		conn, err := p.createNewConnection()
		if err != nil {
			return nil, err
		}

		p.connections = append(p.connections, conn)
		return conn, nil
	}

	fmt.Println("Connection pool exhausted")
	return nil, fmt.Errorf("connection pool exhausted")
}

func (p *ConnectionPool) Release(conn *PooledConnection) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn.state == ConnectionStateInUse {
		conn.state = ConnectionStateIdle
		conn.lastUsed = time.Now()
		fmt.Printf("Connection name: %s released to pool \n", conn.boundDN)
	}
}

func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, connection := range p.connections {
		if connection.state != ConnectionStateClosed {
			fmt.Println("Closing connection")
			_ = connection.conn.Close()
			connection.state = ConnectionStateClosed
		}
	}

	p.connections = nil
}

func (p *ConnectionPool) createNewConnection() (*PooledConnection, error) {
	var conn *ldap.Conn
	var err error

	for retry := 0; retry <= p.config.MaxRetries; retry++ {
		if retry > 0 {
			fmt.Printf("Retry connection attempt (%d/%d) \n", retry, p.config.MaxRetries)
			time.Sleep(p.config.RetryInterval)
		}

		if p.config.UseSSL {
			fmt.Println("ssl dial implementation incoming...")
		} else {
			conn, err = ldap.DialURL(p.config.ServerAddr)
		}

		if err == nil {
			break
		}

		fmt.Printf("Connection attempt[%d] failed: %v, ", retry, err)
	}

	if err != nil {
		return nil, err
	}

	conn.SetTimeout(p.config.OperationTimeout)

	return &PooledConnection{
		conn:      conn,
		state:     ConnectionStateInUse,
		isBound:   false,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}, nil
}
