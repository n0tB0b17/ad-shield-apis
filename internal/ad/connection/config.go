package connection

import (
	"fmt"
	"time"
)

type ConnConfig struct {
	ServerAddr        string
	UseSSL            bool
	ConnectionTimeout time.Duration
	OperationTimeout  time.Duration
	MaxConnection     int
	MaxRetries        int
	IdleTimeout       time.Duration
	RetryInterval     time.Duration
}

func GetConnConfig(addr string) *ConnConfig {
	return &ConnConfig{
		ServerAddr:        addr,
		UseSSL:            false,
		ConnectionTimeout: 10 * time.Second,
		OperationTimeout:  10 * time.Second,
		MaxConnection:     10,
		MaxRetries:        3,
		IdleTimeout:       5 * time.Minute,
		RetryInterval:     time.Second,
	}
}

func (cc *ConnConfig) Validate() error {
	if cc.ServerAddr == "" {
		return fmt.Errorf("invalid ldap server address provided")
	}

	if cc.ConnectionTimeout <= 0 {
		return fmt.Errorf("invalid connection timeout provided")
	}

	if cc.MaxConnection <= 0 {
		return fmt.Errorf("invalid max connection provided")
	}

	return nil
}
