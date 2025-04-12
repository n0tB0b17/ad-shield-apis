package auth

import "time"

type AuthConfig struct {
	BaseDN          string
	BindUser        string
	BindPwd         string
	UserFilter      string
	GroupFilter     string
	SessionTTL      time.Duration
	CacheEnabled    bool
	CacheTTL        time.Duration
	UserAttributes  []string
	GroupAttributes []string
}

func NewAuthDefaultConfig(baseDN string) *AuthConfig {
	return &AuthConfig{
		BaseDN:          baseDN,
		BindUser:        "Administrator@adscanner.local",
		BindPwd:         "admin@123",
		UserFilter:      "(&(objectClass=user)(objectCategory=person)(sAMAccountName=%s))",
		GroupFilter:     "(&(objectClass=group)(member=%s))",
		SessionTTL:      1 * time.Hour,
		CacheEnabled:    true,
		CacheTTL:        10 * time.Minute,
		UserAttributes:  []string{"sAMAccountName", "displayName", "mail", "userPrincipalName", "memberOf"},
		GroupAttributes: []string{"cn", "distinguishedName", "description"},
	}
}
