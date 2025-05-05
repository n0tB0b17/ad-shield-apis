package utils

type MIDDLEWARE_KEY string

const (
	CLAIMS_KEY MIDDLEWARE_KEY = "auth_claims"
	CLIENT_KEY MIDDLEWARE_KEY = "client_info"
	USER_KEY   MIDDLEWARE_KEY = "user_info"
	ROLE_KEY   MIDDLEWARE_KEY = "role_info"
)
