package models

type ReqUserRegistration struct {
	UserName      string `json:"user_name"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Email         string `json:"email"`
	ContactNumber uint64 `json:"contact_number,omitempty"`
	Password      string `json:"password"`
}
