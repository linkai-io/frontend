package authz

import "context"

type AuthState int

type LoginDetails struct {
	OrgName  string `json:"org_name"`
	Username string `json:"user_name"`
	Password string `json:"password"`
	Session  string `json:"session,omitempty"`
	UID      string `json:"uid,omitempty"`
}

// ResetDetails for when a user must reset their password.
type ResetDetails struct {
	OrgName          string `json:"org_name"`
	Username         string `json:"user_name"`
	Password         string `json:"password,omitempty"`
	VerificationCode string `json:"verification_code,omitempty"`
}

type UserDetails struct {
	Details map[string]string `json:"details"`
}

// Authenticator authenticates a user
type Authenticator interface {
	Init(config []byte) error
	Login(ctx context.Context, details *LoginDetails) (map[string]string, error)
	ChangePwd(ctx context.Context, details *LoginDetails) error
	Forgot(ctx context.Context, details *ResetDetails) error
	Reset(ctx context.Context, details *ResetDetails) error
	Logout(ctx context.Context, userDetails *UserDetails) error
}
