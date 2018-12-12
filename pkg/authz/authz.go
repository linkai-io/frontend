package authz

import "context"

const (
	AuthFailed              = "AUTH_FAILED"
	AuthNewPasswordRequired = "NEW_PASSWORD_REQUIRED"
	AuthSuccess             = "AUTH_SUCCESS"
	AuthInvalidRequest      = "INVALID_REQUEST"
	AuthInvalidNewPassword  = "INVALID_NEW_PASSWORD"
)

type LoginDetails struct {
	OrgName     string `json:"org_name" validate:"required,gte=3,lte=128"`
	Username    string `json:"user_name" validate:"required,gte=3,lte=256"`
	Password    string `json:"password,omitempty" validate:"required,gte=8,lte=256"`
	NewPassword string `json:"new_password,omitempty" validate:"omitempty,gte=3,lte=256"`
}

// ResetDetails for when a user must reset their password.
type ResetDetails struct {
	OrgName          string `json:"org_name" validate:"required,gte=3,lte=128"`
	Username         string `json:"user_name" validate:"required,gte=3,lte=256"`
	Password         string `json:"password,omitempty" validate:"omitempty,gte=8,lte=256"`
	VerificationCode string `json:"verification_code,omitempty" validate:"omitempty,gte=3,lte=256"`
}

type UserDetails struct {
	Details map[string]string `json:"details"`
}

// Authenticator authenticates a user
type Authenticator interface {
	Init(config []byte) error
	Login(ctx context.Context, details *LoginDetails) (map[string]string, error)
	SetNewPassword(ctx context.Context, details *LoginDetails) (map[string]string, error)
	//UpdatePassword(ctx context.Context, details *LoginDetails) (map[string]string, error)
	Forgot(ctx context.Context, details *ResetDetails) error
	Reset(ctx context.Context, details *ResetDetails) error
	Logout(ctx context.Context, userDetails *UserDetails) error
}
