package token

import (
	"context"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/linkai-io/am/am"
)

// IDToken represents the parsed JWT token containing user claims
type IDToken struct {
	OrgName         string   `json:"custom:orgname"`
	FirstName       string   `json:"given_name"`
	LastName        string   `json:"family_name"`
	EventID         string   `json:"event_id"`
	Email           string   `json:"email"`
	CognitoUserName string   `json:"cognito:username"`
	TokenUse        string   `json:"token_use"`
	AuthTime        float64  `json:"auth_time"`
	Roles           []string `json:"cognito:roles"`
	Groups          []string `json:"cognito:groups"`
	jwt.StandardClaims
}

// Tokener for extracting details from a cognito jwt token.
type Tokener interface {
	// UnsafeExtractDetails extracts claims but does not verify signature
	UnsafeExtractDetails(ctx context.Context, idKey string) (*IDToken, error)
	// ValidateToken actually verifies signature on the token as well as verifies claims are proper
	ValidateToken(ctx context.Context, org *am.Organization, idKey string) (*IDToken, error)
}
