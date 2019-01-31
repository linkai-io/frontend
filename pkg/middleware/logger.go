package middleware

import (
	"github.com/linkai-io/am/am"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// UserContextLogger adds context information to the logger
func UserContextLogger(userContext am.UserContext) zerolog.Logger {
	return log.With().
		Str("TraceID", userContext.GetTraceID()).
		Str("IPAddress", userContext.GetIPAddress()).
		Int("OrgID", userContext.GetOrgID()).
		Int("UserID", userContext.GetUserID()).
		Str("OrgCID", userContext.GetOrgCID()).
		Str("UserCID", userContext.GetUserCID()).Logger()
}
