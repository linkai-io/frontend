package middleware

import "github.com/linkai-io/am/am"

func AccountDisabled(userContext am.UserContext) bool {
	if userContext.GetOrgStatusID() == 1000 || userContext.GetOrgStatusID() == 9999 {
		return false
	}
	return true
}
