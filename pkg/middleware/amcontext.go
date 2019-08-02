package middleware

import (
	"context"
	"net/http"
	"strconv"

	"github.com/linkai-io/am/am"
	"github.com/rs/zerolog/log"
	"github.com/wirepair/gateway"
)

// UserContextExtractor create the extractor as a type so it's easier to mock/test
type UserContextExtractor func(ctx context.Context) (am.UserContext, bool)

type key int

const userCtxKey = iota

func stringField(key string, properties map[string]interface{}) string {
	str, ok := properties[key].(string)
	if !ok {
		return ""
	}
	return str
}

// ExtractUserContext ...
func ExtractUserContext(ctx context.Context) (am.UserContext, bool) {
	userContext, ok := ctx.Value(userCtxKey).(am.UserContext)
	return userContext, ok
}

func UserCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		var subID int
		var orgStatusID int
		userContext := &am.UserContextData{}

		log.Info().Msg("retrieving user context")
		requestContext, ok := gateway.RequestContext(r.Context())
		if !ok {
			ReturnError(w, "missing request context", 401)
			return
		}

		if requestContext.Authorizer == nil || len(requestContext.Authorizer) == 0 {
			ReturnError(w, "missing authorization context", 401)
			return
		}

		id := stringField("UserID", requestContext.Authorizer)
		if userContext.UserID, err = strconv.Atoi(id); err != nil {
			ReturnError(w, "invalid user id", 401)
			return
		}

		userContext.UserCID = stringField("UserCID", requestContext.Authorizer)
		if userContext.UserCID == "" {
			ReturnError(w, "invalid user cid", 401)
			return
		}

		id = stringField("OrgID", requestContext.Authorizer)
		if userContext.OrgID, err = strconv.Atoi(id); err != nil {
			ReturnError(w, "invalid org id", 401)
			return
		}

		userContext.OrgCID = stringField("OrgCID", requestContext.Authorizer)
		if userContext.OrgCID == "" {
			ReturnError(w, "invalid org cid", 401)
			return
		}

		role := stringField("Group", requestContext.Authorizer)
		if role == "" {
			ReturnError(w, "invalid role", 401)
			return
		}
		userContext.Roles = []string{role}

		subscriptionID := stringField("SubscriptionID", requestContext.Authorizer)
		if subID, err = strconv.Atoi(subscriptionID); err != nil {
			ReturnError(w, "invalid subscription id", 401)
			return
		}
		userContext.SubscriptionID = int32(subID)

		orgStatus := stringField("OrgStatusID", requestContext.Authorizer)
		if orgStatusID, err = strconv.Atoi(orgStatus); err != nil {
			ReturnError(w, "invalid subscription id", 401)
			return
		}
		userContext.OrgStatusID = orgStatusID

		userContext.TraceID = requestContext.RequestID
		userContext.IPAddress = requestContext.Identity.SourceIP
		ctx := context.WithValue(r.Context(), userCtxKey, userContext)
		log.Info().Msgf("user context created, calling next, %#v", userContext)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
