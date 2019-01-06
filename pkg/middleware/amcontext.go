package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"

	"github.com/apex/gateway"
	"github.com/linkai-io/am/am"
	"github.com/rs/zerolog/log"
)

type key int

const userCtxKey = iota

func stringField(key string, properties map[string]interface{}) string {
	str, ok := properties[key].(string)
	if !ok {
		return ""
	}
	return str
}

func ExtractUserContext(ctx context.Context) (am.UserContext, bool) {
	userContext, ok := ctx.Value(userCtxKey).(am.UserContext)
	return userContext, ok
}

func UserCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error

		log.Info().Msg("retrieving user context")
		requestDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(requestDump))

		requestContext, ok := gateway.RequestContext(r.Context())
		if !ok {
			ReturnError(w, "missing request context", 401)
		}

		if requestContext.Authorizer == nil || len(requestContext.Authorizer) == 0 {
			ReturnError(w, "missing authorization context", 401)
			return
		}

		userContext := &am.UserContextData{}

		id := stringField("UserID", requestContext.Authorizer)
		if userContext.UserID, err = strconv.Atoi(id); err != nil {
			ReturnError(w, "invalid user id", 401)
			return
		}

		userContext.UserCID = stringField("UserID", requestContext.Authorizer)
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

		userContext.TraceID = requestContext.RequestID
		userContext.IPAddress = requestContext.Identity.SourceIP
		ctx := context.WithValue(r.Context(), userCtxKey, userContext)
		log.Info().Msg("user context created, calling next")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
