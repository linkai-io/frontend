package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/apex/gateway"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/cookie"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/token"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/linkai-io/frontend/pkg/authz"

	"github.com/rs/zerolog/log"
)

type AuthEnv struct {
	SystemOrgID  int
	SystemUserID int
	Env          string
	Region       string
}

type AuthHandlers struct {
	orgClient     am.OrganizationService
	secureCookie  *cookie.SecureCookie
	authenticator authz.Authenticator
	validate      *validator.Validate
	tokener       token.Tokener
	authEnv       *AuthEnv
}

func New(orgClient am.OrganizationService, authenticator authz.Authenticator, tokener token.Tokener, secureCookie *cookie.SecureCookie, authEnv *AuthEnv) *AuthHandlers {
	return &AuthHandlers{
		orgClient:     orgClient,
		secureCookie:  secureCookie,
		authenticator: authenticator,
		validate:      validator.New(),
		tokener:       tokener,
		authEnv:       authEnv,
	}
}

// getSystemContext extracts the requestid/ip from the request to create a system user context
func (h *AuthHandlers) getSystemContext(r *http.Request) (am.UserContext, error) {
	rc, ok := gateway.RequestContext(r.Context())
	if !ok {
		return nil, errors.New("missing request context")
	}

	return &am.UserContextData{
		UserID:    h.authEnv.SystemUserID,
		OrgID:     h.authEnv.SystemOrgID,
		TraceID:   rc.RequestID,
		IPAddress: rc.Identity.SourceIP,
	}, nil
}

// getOrgData retrieves the organization data needed for awsauth and secure cookie
func (h *AuthHandlers) getOrgByName(ctx context.Context, userContext am.UserContext, orgName string) (*am.Organization, error) {

	_, org, err := h.orgClient.Get(ctx, userContext, orgName)
	if err != nil {
		return nil, err
	}
	return org, nil
}

func (h *AuthHandlers) getOrgFromAccessToken(ctx context.Context, systemContext am.UserContext, accessToken string) (*am.Organization, error) {
	token, err := h.tokener.UnsafeExtractAccess(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	_, org, err := h.orgClient.GetByAppClientID(ctx, systemContext, token.ClientID)
	if err != nil {
		return nil, err
	}
	return org, nil
}

// Refresh user access tokens
func (h *AuthHandlers) Refresh(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	systemContext, err := h.getSystemContext(req)
	if err != nil {
		log.Error().Err(err).Msg("request context retrevial failure")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading refresh data", 500)
		return
	}
	defer req.Body.Close()

	tokenDetails := &authz.TokenDetails{}
	if err := json.Unmarshal(data, tokenDetails); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading refresh data", 500)
		return
	}

	if err := h.validate.Struct(tokenDetails); err != nil {
		middleware.ReturnError(w, "validation failure "+err.Error(), 500)
		return
	}

	orgData, err := h.getOrgFromAccessToken(req.Context(), systemContext, tokenDetails.AccessToken)
	if err != nil {
		log.Error().Err(err).Msg("failed to get organization from access token/clientid")
		middleware.ReturnError(w, "error validating access token details", 500)
		return
	}

	results, err := h.authenticator.Refresh(req.Context(), tokenDetails)
	if err != nil {
		middleware.ReturnError(w, "refresh failed", 403)
		return
	}

	// add subscription id to response
	results["subscription_id"] = fmt.Sprintf("%d", orgData.SubscriptionID)

	respData, err := json.Marshal(results)
	if err != nil {
		middleware.ReturnError(w, "marshal auth response failed", 500)
		return
	}

	// if this happens, someone is up to something bad. like created their own user pool, and attempted to impersonate
	// a different organization.
	if _, err := h.tokener.ValidateAccessToken(req.Context(), orgData, results["access_token"]); err != nil {
		log.Error().Err(err).Msg("WOAH someone tried to refresh token as a different org that didn't match the org details we have in db")
		middleware.ReturnError(w, "NICE TRY BUT YOU DON'T OWN THIS ORG.", 500)
		return
	}

	if err := h.secureCookie.SetAuthCookie(w, results["access_token"], orgData.OrgCID); err != nil {
		middleware.ReturnError(w, "internal cookie failure", 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// Login to the application, returning access/refresh tokens
func (h *AuthHandlers) Login(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	systemContext, err := h.getSystemContext(req)
	if err != nil {
		log.Error().Err(err).Msg("request context retrevial failure")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading login data", 500)
		return
	}
	defer req.Body.Close()

	loginDetails := &authz.LoginDetails{}
	if err := json.Unmarshal(data, loginDetails); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading login data", 500)
		return
	}

	if err := h.validate.Struct(loginDetails); err != nil {
		middleware.ReturnError(w, "validation failure "+err.Error(), 500)
		return
	}

	orgData, err := h.getOrgByName(req.Context(), systemContext, loginDetails.OrgName)
	if err != nil {
		log.Error().Err(err).Msg("failed to get organization from name")
		middleware.ReturnError(w, "login failed", 403)
		return
	}

	results, err := h.authenticator.Login(req.Context(), orgData, loginDetails)
	if err != nil {
		log.Error().Err(err).Msg("login failed")
		if req.Context().Err() != nil {
			middleware.ReturnError(w, "internal server error", 500)
			return
		}
		middleware.ReturnError(w, "login failed", 403)
		return
	}
	// add subscription id to response
	results["subscription_id"] = fmt.Sprintf("%d", orgData.SubscriptionID)

	respData, err := json.Marshal(results)
	if err != nil {
		middleware.ReturnError(w, "marshal auth response failed", 500)
		return
	}

	log.Info().Str("OrgCID", orgData.OrgCID).Msg("setting orgCID in cookie")
	if err := h.secureCookie.SetAuthCookie(w, results["access_token"], orgData.OrgCID, orgData.SubscriptionID); err != nil {
		middleware.ReturnError(w, "internal cookie failure", 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// Forgot password flow sending email to user with verification code
func (h *AuthHandlers) Forgot(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	systemContext, err := h.getSystemContext(req)
	if err != nil {
		log.Error().Err(err).Msg("request context retrevial failure")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading refresh data", 500)
		return
	}
	defer req.Body.Close()

	forgotDetails := &authz.ResetDetails{}
	if err := json.Unmarshal(data, forgotDetails); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading forgot password data", 500)
		return
	}

	if err := h.validate.Struct(forgotDetails); err != nil {
		middleware.ReturnError(w, "validation failure "+err.Error(), 500)
		return
	}

	orgData, err := h.getOrgByName(req.Context(), systemContext, forgotDetails.OrgName)
	if err != nil {
		log.Error().Err(err).Msg("failed to get organization from name")
		middleware.ReturnError(w, "forgot password failed", 403)
		return
	}

	log.Info().Msg("calling authenticator.Forgot")
	if err := h.authenticator.Forgot(req.Context(), orgData, forgotDetails); err != nil {
		log.Error().Err(err).Msg("forgot password failed")
		middleware.ReturnError(w, "forgot password failed", 403)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	respData, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// ForgotConfirm to allow user who successfully retrieved verification code to set a
// new password
func (h *AuthHandlers) ForgotConfirm(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	systemContext, err := h.getSystemContext(req)
	if err != nil {
		log.Error().Err(err).Msg("request context retrevial failure")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading refresh data", 500)
		return
	}
	defer req.Body.Close()

	resetDetails := &authz.ResetDetails{}
	if err := json.Unmarshal(data, resetDetails); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading forgot_confirm data", 500)
		return
	}

	if err := h.validate.Struct(resetDetails); err != nil {
		middleware.ReturnError(w, "validation failure "+err.Error(), 500)
		return
	}

	orgData, err := h.getOrgByName(req.Context(), systemContext, resetDetails.OrgName)
	if err != nil {
		log.Error().Err(err).Msg("failed to get organization from name")
		middleware.ReturnError(w, "forgot password confirm failed", 403)
		return
	}

	if err := h.authenticator.Reset(req.Context(), orgData, resetDetails); err != nil {
		log.Error().Err(err).Msg("forgot password confirm failed")
		middleware.ReturnError(w, "forgot password confirm failed", 403)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	respData, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// ChangePwd allows a user to change their password provided the current password works.
func (h *AuthHandlers) ChangePwd(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	systemContext, err := h.getSystemContext(req)
	if err != nil {
		log.Error().Err(err).Msg("request context retrevial failure")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading changepwd data", 500)
		return
	}
	defer req.Body.Close()

	loginDetails := &authz.LoginDetails{}
	if err := json.Unmarshal(data, loginDetails); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading changepwd data", 500)
		return
	}

	if err := h.validate.Struct(loginDetails); err != nil {
		middleware.ReturnError(w, "validation failure "+err.Error(), 500)
		return
	}

	orgData, err := h.getOrgByName(req.Context(), systemContext, loginDetails.OrgName)
	if err != nil {
		log.Error().Err(err).Msg("failed to get organization from name")
		middleware.ReturnError(w, "forgot password confirm failed", 403)
		return
	}

	if _, err := h.authenticator.SetNewPassword(req.Context(), orgData, loginDetails); err != nil {
		middleware.ReturnError(w, "set new password failed", 403)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	respData, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}
