package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/cookie"

	"github.com/apex/gateway"
	"github.com/linkai-io/frontend/pkg/middleware"

	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/linkai-io/frontend/pkg/authz/awsauthz"

	"github.com/rs/zerolog/log"
)

type AuthEnv struct {
	SystemOrgID  int
	SystemUserID int
	Env          string
	Region       string
}
type AuthHandlers struct {
	orgClient    am.OrganizationService
	secureCookie *cookie.SecureCookie
	authEnv      *AuthEnv
}

func New(orgClient am.OrganizationService, secureCookie *cookie.SecureCookie, authEnv *AuthEnv) *AuthHandlers {
	return &AuthHandlers{
		orgClient:    orgClient,
		secureCookie: secureCookie,
		authEnv:      authEnv,
	}
}

func (h *AuthHandlers) getSystemContext(requestID, ipAddress string) am.UserContext {
	return &am.UserContextData{
		UserID:    h.authEnv.SystemUserID,
		OrgID:     h.authEnv.SystemOrgID,
		TraceID:   requestID,
		IPAddress: ipAddress,
	}
}

func (h *AuthHandlers) getAuthenticator(r *http.Request) (authz.Authenticator, error) {
	requestContext, ok := gateway.RequestContext(r.Context())
	if !ok {
		return nil, errors.New("missing request context")
	}

	systemUserContext := h.getSystemContext(requestContext.RequestID, requestContext.Identity.SourceIP)
	authenticator := awsauthz.New(h.authEnv.Env, h.authEnv.Region, h.orgClient, systemUserContext)
	if err := authenticator.Init(nil); err != nil {
		return nil, errors.New("internal authenticator error")
	}

	return authenticator, nil
}

// Refresh user access tokens
func (h *AuthHandlers) Refresh(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	authenticator, err := h.getAuthenticator(req)
	if err != nil {
		log.Error().Err(err).Msg("authenticator init failure")
		middleware.ReturnError(w, "internal authenticator failure", 500)
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

	results, err := authenticator.Refresh(req.Context(), tokenDetails)
	if err != nil {
		middleware.ReturnError(w, "refresh failed", 403)
		return
	}

	respData, err := json.Marshal(results)
	if err != nil {
		middleware.ReturnError(w, "marshal auth response failed", 500)
		return
	}

	if err := h.secureCookie.SetAuthCookie(w, results["access_token"]); err != nil {
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

	authenticator, err := h.getAuthenticator(req)
	if err != nil {
		log.Error().Err(err).Msg("authenticator init failure")
		middleware.ReturnError(w, "internal authenticator failure", 500)
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

	results, err := authenticator.Login(req.Context(), loginDetails)
	if err != nil {
		log.Error().Err(err).Msg("login failed")
		if req.Context().Err() != nil {
			middleware.ReturnError(w, "internal server error", 500)
			return
		}
		middleware.ReturnError(w, "login failed", 403)
		return
	}

	respData, err := json.Marshal(results)
	if err != nil {
		middleware.ReturnError(w, "marshal auth response failed", 500)
		return
	}

	if err := h.secureCookie.SetAuthCookie(w, results["access_token"]); err != nil {
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

	authenticator, err := h.getAuthenticator(req)
	if err != nil {
		log.Error().Err(err).Msg("authenticator init failure")
		middleware.ReturnError(w, "internal authenticator failure", 500)
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

	log.Info().Msg("calling authenticator.Forgot")
	if err := authenticator.Forgot(req.Context(), forgotDetails); err != nil {
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

	authenticator, err := h.getAuthenticator(req)
	if err != nil {
		log.Error().Err(err).Msg("authenticator init failure")
		middleware.ReturnError(w, "internal authenticator failure", 500)
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

	if err := authenticator.Reset(req.Context(), resetDetails); err != nil {
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

	authenticator, err := h.getAuthenticator(req)
	if err != nil {
		log.Error().Err(err).Msg("authenticator init failure")
		middleware.ReturnError(w, "internal authenticator failure", 500)
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

	if _, err := authenticator.SetNewPassword(req.Context(), loginDetails); err != nil {
		middleware.ReturnError(w, "set new password failed", 403)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	respData, _ := json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}
