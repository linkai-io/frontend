package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"

	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/linkai-io/frontend/pkg/authz/awsauthz"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	env          string
	region       string
	systemOrgID  int
	systemUserID int

	orgClient         am.OrganizationService
	systemUserContext am.UserContext
)

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "AuthAPI").Logger()
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	log.Info().Str("env", env).Str("region", region).Msg("authapi initializing")

	sec := secrets.NewSecretsCache(env, region)
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	if systemOrgID, err = sec.SystemOrgID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system org id")
	}

	if systemUserID, err = sec.SystemUserID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system user id")
	}

	log.Info().Int("org_id", systemOrgID).Int("user_id", systemUserID).Msg("auth handler configured with system ids")
	orgClient = initializers.OrgClient(lb)
}

func getSystemContext(requestID, ipAddress string) am.UserContext {
	return &am.UserContextData{
		UserID:    systemUserID,
		OrgID:     systemOrgID,
		TraceID:   requestID,
		IPAddress: ipAddress,
	}
}

func getAuthenticator(r *http.Request) (authz.Authenticator, error) {
	requestContext, ok := gateway.RequestContext(r.Context())
	if !ok {
		return nil, errors.New("missing request context")
	}

	systemUserContext := getSystemContext(requestContext.RequestID, requestContext.Identity.SourceIP)
	authenticator := awsauthz.New(env, region, orgClient, systemUserContext)
	if err := authenticator.Init(nil); err != nil {
		return nil, errors.New("internal authenticator error")
	}

	return authenticator, nil
}

// Refresh user access tokens
func Refresh(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	authenticator, err := getAuthenticator(req)
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

	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// Login to the application, returning access/refresh tokens
func Login(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	authenticator, err := getAuthenticator(req)
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
		middleware.ReturnError(w, "login failed", 403)
		return
	}

	respData, err := json.Marshal(results)
	if err != nil {
		middleware.ReturnError(w, "marshal auth response failed", 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// Forgot password flow sending email to user with verification code
func Forgot(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	authenticator, err := getAuthenticator(req)
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
func ForgotConfirm(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	authenticator, err := getAuthenticator(req)
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
func ChangePwd(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	authenticator, err := getAuthenticator(req)
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

	results, err := authenticator.SetNewPassword(req.Context(), loginDetails)
	if err != nil {
		middleware.ReturnError(w, "set new password failed", 403)
		return
	}

	respData, err := json.Marshal(results)
	if err != nil {
		middleware.ReturnError(w, "marshal auth response failed", 500)
		return
	}

	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

func main() {
	r := chi.NewRouter()

	r.Route("/auth", func(r chi.Router) {
		r.Post("/refresh", Refresh)
		r.Post("/login", Login)
		r.Post("/forgot", Forgot)
		r.Post("/forgot_confirm", ForgotConfirm)
		r.Post("/changepwd", ChangePwd)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
