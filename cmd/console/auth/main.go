package main

import (
	"os"
	"time"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/api/console/auth"
	"github.com/linkai-io/frontend/pkg/cookie"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	authEnv      *auth.AuthEnv
	env          string
	region       string
	systemOrgID  int
	systemUserID int

	secureCookie *cookie.SecureCookie
	hashKey      string // for cookie signing/encrypting
	blockKey     string // for cookie signing/encrypting

	orgClient         am.OrganizationService
	systemUserContext am.UserContext
)

func init() {
	var err error

	zerolog.TimeFieldFormat = ""
	authEnv = &auth.AuthEnv{}
	log.Logger = log.With().Str("lambda", "AuthAPI").Logger()
	hashKey = os.Getenv("APP_HASHKEY")
	blockKey = os.Getenv("APP_BLOCKKEY")
	if hashKey == "" || blockKey == "" {
		log.Fatal().Err(err).Msg("error reading hash or block keys")
	}
	secureCookie = cookie.New([]byte(hashKey), []byte(blockKey))

	authEnv.Env = os.Getenv("APP_ENV")
	authEnv.Region = os.Getenv("APP_REGION")
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")

	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	log.Info().Str("env", authEnv.Env).Str("region", authEnv.Region).Msg("authapi initializing")

	sec := secrets.NewSecretsCache(authEnv.Env, authEnv.Region)
	if authEnv.SystemOrgID, err = sec.SystemOrgID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system org id")
	}

	if authEnv.SystemUserID, err = sec.SystemUserID(); err != nil {
		log.Fatal().Err(err).Msg("error reading system user id")
	}

	log.Info().Int("org_id", authEnv.SystemOrgID).Int("user_id", authEnv.SystemUserID).Msg("auth handler configured with system ids")
	orgClient = initializers.OrgClient()
}

func main() {
	r := chi.NewRouter()
	authHandlers := auth.New(orgClient, secureCookie, authEnv)

	r.Route("/auth", func(r chi.Router) {
		r.Get("/health", middleware.Health)
		r.Post("/refresh", authHandlers.Refresh)
		r.Post("/login", authHandlers.Login)
		r.Post("/forgot", authHandlers.Forgot)
		r.Post("/forgot_confirm", authHandlers.ForgotConfirm)
		r.Post("/changepwd", authHandlers.ChangePwd)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
