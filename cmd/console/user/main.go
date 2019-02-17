package main

import (
	"os"
	"time"

	"github.com/linkai-io/frontend/pkg/authz/awsauthz"
	"github.com/linkai-io/frontend/pkg/token/awstoken"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/api/console/user"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
)

var userClient am.UserService
var orgClient am.OrganizationService
var userEnv *user.UserEnv
var env string
var region string

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "User").Logger()
	userEnv = &user.UserEnv{}

	userEnv.Env = os.Getenv("APP_ENV")
	userEnv.Region = os.Getenv("APP_REGION")
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata
	log.Info().Str("env", userEnv.Env).Str("region", userEnv.Region).Msg("userservice api initializing")
	userClient = initializers.UserClient()
	orgClient = initializers.OrgClient()
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)
	tokener := awstoken.New(userEnv.Env, userEnv.Region)
	authenticator := awsauthz.New(userEnv.Env, userEnv.Region, tokener)
	if err := authenticator.Init(nil); err != nil {
		log.Fatal().Err(err).Msg("internal authenticator error")
		return
	}
	userHandlers := user.New(userClient, tokener, authenticator, orgClient, userEnv)

	r.Route("/user", func(r chi.Router) {
		//r.Get("/", GetUser)
		r.Get("/logout", userHandlers.Logout)
		//r.Patch("/details", userHandlers.UpdateUser)
		//r.Patch("/password", userHandlers.ChangePassword)
		r.Post("/feedback", userHandlers.SubmitFeedback)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
