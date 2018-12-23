package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/linkai-io/frontend/pkg/authz/awsauthz"
	"github.com/linkai-io/frontend/pkg/initializers"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/provision"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/linkai-io/am/am"
)

var userClient am.UserService
var orgClient am.OrganizationService
var env string
var region string

func init() {
	var err error

	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "User").Logger()
	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")

	sec := secrets.NewSecretsCache(env, region)
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	userClient = initializers.UserClient(sec)
	orgClient = initializers.OrgClient(sec)
}

func CreateOrg(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte
	orgDetails := &provision.OrgDetails{}

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}
	defer req.Body.Close()

	if err := json.Unmarshal(data, orgDetails); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}

	org, err := orgDetails.ToOrganization()
	if err != nil {
		log.Error().Err(err).Msg("validation failed for provision data")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func UpdateUser(w http.ResponseWriter, req *http.Request) {
	var data []byte
	var err error

	type userDetails struct {
		FirstName string `json:"first_name" validate:"required,gte=1,lte=256"`
		LastName  string `json:"last_name" validate:"required,gte=1,lte=256"`
		Email     string `json:"email" validate:"required,email`
	}

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading login details", 500)
		return
	}
	defer req.Body.Close()

	user := &userDetails{}
	if err := json.Unmarshal(data, user); err != nil {
		middleware.ReturnError(w, "error reading user details", 500)
		return
	}

	validate := validator.New()
	if err := validate.Struct(user); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	amUser := &am.User{
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UserEmail: user.Email,
	}
	
	_, _, err = userClient.Update(req.Context(), userContext, amUser, userContext.GetUserID())
	if err != nil {
		log.Error().Err(err).Msg("failed to update user")
		middleware.ReturnError(w, "error updating user information", 500)
		return
	}
}

func ChangePassword(w http.ResponseWriter, req *http.Request) {
	var data []byte
	var err error

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading login details", 500)
		return
	}
	defer req.Body.Close()

	loginDetails := &authz.LoginDetails{}
	if err := json.Unmarshal(data, loginDetails); err != nil {
		middleware.ReturnError(w, "error reading login details", 500)
		return
	}

	authenticator := awsauthz.New(env, region, orgClient, userContext)
	if err := authenticator.Init(nil); err != nil {
		log.Error().Err(err).Msg("internal authenticator error")
		middleware.ReturnError(w, "internal authenticator error", 500)
		return
	}

	tokens, err := authenticator.SetNewPassword(req.Context(), loginDetails)
	if err != nil {
		log.Error().Err(err).Msg("internal authenticator error")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	data, _ = json.Marshal(tokens)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)

	r.Route("/user", func(r chi.Router) {
		r.Get("/", GetUser)
		r.Patch("/details", UpdateUser)
		r.Patch("/password", ChangePassword)

	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
