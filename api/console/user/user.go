package user

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/token"
	"github.com/rs/zerolog/log"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/linkai-io/am/am"
)

type UserEnv struct {
	Env    string
	Region string
}

type UserHandlers struct {
	env              *UserEnv
	userClient       am.UserService
	orgClient        am.OrganizationService
	ContextExtractor middleware.UserContextExtractor
	tokener          token.Tokener
	authenticator    authz.Authenticator
}

func New(userClient am.UserService, tokener token.Tokener, authenticator authz.Authenticator, orgClient am.OrganizationService, userEnv *UserEnv) *UserHandlers {
	return &UserHandlers{
		userClient:       userClient,
		orgClient:        orgClient,
		env:              userEnv,
		tokener:          tokener,
		authenticator:    authenticator,
		ContextExtractor: middleware.ExtractUserContext,
	}
}

func (h *UserHandlers) UpdateUser(w http.ResponseWriter, req *http.Request) {
	var data []byte
	var err error

	type userDetails struct {
		FirstName string `json:"first_name" validate:"required,gte=1,lte=256"`
		LastName  string `json:"last_name" validate:"required,gte=1,lte=256"`
		Email     string `json:"email" validate:"required,email"`
	}

	userContext, ok := h.ContextExtractor(req.Context())
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

	_, _, err = h.userClient.Update(req.Context(), userContext, amUser, userContext.GetUserID())
	if err != nil {
		log.Error().Err(err).Msg("failed to update user")
		middleware.ReturnError(w, "error updating user information", 500)
		return
	}
}

func (h *UserHandlers) ChangePassword(w http.ResponseWriter, req *http.Request) {
	var data []byte
	var err error

	userContext, ok := h.ContextExtractor(req.Context())
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

	_, orgData, err := h.orgClient.GetByID(req.Context(), userContext, userContext.GetOrgID())
	if err != nil {
		log.Error().Err(err).Msg("error getting org by id")
		middleware.ReturnError(w, "internal authenticator error", 500)
		return
	}

	tokens, err := h.authenticator.SetNewPassword(req.Context(), orgData, loginDetails)
	if err != nil {
		log.Error().Err(err).Msg("internal authenticator error")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	data, _ = json.Marshal(tokens)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}
