package user

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

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

// Logout a user from cognito and redirect to login page.
func (h *UserHandlers) Logout(w http.ResponseWriter, req *http.Request) {
	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	_, orgData, err := h.orgClient.GetByID(req.Context(), userContext, userContext.GetOrgID())
	if err != nil {
		w.Header().Set("Set-Cookie", "linkai_auth=")
		w.Header().Set("Location", "/login/")
		middleware.ReturnError(w, "failed to find organization to logout user", 301)
		return
	}

	tok, err := h.tokener.ValidateAccessToken(req.Context(), orgData, req.Header.Get("Authorization"))
	if err != nil {
		w.Header().Set("Set-Cookie", "linkai_auth=")
		w.Header().Set("Location", "/login/")
		middleware.ReturnError(w, "invalid token", 301)
		return
	}

	if err := h.authenticator.Logout(req.Context(), orgData, tok.Subject); err != nil {
		w.Header().Set("Set-Cookie", "linkai_auth=")
		w.Header().Set("Location", "/login/")
		middleware.ReturnError(w, "failed to logout user", 300)
		return
	}

	w.Header().Set("Set-Cookie", "linkai_auth=")
	w.Header().Set("Location", "/login/")
	middleware.ReturnSuccess(w, "OK", 301)
}

func (h *UserHandlers) SubmitFeedback(w http.ResponseWriter, req *http.Request) {
	var data []byte
	var err error

	type feedbackDetails struct {
		Type     string `json:"type" validate:"required,oneof=feedback bug feature"`
		Message  string `json:"message" validate:"required,gte=5"`
		Location string `json:"location" validate:"required"`
		Screen   string `json:"screen" validate:"required"`
	}

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	logger := middleware.UserContextLogger(userContext)

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		logger.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading feedback body", 500)
		return
	}
	defer req.Body.Close()

	feedback := &feedbackDetails{}
	if err := json.Unmarshal(data, feedback); err != nil {
		logger.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading feedback details", 500)
		return
	}

	validate := validator.New()
	if err := validate.Struct(feedback); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	userID := strconv.Itoa(userContext.GetUserID())
	resp, err := http.PostForm("https://docs.google.com/forms/d/e/1FAIpQLSf9yJ-M2Vjc2MywIi0xIO1Nn6yCXc9rT2zTQ7upNnK8OJWZmw/formResponse",
		url.Values{
			"entry.1802046778": {userID},
			"entry.1301026583": {feedback.Type},
			"entry.1849748799": {feedback.Location},
			"entry.2108597312": {feedback.Screen},
			"entry.634199886":  {feedback.Message},
		})
	defer req.Body.Close()
	if resp.StatusCode == 200 {
		middleware.ReturnSuccess(w, "OK", 200)
		return
	}
	logger.Warn().Int("status", resp.StatusCode).Msg("google forms returned error")
	middleware.ReturnError(w, "error from feedback server", 500)
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

type userDetails struct {
	*am.User
	LimitTLDReached   bool `json:"limit_tld_reached"`
	LimitHostsReached bool `json:"limit_hosts_reached"`
	PortScanEnabled   bool `json:"port_scan_enabled"`
}

func (h *UserHandlers) Get(w http.ResponseWriter, req *http.Request) {

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	logger := middleware.UserContextLogger(userContext)

	_, user, err := h.userClient.GetByCID(req.Context(), userContext, userContext.GetUserCID())
	if err != nil {
		logger.Error().Err(err).Msg("failed to get user details")
		middleware.ReturnError(w, "error retreiving user details", 500)
		return
	}

	_, org, err := h.orgClient.GetByCID(req.Context(), userContext, userContext.GetOrgCID())
	if err != nil {
		logger.Error().Err(err).Msg("failed to get org details to check features")
		middleware.ReturnError(w, "error retreiving user details", 500)
	}

	details := &userDetails{User: user, LimitHostsReached: org.LimitHostsReached, LimitTLDReached: org.LimitTLDReached, PortScanEnabled: org.PortScanEnabled}

	data, _ := json.Marshal(details)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func (h *UserHandlers) AcceptAgreement(w http.ResponseWriter, req *http.Request) {
	var data []byte
	var err error

	type acceptDetails struct {
		Accept bool `json:"accept"`
	}

	userContext, ok := h.ContextExtractor(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	logger := middleware.UserContextLogger(userContext)

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading login details", 500)
		return
	}
	defer req.Body.Close()

	details := &acceptDetails{}
	if err := json.Unmarshal(data, details); err != nil {
		middleware.ReturnError(w, "error reading acceptance details", 500)
		return
	}

	logger.Info().Msg("Calling AcceptAgreement...")

	if details.Accept == false {
		logger.Warn().Msg("user did not accept agreement")
		middleware.ReturnError(w, "user did not accept agreement", 401)
		return
	}

	_, _, err = h.userClient.AcceptAgreement(req.Context(), userContext, details.Accept)
	if err != nil {
		logger.Error().Err(err).Msg("failed to accept agreement")
		middleware.ReturnError(w, "error in user acceptance agreement", 500)
		return
	}

	middleware.ReturnSuccess(w, "OK", 200)
}
