package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/linkai-io/frontend/pkg/authz/awsauthz"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
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

type AuthResponse struct {
	Results map[string]string `json:"results,omitempty"`
	Status  string            `json:"status"`
	Msg     string            `json:"msg,omitempty"`
}

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
	orgClient = organization.New()
	if err := orgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}

	log.Info().Str("load_balancer", lb).Msg("orgClient initialized with lb")
}

func getSystemContext(requestID, ipAddress string) am.UserContext {
	return &am.UserContextData{
		UserID:    systemUserID,
		OrgID:     systemOrgID,
		TraceID:   requestID,
		IPAddress: ipAddress,
	}
}

func returnError(msg string, code int) events.APIGatewayProxyResponse {
	resp := &AuthResponse{Status: "error", Msg: msg, Results: make(map[string]string, 0)}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to returnError due to marshal failure")
		return events.APIGatewayProxyResponse{Body: "{\"status\":\"error\"}", StatusCode: 500}
	}
	return events.APIGatewayProxyResponse{Body: string(data), StatusCode: code}
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	route := request.RequestContext.HTTPMethod + request.Path

	fmt.Printf("route: %v\n", route)
	fmt.Printf("request: %#v\n", request)
	fmt.Printf("request context: %#v\n", request.RequestContext)
	fmt.Printf("request context identity: %#v\n", request.RequestContext.Identity)
	fmt.Println("Received: ", request.Body)
	fmt.Printf("REQUEST: %#v\n", request.PathParameters)

	systemUserContext := getSystemContext(request.RequestContext.RequestID, request.RequestContext.Identity.SourceIP)
	authenticator := awsauthz.New(env, region, orgClient, systemUserContext)
	if err := authenticator.Init(nil); err != nil {
		return returnError("internal authenticator error", 500), nil
	}

	switch route {
	case "POST/auth/login":
		return handleLogin(ctx, authenticator, request)
	case "POST/auth/forgot":
		return handleForgot(ctx, authenticator, request)
	case "POST/auth/forgot_confirm":
		return handleForgotConfirm(ctx, authenticator, request)
	case "POST/auth/logout":
		return returnError("not implemented", 500), nil
	case "POST/auth/changepwd":
		return handleChangePwd(ctx, authenticator, request)
	}

	return returnError("not implemented", 500), nil
}

func handleLogin(ctx context.Context, authenticator authz.Authenticator, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	loginDetails := &authz.LoginDetails{}
	if err := json.Unmarshal([]byte(request.Body), loginDetails); err != nil {
		return returnError("unmarshal failed", 500), nil
	}

	results, err := authenticator.Login(ctx, loginDetails)
	if err != nil {
		return returnError("login failed", 403), nil
	}

	authResponse := &AuthResponse{Status: "ok", Results: results}
	data, err := json.Marshal(authResponse)
	if err != nil {
		return returnError("marshal auth response failed", 500), nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(data),
		StatusCode: 200,
	}, err
}

func handleChangePwd(ctx context.Context, authenticator authz.Authenticator, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	loginDetails := &authz.LoginDetails{}
	if err := json.Unmarshal([]byte(request.Body), loginDetails); err != nil {
		return returnError("unmarshal failed", 500), nil
	}

	results, err := authenticator.SetNewPassword(ctx, loginDetails)
	if err != nil {
		return returnError("login failed", 403), nil
	}

	authResponse := &AuthResponse{Status: "ok", Results: results}
	data, err := json.Marshal(authResponse)
	if err != nil {
		return returnError("marshal auth response failed", 500), err
	}

	return events.APIGatewayProxyResponse{
		Body:       string(data),
		StatusCode: 200,
	}, nil
}

func handleForgot(ctx context.Context, authenticator authz.Authenticator, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	resetDetails := &authz.ResetDetails{}
	if err := json.Unmarshal([]byte(request.Body), resetDetails); err != nil {
		return returnError("unmarshal failed", 500), nil
	}

	err := authenticator.Forgot(ctx, resetDetails)
	if err != nil {
		return returnError("forgot password sequence failed", 400), nil
	}

	authResponse := &AuthResponse{Status: "ok"}
	data, err := json.Marshal(authResponse)
	if err != nil {
		return returnError("marshal auth response failed", 500), nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(data),
		StatusCode: 200,
	}, err
}

func handleForgotConfirm(ctx context.Context, authenticator authz.Authenticator, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	resetDetails := &authz.ResetDetails{}
	if err := json.Unmarshal([]byte(request.Body), resetDetails); err != nil {
		return returnError("unmarshal failed", 500), nil
	}

	if err := authenticator.Reset(ctx, resetDetails); err != nil {
		return returnError("reset failed", 403), nil
	}

	authResponse := &AuthResponse{Status: "ok"}
	data, err := json.Marshal(authResponse)
	if err != nil {
		return returnError("marshal auth response failed", 500), nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(data),
		StatusCode: 200,
	}, nil
}

func main() {
	lambda.Start(Handler)
}
