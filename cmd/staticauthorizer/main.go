package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/linkai-io/frontend/pkg/token/awstoken"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/linkai-io/frontend/pkg/cookie"
	"github.com/linkai-io/frontend/pkg/token"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	env       string
	region    string
	accountID string // needed for policy creation
	restAPI   string // needed for policy creation

	policyResource string
	secureCookie   *cookie.SecureCookie
	tokener        token.Tokener
	hashKey        string // for cookie signing/encrypting
	blockKey       string // for cookie signing/encrypting
)

func init() {
	var err error
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "StaticAuthorizer").Logger()

	env = os.Getenv("APP_ENV")
	region = os.Getenv("APP_REGION")
	accountID = os.Getenv("APP_ACCOUNTID")
	if accountID == "" {
		log.Fatal().Err(err).Msg("error reading account ID")
	}

	hashKey = os.Getenv("APP_HASHKEY")
	blockKey = os.Getenv("APP_BLOCKKEY")
	if hashKey == "" || blockKey == "" {
		log.Fatal().Err(err).Msg("error reading hash or block keys")
	}
	secureCookie = cookie.New([]byte(hashKey), []byte(blockKey))
	tokener = awstoken.New(env, region)
	// TODO: right now this policy states *all* apis, but restricts to stage (env)... so maybe not a big deal?
	policyResource = fmt.Sprintf("arn:aws:execute-api:%s:%s:*/%s/GET/app/*", region, accountID, env)
}

// Help function to generate an IAM policy
func generatePolicy(orgCID string, accessToken *token.AccessToken) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Info().Str("OrgCID", orgCID).Str("cognito_user_name", accessToken.CognitoUserName).Msg("returning success policy")
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: accessToken.CognitoUserName,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				events.IAMPolicyStatement{
					Effect:   "Allow",
					Action:   []string{"execute-api:Invoke"},
					Resource: []string{policyResource},
				},
				events.IAMPolicyStatement{
					Effect:   "Allow",
					Action:   []string{"s3:GetObject", "s3:ListBucket"},
					Resource: []string{fmt.Sprintf("arn:aws:s3:::%s-linkai-webdata/%s/*", env, orgCID)},
				},
			},
		},
		Context: nil,
	}, nil
}

func returnUnauthorized(msg string) (events.APIGatewayCustomAuthorizerResponse, error) {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: "error",
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{events.IAMPolicyStatement{
				Effect:   "Deny",
				Action:   []string{"*"},
				Resource: []string{"*"},
			},
			},
		},
		Context: map[string]interface{}{"message": msg, "errorMsg": msg},
	}, nil
}

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	header := http.Header{}
	header.Add("Cookie", event.Headers["cookie"])
	request := http.Request{Header: header}

	cookie, err := request.Cookie("linkai_auth")
	if err != nil || cookie.Value == "" {
		log.Error().Err(err).Msg("unable to extract cookie, or value was empty")
		return returnUnauthorized("unable to extract cookie")
	}

	safeCookie, valid, err := secureCookie.GetAuthCookie(cookie)
	if err != nil {
		log.Error().Err(err).Msg("unable to validate cookie")
		return returnUnauthorized("invalid cookie")
	}

	if !valid {
		log.Error().Msg("cookie data was not valid (no data?)")
		return returnUnauthorized("cookie validation failed")
	}

	// NOTE: While we are 'unsafe extracting' keep in mind the following:
	// The cookie has been *encrypted* with private key data.
	// The cookie which encrypted the access token came directly from cognito after authorization succeeded.
	// So while not imperfect, this is definitely safe enough for allowing access to static content.
	// Also, we are only using this to pull out the principal ID.
	accessToken, err := tokener.UnsafeExtractAccess(ctx, safeCookie.Data)
	if err != nil {
		log.Error().Err(err).Msg("unable to extract token data from cookie")
		return returnUnauthorized("bad cookie value")
	}

	if safeCookie.OrgCID == "" {
		log.Error().Err(err).Msg("orgCID was empty")
		return returnUnauthorized("bad cookie value")
	}

	return generatePolicy(safeCookie.OrgCID, accessToken)
}

func main() {
	lambda.Start(handleRequest)
}
