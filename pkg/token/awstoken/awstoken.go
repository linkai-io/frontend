package awstoken

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	identity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/token"
	"github.com/rs/zerolog/log"
)

// JWK is json data struct for JSON Web Key
type JWK struct {
	Keys []JWKKey
}

// JWKKey is json data struct for cognito jwk key
type JWKKey struct {
	Alg string
	E   string
	Kid string
	Kty string
	N   string
	Use string
}

type AWSToken struct {
	env    string
	region string
	fedSvc *identity.Client
}

func New(env, region string) *AWSToken {
	t := &AWSToken{}
	t.env = env
	t.region = region
	cfg, _ := external.LoadDefaultAWSConfig()
	cfg.Region = t.region

	t.fedSvc = identity.New(cfg)
	return t
}

func (t *AWSToken) UnsafeExtractID(ctx context.Context, idKey string) (*token.IDToken, error) {
	p := &jwt.Parser{}
	tok := &token.IDToken{}
	_, _, err := p.ParseUnverified(idKey, tok)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func (t *AWSToken) UnsafeExtractAccess(ctx context.Context, accessKey string) (*token.AccessToken, error) {
	p := &jwt.Parser{}
	tok := &token.AccessToken{}
	_, _, err := p.ParseUnverified(accessKey, tok)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// ValidateAccessToken verifies the signature from the user pool is valid (not expired, properly signed) then verifies individual
// claims inside the parsed token.
func (t *AWSToken) ValidateAccessToken(ctx context.Context, org *am.Organization, accessKey string) (*token.AccessToken, error) {
	jwk, err := readJWK([]byte(org.UserPoolJWK))
	if err != nil {
		return nil, err
	}

	tok := &token.AccessToken{}

	_, err = jwt.ParseWithClaims(accessKey, tok, func(jwToken *jwt.Token) (interface{}, error) {
		if _, ok := jwToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", jwToken.Header["alg"])
		}

		if kid, ok := jwToken.Header["kid"]; ok {
			if kidStr, ok := kid.(string); ok {
				key := jwk[kidStr]
				// 6. Verify the signature of the decoded JWT token.
				rsaPublicKey := convertKey(key.E, key.N)
				return rsaPublicKey, nil
			}
		}
		return nil, nil
	})

	if err != nil {
		return tok, err
	}

	// careful here, ParseWithClaims ignores standard claims if they don't exist (which seems crazy)
	// so validate they are actually set.
	log.Info().Msgf("%#v\n", tok)
	if tok.TokenUse != "access" {
		return nil, errors.New("wrong key type")
	}

	if tok.ExpiresAt == 0 {
		return nil, errors.New("exp empty or missing")
	}

	if tok.IssuedAt == 0 {
		return nil, errors.New("iat empty or missing")
	}
	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", t.region, org.UserPoolID)
	log.Info().Str("issuer", issuer).Str("tok_issuer", tok.Issuer).Msg("comparing issuer with tok.Issuer")
	if tok.Issuer != issuer {
		return nil, errors.New("invalid token issuer detected")
	}

	if tok.CognitoUserName == "" {
		return nil, errors.New("username not set")
	}

	if tok.Groups == nil || len(tok.Groups) == 0 {
		return nil, errors.New("groups not set")
	}

	if tok.ClientID != org.UserPoolAppClientID {
		return nil, errors.New("wrong client id set")
	}

	return tok, nil
}

// ValidateIDToken verifies the signature from the user pool is valid (not expired, properly signed) then verifies individual
// claims inside the parsed token.
func (t *AWSToken) ValidateIDToken(ctx context.Context, org *am.Organization, idKey string) (*token.IDToken, error) {
	jwk, err := readJWK([]byte(org.UserPoolJWK))
	if err != nil {
		return nil, err
	}

	tok := &token.IDToken{}

	_, err = jwt.ParseWithClaims(idKey, tok, func(jwToken *jwt.Token) (interface{}, error) {
		if _, ok := jwToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", jwToken.Header["alg"])
		}

		if kid, ok := jwToken.Header["kid"]; ok {
			if kidStr, ok := kid.(string); ok {
				key := jwk[kidStr]
				// 6. Verify the signature of the decoded JWT token.
				rsaPublicKey := convertKey(key.E, key.N)
				return rsaPublicKey, nil
			}
		}
		return nil, nil
	})

	if err != nil {
		return tok, err
	}

	// careful here, ParseWithClaims ignores standard claims if they don't exist (which seems crazy)
	// so validate they are actually set.
	log.Info().Msgf("%#v\n", tok)
	if tok.Audience == "" {
		return nil, errors.New("aud missing")
	}
	if tok.TokenUse != "id" {
		return nil, errors.New("wrong token type")
	}

	if tok.ExpiresAt == 0 {
		return nil, errors.New("exp empty or missing")
	}

	if tok.IssuedAt == 0 {
		return nil, errors.New("iat empty or missing")
	}

	if tok.Issuer != fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", t.region, org.UserPoolID) {
		return nil, errors.New("invalid token issuer detected")
	}
	return tok, nil
}

func (t *AWSToken) ExchangeCredentials(ctx context.Context, org *am.Organization, idKey, accessKey string) (string, error) {
	tok, err := t.ValidateIDToken(ctx, org, idKey)
	if err != nil {
		return "", err
	}

	loginProvider := strings.Replace(tok.Issuer, "https://", "", -1)
	idInput := &identity.GetIdInput{
		IdentityPoolId: aws.String(org.IdentityPoolID),
		Logins:         map[string]string{loginProvider: idKey},
	}

	req := t.fedSvc.GetIdRequest(idInput)
	out, err := req.Send(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error in Cognito GetID")
		return "", err
	}

	credInput := &identity.GetCredentialsForIdentityInput{
		IdentityId: out.IdentityId,
		Logins:     map[string]string{loginProvider: idKey},
	}
	credReq := t.fedSvc.GetCredentialsForIdentityRequest(credInput)
	cred, err := credReq.Send(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error in Cognito GetCreds")
		return "", err
	}

	return *cred.Credentials.SessionToken, nil
}

func readJWK(jwkData []byte) (map[string]JWKKey, error) {
	jwk := &JWK{}
	if err := json.Unmarshal(jwkData, jwk); err != nil {
		return nil, err
	}

	jwkMap := make(map[string]JWKKey, 0)
	for _, jwk := range jwk.Keys {
		jwkMap[jwk.Kid] = jwk
	}
	return jwkMap, nil
}

// https://gist.github.com/MathieuMailhos/361f24316d2de29e8d41e808e0071b13
func convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		return nil
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		return nil
	}

	pubKey.N.SetBytes(decodedN)
	return pubKey
}
