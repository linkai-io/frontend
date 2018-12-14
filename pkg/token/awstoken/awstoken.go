package awstoken

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	identity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/linkai-io/am/am"
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

type IDToken struct {
	OrgName         string   `json:"custom:orgname"`
	FirstName       string   `json:"given_name"`
	LastName        string   `json:"family_name"`
	EventID         string   `json:"event_id"`
	Email           string   `json:"email"`
	CognitoUserName string   `json:"cognito:username"`
	TokenUse        string   `json:"token_use"`
	AuthTime        float64  `json:"auth_time"`
	Roles           []string `json:"cognito:roles"`
	Groups          []string `json:"cognito:groups"`
	jwt.StandardClaims
}

type AWSToken struct {
	env    string
	region string
	fedSvc *identity.CognitoIdentity
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

func (t *AWSToken) ParseIDKey(userPoolID, jwkData, idKey string) (*IDToken, error) {
	//https: //cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
	jwk, err := readJWK([]byte(jwkData))
	if err != nil {
		return nil, err
	}

	tok := &IDToken{}
	pubKey, err := jwt.ParseWithClaims(idKey, tok, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		if kid, ok := token.Header["kid"]; ok {
			if kidStr, ok := kid.(string); ok {
				key := jwk[kidStr]
				// 6. Verify the signature of the decoded JWT token.
				rsaPublicKey := convertKey(key.E, key.N)
				return rsaPublicKey, nil
			}
		}
		log.Printf("%#v\n", token)
		return nil, nil
	})

	if err != nil {
		return tok, err
	}
	log.Printf("pubKey: %#v\n", pubKey)
	log.Printf("tok: %#v\n", tok)
	// TODO: Validate claims before returning
	return tok, nil
}

func (t *AWSToken) ExchangeCredentials(ctx context.Context, org *am.Organization, idKey, accessKey string) (string, error) {
	tok, err := t.ParseIDKey(org.UserPoolID, org.UserPoolJWK, idKey)
	if err != nil {
		return "", err
	}

	loginProvider := strings.Replace(tok.Issuer, "https://", "", -1)
	idInput := &identity.GetIdInput{
		IdentityPoolId: aws.String(org.IdentityPoolID),
		Logins:         map[string]string{loginProvider: idKey},
	}

	req := t.fedSvc.GetIdRequest(idInput)
	out, err := req.Send()
	if err != nil {
		log.Printf("error in getID request: %v\n", err)
		return "", err
	}

	credInput := &identity.GetCredentialsForIdentityInput{
		IdentityId: out.IdentityId,
		Logins:     map[string]string{loginProvider: idKey},
	}
	credReq := t.fedSvc.GetCredentialsForIdentityRequest(credInput)
	cred, err := credReq.Send()
	if err != nil {
		log.Printf("error in GetCreds request: %v\n", err)
		return "", err
	}
	log.Printf("cred.Credential: %#v\n", cred.Credentials)
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
		panic(err)
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
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	// fmt.Println(decodedN)
	// fmt.Println(decodedE)
	// fmt.Printf("%#v\n", *pubKey)
	return pubKey
}
