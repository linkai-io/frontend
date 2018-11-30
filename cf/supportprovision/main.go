package main

import (
	"context"
	"os"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/clients/organization"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/pkg/cf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var orgClient am.OrganizationService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Provisioner").Logger()

	sec := secrets.NewSecretsCache(os.Getenv("APP_ENV"), os.Getenv("APP_REGION"))
	lb, err := sec.LoadBalancerAddr()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading load balancer data")
	}

	orgClient = organization.New()
	if err := orgClient.Init([]byte(lb)); err != nil {
		log.Fatal().Err(err).Msg("error initializing organization client")
	}
}

func main() {
	cf.StartLambda(&handler{})
}

type resourceProperties struct {
	OrgName      string `json:"OrgName,omitempty"`
	FirstName    string `json:"FirstName,omitempty"`
	LastName     string `json:"LastName,omitempty"`
	SupportEmail string `json:"SupportEmail,omitempty"`
	Password     string `json:"Password,omitempty"`
}

type responseData struct {
	UserPoolID     string `json:"UserPoolId,omitempty"`
	IdentityPoolID string `json:"IdentityPoolId,omitempty"`
}

type handler struct{}

func orgFromInput(props *resourceProperties) *am.Organization {
	return &am.Organization{
		OrgID:                   0,
		OrgCID:                  "",
		OrgName:                 props.OrgName,
		OwnerEmail:              props.SupportEmail,
		UserPoolID:              "",
		UserPoolAppClientID:     "",
		UserPoolAppClientSecret: "",
		IdentityPoolID:          "",
		FirstName:               props.FirstName,
		LastName:                props.LastName,
		Phone:                   "placeholder",
		Country:                 "placeholder",
		StatePrefecture:         "placeholder",
		Street:                  "placeholder",
		Address1:                "placeholder",
		Address2:                "placeholder",
		City:                    "placeholder",
		PostalCode:              "placeholder",
		CreationTime:            0,
		StatusID:                0,
		Deleted:                 false,
		SubscriptionID:          0,
	}
}
func (h *handler) Create(ctx context.Context, req cf.Request) (physicalResourceID string, data interface{}, err error) {
	p := resourceProperties{}
	err = req.ResourceProperties.Unmarshal(&p)
	if err != nil {
		return "", nil, err
	}

	return "", &responseData{}, nil
}

func (h *handler) Update(ctx context.Context, req cf.Request) (data interface{}, err error) {
	_, data, err = h.Create(ctx, req)
	return data, err
}

func (h *handler) Delete(ctx context.Context, req cf.Request) error {
	return nil
}
