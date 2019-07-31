package provision

import (
	"github.com/linkai-io/am/am"
	validator "gopkg.in/go-playground/validator.v9"
)

// OrgDetails represents the details necessary to provision an organization
// to be converted to an am.Organization after validation.
type OrgDetails struct {
	OrgName         string `json:"org_name" validate:"required,gte=3,lte=128"`
	OwnerEmail      string `json:"owner_email" validate:"required,email"`
	FirstName       string `json:"first_name" validate:"required,gte=1,lte=256"`
	LastName        string `json:"last_name" validate:"required,gte=1,lte=256"`
	Phone           string `json:"phone,omitempty" validate:"omitempty,gte=7,lte=256"`
	Country         string `json:"country" validate:"required,gte=2,lte=3"`
	StatePrefecture string `json:"state_prefecture,omitempty" validate:"omitempty,gte=3,lte=256"`
	Street          string `json:"street,omitempty" validate:"omitempty,gte=3,lte=256"`
	Address1        string `json:"address1,omitempty" validate:"omitempty,gte=3,lte=256"`
	Address2        string `json:"address2,omitempty" validate:"omitempty,gte=3,lte=256"`
	City            string `json:"city,omitempty" validate:"omitempty,gte=3,lte=256"`
	PostalCode      string `json:"postal_code,omitempty" validate:"omitempty,gte=3,lte=24"`
	StatusID        int    `json:"status_id" validate:"required,oneof=1 2 3 100 1000"`
	SubscriptionID  int32  `json:"subscription_id" validate:"required,oneof=1 10 100 101 102 1000"`
}

// ToOrganization converts the details to an am.Organization if it validates successfully.
func (o *OrgDetails) ToOrganization() (*am.Organization, error) {
	validate := validator.New()
	if err := validate.Struct(o); err != nil {
		return nil, err
	}
	limitTLD := int32(1)
	limitHosts := int32(25)
	limitCustomWebFlows := int32(1)
	switch o.SubscriptionID {
	case am.SubscriptionMonthlySmall:
		limitTLD = 1
		limitHosts = 25
		limitCustomWebFlows = 1
	case am.SubscriptionMonthlyMedium:
		limitTLD = 3
		limitHosts = 260
		limitCustomWebFlows = 3
	case am.SubscriptionEnterprise:
		limitTLD = 50
		limitHosts = 10000
		limitCustomWebFlows = 10
	}

	return &am.Organization{
		OrgName:                    o.OrgName,
		OwnerEmail:                 o.OwnerEmail,
		FirstName:                  o.FirstName,
		LastName:                   o.LastName,
		Phone:                      o.Phone,
		Country:                    o.Country,
		StatePrefecture:            o.StatePrefecture,
		Street:                     o.Street,
		Address1:                   o.Address1,
		Address2:                   o.Address2,
		City:                       o.City,
		PostalCode:                 o.PostalCode,
		CreationTime:               0,
		StatusID:                   o.StatusID,
		Deleted:                    false,
		SubscriptionID:             o.SubscriptionID,
		LimitTLD:                   limitTLD,
		LimitTLDReached:            false,
		LimitHosts:                 limitHosts,
		LimitHostsReached:          false,
		LimitCustomWebFlows:        limitCustomWebFlows,
		LimitCustomWebFlowsReached: false,
		PortScanEnabled:            false,
		PaymentRequiredTimestamp:   0,
		BillingPlanType:            "",
		BillingPlanID:              "",
		BillingSubscriptionID:      "",
		IsBetaPlan:                 true,
	}, nil
}
