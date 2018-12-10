package provision

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/amtest"
	"github.com/linkai-io/am/mock"
)

func TestOrgProvisionPoolExists(t *testing.T) {
	//userContext := amtest.CreateUserContext(1, 1)
	orgClient := &mock.OrganizationService{}
	orgClient.GetFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		return 0, nil, nil
	}
	provisioner := NewOrgProvisioner("dev", "us-east-1", orgClient)
	poolName := aws.String("org-linkai-" + "support-linkai")
	ret := provisioner.checkUserPoolExists(*poolName, "")
	if ret == true {
		t.Fatal("error should not exist")
	}
}
func TestOrgProvision(t *testing.T) {
	userContext := amtest.CreateUserContext(1, 1)
	orgClient := &mock.OrganizationService{}
	orgClient.GetFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		return 0, nil, nil
	}

	provisioner := NewOrgProvisioner("dev", "us-east-1", orgClient)

	orgData := testOrgData()
	ctx := context.Background()
	roles := make(map[string]string, 0)
	roles["unauthenticated"] = "arn:aws:iam::447064213022:role/hakken-dev-frontend-console-UnAuthIdentityPoolRole-UQ7467HUVFPH"
	roles["authenticated"] = "arn:aws:iam::447064213022:role/hakken-dev-frontend-console-a-AuthIdentityPoolRole-ZAB9D34EOSKY"
	roles["owner"] = "arn:aws:iam::447064213022:role/hakken-dev-frontend-console-api-OwnerOrgRole-424LEW9CGSWI"
	roles["admin"] = "arn:aws:iam::447064213022:role/hakken-dev-frontend-console-api-AdminOrgRole-XMNAWLAMH8PW"
	roles["auditor"] = "arn:aws:iam::447064213022:role/hakken-dev-frontend-console-api-AuditorOrgRole-PEOIQLQK6RJ4"
	roles["editor"] = "arn:aws:iam::447064213022:role/hakken-dev-frontend-console-api-EditorOrgRole-VY3VD72JGNRS"
	roles["reviewer"] = "arn:aws:iam::447064213022:role/hakken-dev-frontend-console-api-ReviewerOrgRole-3OJZH1QT07Y7"

	if err := provisioner.Add(ctx, userContext, orgData, roles); err != nil {
		t.Fatalf("Error provisioning: %v\n", err)
	}
}

func TestDeleteOrg(t *testing.T) {
	orgClient := &mock.OrganizationService{}
	orgClient.GetFn = func(ctx context.Context, userContext am.UserContext, orgName string) (oid int, org *am.Organization, err error) {
		return 0, nil, nil
	}
	orgData := testOrgData()
	provisioner := NewOrgProvisioner("dev", "us-east-1", orgClient)
	err := provisioner.Delete(context.Background(), orgData)
	if err != nil {
		t.Fatalf("failed to delete org: %v\n", err)
	}
}

func testOrgData() *am.Organization {
	return &am.Organization{
		OrgID:                   0,
		OrgCID:                  "",
		OrgName:                 "test-org",
		OwnerEmail:              "isaac.dawson@linkai.io",
		UserPoolID:              "",
		UserPoolAppClientID:     "",
		UserPoolAppClientSecret: "",
		IdentityPoolID:          "",
		FirstName:               "isaac",
		LastName:                "dawson",
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
		SubscriptionID:          am.SubscriptionMonthly,
	}
}
