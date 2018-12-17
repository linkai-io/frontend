package main

import (
	"strings"
	"testing"
)

func TestGetRolePolicy(t *testing.T) {
	p := New("dev", "us-east-1")
	out, err := p.GetRolePolicies("hakken-dev-frontend-conso-InternalAdminSupportRole-1CWO3QU6J018A")
	if err != nil {
		t.Fatalf("error gettingg role policy: %v\n", err)
	}

	t.Logf("out: %#v\n", out)
}

func TestPolicyContainerInit(t *testing.T) {
	roles := "hakken-dev-frontend-ConsoleAPIRo-InternalAdminRole-1BZQWQN2BW9N1,hakken-dev-frontend-ConsoleAPIR-InternalReviewRole-EP5IMTJYID7E,hakken-dev-frontend-ConsoleAPIRoles-G-OwnerOrgRole-82CX606LLIIX,hakken-dev-frontend-ConsoleAPIRoles-G-AdminOrgRole-1WGMTORTKCSV7,hakken-dev-frontend-ConsoleAPIRoles-AuditorOrgRole-Z2GIX0UBSF59,hakken-dev-frontend-ConsoleAPIRoles-EditorOrgRole-FEU1SCQ1JT74,hakken-dev-frontend-ConsoleAPIRole-ReviewerOrgRole-1P2HBHSQ4618I"
	p := New("dev", "us-east-1")
	roleArns := strings.Split(roles, ",")
	if err := p.Init(roleArns); err != nil {
		t.Fatalf("error initializing policy container: %v\n", err)
	}
}
