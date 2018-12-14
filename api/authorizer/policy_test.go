package main

import (
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
