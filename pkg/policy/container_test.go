package policy_test

import (
	"testing"

	"github.com/linkai-io/frontend/pkg/policy"
)

func TestGetRolePolicy(t *testing.T) {
	p := policy.New("dev", "us-east-1")
	roleMap := map[string]string{"internal_admin": "arn:aws:iam::447064213022:role/hakken-dev-frontend-ConsoleAPIRo-InternalAdminRole-1BZQWQN2BW9N1"}
	if err := p.Init(roleMap); err != nil {
		t.Fatalf("error initializing: %v\n", err)
	}
	out, err := p.GetPolicy("internal_admin")
	if err != nil {
		t.Fatalf("error getting policy from cache: %v\n", err)
	}
	t.Logf("%#v\n", out)
}
