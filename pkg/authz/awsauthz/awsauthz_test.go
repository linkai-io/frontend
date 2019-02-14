package awsauthz_test

import (
	"context"
	"testing"

	"github.com/linkai-io/frontend/pkg/authz"
	"github.com/linkai-io/frontend/pkg/token/awstoken"

	"github.com/linkai-io/frontend/pkg/authz/awsauthz"
)

func TestRefresh(t *testing.T) {
	accessToken := ""
	refreshToken := ""
	if accessToken == "" {
		t.Skip()
	}
	ctx := context.Background()
	tokener := awstoken.New("dev", "us-east-1")
	auth := awsauthz.New("dev", "us-east-1", tokener)
	if err := auth.Init(nil); err != nil {
		t.Fatalf("error initing awsauth: %v\n", err)
	}
	resp, err := auth.Refresh(ctx, &authz.TokenDetails{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

	if err != nil {
		t.Fatalf("error: %v\n", err)
	}
	t.Logf("%#v\n", resp)
}
