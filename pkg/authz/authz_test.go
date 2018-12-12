package authz_test

import (
	"testing"

	"github.com/linkai-io/frontend/pkg/authz"
	validator "gopkg.in/go-playground/validator.v9"
)

func TestLoginDetailsValidation(t *testing.T) {
	validate := validator.New()

	good := &authz.LoginDetails{
		OrgName:     "someorg",
		Username:    "someuser",
		Password:    "somepass",
		NewPassword: "",
	}

	if err := validate.Struct(good); err != nil {
		t.Fatalf("failed validation: %s\n", err)
	}

	badNewPwd := &authz.LoginDetails{
		OrgName:     "someorg",
		Username:    "someuser",
		Password:    "somepass",
		NewPassword: "ab",
	}

	if err := validate.Struct(badNewPwd); err == nil {
		t.Fatalf("bad new password when provided was not validated\n")
	}
}
