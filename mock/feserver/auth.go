package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/linkai-io/frontend/pkg/authz"
)

type AuthEnv struct {
	SystemOrgID  int
	SystemUserID int
	Env          string
	Region       string
}

type testAuth struct {
}

func New() *testAuth {
	return &testAuth{}
}

// Refresh user access tokens
func (h *testAuth) Refresh(w http.ResponseWriter, req *http.Request) {

	response := make(map[string]string, 5)

	response["state"] = authz.AuthSuccess
	response["access_token"] = "access"
	//response["id_token"] = *authResult.IdToken
	response["refresh_token"] = "refersh"
	response["expires"] = "3600"
	response["token_type"] = "Bearer"
	respData, _ := json.Marshal(response)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// Login to the application, returning access/refresh tokens
func (h *testAuth) Login(w http.ResponseWriter, req *http.Request) {

	response := make(map[string]string, 5)

	response["state"] = authz.AuthNewPasswordRequired
	response["access_token"] = "access"
	//response["id_token"] = *authResult.IdToken
	response["refresh_token"] = "refersh"
	response["expires"] = "3600"
	response["token_type"] = "Bearer"
	respData, _ := json.Marshal(response)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// Forgot password flow sending email to user with verification code
func (h *testAuth) Forgot(w http.ResponseWriter, req *http.Request) {
	response := make(map[string]string, 5)

	response["state"] = authz.AuthSuccess
	response["access_token"] = "access"
	//response["id_token"] = *authResult.IdToken
	response["refresh_token"] = "refersh"
	response["expires"] = "3600"
	response["token_type"] = "Bearer"
	respData, _ := json.Marshal(response)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// ForgotConfirm to allow user who successfully retrieved verification code to set a
// new password
func (h *testAuth) ForgotConfirm(w http.ResponseWriter, req *http.Request) {
	response := make(map[string]string, 5)

	response["state"] = authz.AuthSuccess
	response["access_token"] = "access"
	//response["id_token"] = *authResult.IdToken
	response["refresh_token"] = "refersh"
	response["expires"] = "3600"
	response["token_type"] = "Bearer"
	respData, _ := json.Marshal(response)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}

// ChangePwd allows a user to change their password provided the current password works.
func (h *testAuth) ChangePwd(w http.ResponseWriter, req *http.Request) {
	response := make(map[string]string, 5)

	response["state"] = authz.AuthSuccess
	response["access_token"] = "access"
	//response["id_token"] = *authResult.IdToken
	response["refresh_token"] = "refersh"
	response["expires"] = "3600"
	response["token_type"] = "Bearer"
	respData, _ := json.Marshal(response)
	w.WriteHeader(200)
	fmt.Fprint(w, string(respData))
}
