package serializers

import (
	"encoding/json"

	"github.com/linkai-io/am/am"
)

type ScanGroupForUser struct {
	*am.ScanGroup
}

func (s *ScanGroupForUser) MarshalJSON() ([]byte, error) {
	type Alias ScanGroupForUser
	return json.Marshal(&struct {
		OrgID              int    `json:"org_id,omitempty"`
		CreatedByID        int    `json:"created_by_id,omitempty"`
		ModifiedByID       int    `json:"modified_by_id,omitempty"`
		OriginalInputS3URL string `json:"original_input_s3_url,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

func ScanGroupForUsers(group *am.ScanGroup) ([]byte, error) {
	type Alias am.ScanGroup
	return json.Marshal(&struct {
		OrgID              int    `json:"org_id,omitempty"`
		CreatedByID        int    `json:"created_by_id,omitempty"`
		ModifiedByID       int    `json:"modified_by_id,omitempty"`
		OriginalInputS3URL string `json:"original_input_s3_url,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(group),
	})
}

func UserForUsers(user *am.User) ([]byte, error) {
	type Alias am.User
	return json.Marshal(&struct {
		OrgID        int    `json:"org_id,omitempty"`
		OrgCID       string `json:"org_customer_id,omitempty"`
		UserCID      string `json:"user_customer_id,omitempty"`
		UserID       int    `json:"user_id,omitempty"`
		StatusID     int    `json:"status_id,omitempty"`
		CreationTime int64  `json:"creation_time,omitempty"`
		Deleted      bool   `json:"deleted,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(user),
	})
}

func DeserializeUserForUsers(data []byte) (*am.User, error) {
	user := &am.User{}
	/*
		type Alias am.User
		safeUser := &struct {
			OrgID        int    `json:"org_id,omitempty"`
			OrgCID       string `json:"org_customer_id,omitempty"`
			UserCID      string `json:"user_customer_id,omitempty"`
			UserID       int    `json:"user_id,omitempty"`
			StatusID     int    `json:"status_id,omitempty"`
			CreationTime int64  `json:"creation_time,omitempty"`
			Deleted      bool   `json:"deleted,omitempty"`
			*Alias
		}{
			Alias: (*Alias)(user),
		}*/
	err := json.Unmarshal(data, &user)
	return user, err
}

func OrgForUsers(org *am.Organization) ([]byte, error) {
	type Alias am.Organization
	return json.Marshal(&struct {
		OrgID                   int    `json:"org_id,omitempty"`
		UserPoolID              string `json:"user_pool_id,omitempty"`
		UserPoolAppClientID     string `json:"user_pool_app_client_id,omitempty"`
		UserPoolAppClientSecret string `json:"user_pool_app_client_secret,omitempty"`
		IdentityPoolID          string `json:"identity_pool_id,omitempty"`
		UserPoolJWK             string `json:"user_pool_jwk,omitempty"`
		Deleted                 bool   `json:"deleted,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(org),
	})
}
