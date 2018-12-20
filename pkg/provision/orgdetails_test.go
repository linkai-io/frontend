package provision_test

import (
	"testing"

	"github.com/linkai-io/frontend/pkg/provision"
	validator "gopkg.in/go-playground/validator.v9"
)

func TestOrgDetails(t *testing.T) {
	o := &provision.OrgDetails{
		OrgName:         "test",
		OwnerEmail:      "test@owner.io",
		FirstName:       "test",
		LastName:        "owner",
		Phone:           "1-111-111-1111",
		Country:         "USA",
		StatePrefecture: "California",
		Street:          "1 fake lane",
		Address1:        "",
		Address2:        "",
		City:            "beverly hills",
		PostalCode:      "90210",
		StatusID:        1,
		SubscriptionID:  1,
	}
	_, err := o.ToOrganization()
	if err != nil {
		t.Fatalf("failed to convert to org: %v\n", err)
	}

	o.OwnerEmail = ""
	o.FirstName = ""
	o.LastName = ""
	o.StatusID = 9999
	o.SubscriptionID = 9999

	_, err = o.ToOrganization()
	if err == nil {
		t.Fatalf("failed to get validation error with invalid values\n")
	}
	expectedCount := 5
	errorCount := 0

	var owner, first, last, status, sub bool

	for _, err := range err.(validator.ValidationErrors) {
		errorCount++
		if err.StructField() == "OwnerEmail" {
			owner = true
		} else if err.StructField() == "FirstName" {
			first = true
		} else if err.StructField() == "LastName" {
			last = true
		} else if err.StructField() == "StatusID" {
			status = true
		} else if err.StructField() == "SubscriptionID" {
			sub = true
		}
	}

	if errorCount != expectedCount {
		t.Fatalf("expected %d errors got %d\n", expectedCount, errorCount)
	}
	if owner == false || first == false || last == false || status == false || sub == false {
		t.Fatalf("unexpected validation error")
	}
}
