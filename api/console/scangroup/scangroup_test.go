package scangroup_test

import (
	"testing"

	"github.com/linkai-io/frontend/api/console/scangroup"
	validator "gopkg.in/go-playground/validator.v9"
)

func TestNewGroupValidators(t *testing.T) {
	validate := validator.New()
	validate.RegisterValidation("subdomain", scangroup.ValidateSubDomain)

	var er struct {
		groupName  bool
		sub2       bool
		sub3       bool
		sub4       bool
		port2      bool
		port3      bool
		concurrent bool
	}
	newGroup := &scangroup.NewScanGroup{}
	newGroup.GroupName = "test/"
	domains := []string{"ok", "日本", ")@#asdbadf", "bad.bad", "bad,"}
	newGroup.CustomSubNames = domains
	newGroup.ConcurrentRequests = 100
	newGroup.CustomPorts = []int32{1, 65535, 90000, 0}

	err := validate.Struct(newGroup)
	if err == nil {
		t.Fatalf("should have got error on validation")
	}

	for _, v := range err.(validator.ValidationErrors) {
		switch v.Field() {
		case "GroupName":
			er.groupName = true
		case "CustomSubNames[0]", "CustomSubNames[1]":
			t.Fatalf("got error when should not have %s", v.Field())
		case "CustomSubNames[2]":
			er.sub2 = true
		case "CustomSubNames[3]":
			er.sub3 = true
		case "CustomSubNames[4]":
			er.sub4 = true
		case "CustomPorts[0]", "CustomPorts[1]":
			t.Fatalf("got error on ports when should not have")
		case "CustomPorts[2]":
			er.port2 = true
		case "CustomPorts[3]":
			er.port3 = true
		case "ConcurrentRequests":
			er.concurrent = true
		}
		t.Logf("error! %#v", v)
	}
	if !er.groupName || !er.sub2 || !er.sub3 || !er.sub4 || !er.port2 || !er.port3 || !er.concurrent {
		t.Fatalf("%#v\n", er)
	}

	validGroup := &scangroup.NewScanGroup{}
	validGroup.GroupName = "日本"
	validGroup.CustomSubNames = []string{"ok", "日本", "some", "domain"}
	validGroup.ConcurrentRequests = 10
	validGroup.CustomPorts = []int32{80, 443, 8080, 9000, 9200, 8443, 8555}
	if err := validate.Struct(validGroup); err != nil {
		t.Fatalf("should not have got error on validation: %#v\n", err)
	}

}
