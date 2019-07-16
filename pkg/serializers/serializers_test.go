package serializers_test

import (
	"encoding/json"
	"testing"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/serializers"
)

func TestUserForUsers(t *testing.T) {
	user := &am.User{
		OrgID:        100,
		OrgCID:       "asdf",
		UserCID:      "asdf",
		UserID:       100,
		UserEmail:    "test@test.com",
		FirstName:    "first",
		LastName:     "last",
		StatusID:     1000,
		CreationTime: 0,
		Deleted:      false,
	}
	data, err := serializers.UserForUsers(user)
	if err != nil {
		t.Fatalf("error serializing")
	}
	t.Logf("%s\n", string(data))
	returned, err := serializers.DeserializeUserForUsers(data)
	if err != nil {
		t.Fatalf("error deserializing: %v\n", err)
	}
	t.Logf("%v\n", returned)
}

func TestScanGroupForUsers(t *testing.T) {
	group := am.ScanGroup{
		OrgID:              10,
		GroupID:            10,
		GroupName:          "test",
		CreationTime:       0,
		CreatedByID:        0,
		ModifiedByID:       0,
		ModifiedTime:       0,
		OriginalInputS3URL: "s3://some/thing",
		ModuleConfigurations: &am.ModuleConfiguration{
			NSModule: &am.NSModuleConfig{
				RequestsPerSecond: 0,
			},
			BruteModule: &am.BruteModuleConfig{
				CustomSubNames:    []string{"some", "domain"},
				RequestsPerSecond: 0,
				MaxDepth:          0,
			},
			PortModule: &am.PortScanModuleConfig{
				RequestsPerSecond: 0,
				CustomWebPorts:    []int32{80, 443},
			},
			WebModule: &am.WebModuleConfig{
				TakeScreenShots:       false,
				RequestsPerSecond:     0,
				MaxLinks:              0,
				ExtractJS:             false,
				FingerprintFrameworks: false,
			},
			KeywordModule: &am.KeywordModuleConfig{
				Keywords: nil,
			},
		},
		Paused:  false,
		Deleted: false,
	}

	data, err := serializers.ScanGroupForUsers(&group)
	if err != nil {
		t.Fatalf("error marshaling scan group: %v\n", err)
	}

	returned := &am.ScanGroup{}
	if err := json.Unmarshal(data, returned); err != nil {
		t.Fatalf("error unmarshaling group: %v\n", err)
	}

	if returned.OrgID != 0 {
		t.Fatalf("org id was retained")
	}

	if returned.OriginalInputS3URL != "" {
		t.Fatalf("s3 url was retained")
	}
	if returned.GroupName != "test" {
		t.Fatalf("group name was not retained")
	}
	if returned.GroupID != 10 {
		t.Fatalf("group id was not retained")
	}
}

func TestCustomMarshal(t *testing.T) {
	group1 := testGroup("somegroup1")
	group2 := testGroup("somegroup2")
	groups := make([]*serializers.ScanGroupForUser, 2)
	groups[0] = &serializers.ScanGroupForUser{group1}
	groups[1] = &serializers.ScanGroupForUser{group2}

	data, err := json.Marshal(groups)
	if err != nil {
		t.Fatalf("error marshaling groups foruser: %v\n", err)
	}

	var returned []am.ScanGroup
	if err := json.Unmarshal(data, &returned); err != nil {
		t.Fatalf("error unmarshaling group: %v\n", err)
	}
	t.Logf("%s\n", string(data))
	for _, v := range returned {
		if v.CreatedByID != 0 {
			t.Fatalf("failed to mask ids after unmarshal\n")
		}
	}
}

func testGroup(name string) *am.ScanGroup {
	return &am.ScanGroup{
		OrgID:              10,
		GroupID:            10,
		GroupName:          name,
		CreationTime:       0,
		CreatedBy:          "someuser@email.com",
		CreatedByID:        10,
		ModifiedBy:         "someuser@email.com",
		ModifiedByID:       10,
		ModifiedTime:       0,
		OriginalInputS3URL: "s3://some/thing",
		ModuleConfigurations: &am.ModuleConfiguration{
			NSModule: &am.NSModuleConfig{
				RequestsPerSecond: 0,
			},
			BruteModule: &am.BruteModuleConfig{
				CustomSubNames:    []string{"some", "domain"},
				RequestsPerSecond: 0,
				MaxDepth:          0,
			},
			PortModule: &am.PortScanModuleConfig{
				RequestsPerSecond: 0,
				CustomWebPorts:    []int32{80, 443},
			},
			WebModule: &am.WebModuleConfig{
				TakeScreenShots:       false,
				RequestsPerSecond:     0,
				MaxLinks:              0,
				ExtractJS:             false,
				FingerprintFrameworks: false,
			},
			KeywordModule: &am.KeywordModuleConfig{
				Keywords: nil,
			},
		},
		Paused:  false,
		Deleted: false,
	}
}
