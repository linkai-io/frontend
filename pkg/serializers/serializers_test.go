package serializers_test

import (
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
