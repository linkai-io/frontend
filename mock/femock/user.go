package femock

import (
	"context"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/mock"
)

func MockUserClient() am.UserService {
	userClient := &mock.UserService{}
	user := &am.User{
		UserEmail:                  "test@test.com",
		FirstName:                  "test",
		LastName:                   "test",
		StatusID:                   am.UserStatusActive,
		CreationTime:               time.Now().UnixNano(),
		Deleted:                    false,
		AgreementAccepted:          false,
		AgreementAcceptedTimestamp: 0,
	}
	userClient.GetFn = func(ctx context.Context, userContext am.UserContext, userEmail string) (int, *am.User, error) {
		user.OrgID = userContext.GetOrgID()
		user.UserCID = userContext.GetUserCID()
		user.OrgCID = userContext.GetOrgCID()
		user.UserID = userContext.GetUserID()
		return userContext.GetOrgID(), user, nil
	}

	userClient.GetByCIDFn = userClient.GetFn

	userClient.AcceptAgreementFn = func(ctx context.Context, userContext am.UserContext, accepted bool) (int, int, error) {
		user.AgreementAccepted = accepted
		user.AgreementAcceptedTimestamp = time.Now().UnixNano()
		return userContext.GetOrgID(), userContext.GetUserID(), nil
	}

	return userClient
}
