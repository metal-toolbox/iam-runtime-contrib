package mockruntime

import (
	"context"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"
	"google.golang.org/grpc"
)

// GetAccessToken mocks iam-runtime identity.GetAccessToken
func (r *MockRuntime) GetAccessToken(_ context.Context, _ *identity.GetAccessTokenRequest, _ ...grpc.CallOption) (*identity.GetAccessTokenResponse, error) {
	args := r.Mock.Called()

	return args.Get(0).(*identity.GetAccessTokenResponse), args.Error(1)
}
