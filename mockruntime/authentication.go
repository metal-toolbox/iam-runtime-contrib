package mockruntime

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"google.golang.org/grpc"
)

// ValidateCredential mocks iam-runtime authentication.ValidateCredential
func (r *MockRuntime) ValidateCredential(_ context.Context, in *authentication.ValidateCredentialRequest, _ ...grpc.CallOption) (*authentication.ValidateCredentialResponse, error) {
	var subject string

	token, _, err := jwt.NewParser().ParseUnverified(in.Credential, jwt.MapClaims{})
	if err == nil {
		subject, err = token.Claims.GetSubject()
		if err != nil {
			return nil, err
		}
	}

	args := r.Mock.Called(subject)

	return args.Get(0).(*authentication.ValidateCredentialResponse), args.Error(1)
}
