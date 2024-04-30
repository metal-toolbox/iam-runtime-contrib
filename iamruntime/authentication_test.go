package iamruntime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/metal-toolbox/iam-runtime-contrib/internal/testauth"
	"github.com/metal-toolbox/iam-runtime-contrib/mockruntime"
)

func TestValidateCredential(t *testing.T) {
	authsrv := testauth.NewServer(t)
	t.Cleanup(authsrv.Stop)

	testCases := []struct {
		name                   string
		authenticationResponse *authentication.ValidateCredentialResponse
		authenticationError    error
		expectError            error
	}{
		{
			"permitted",
			&authentication.ValidateCredentialResponse{Result: authentication.ValidateCredentialResponse_RESULT_VALID},
			nil,
			nil,
		},
		{
			"denied",
			&authentication.ValidateCredentialResponse{Result: authentication.ValidateCredentialResponse_RESULT_INVALID},
			nil,
			ErrInvalidCredentials,
		},
		{
			"failed request",
			nil,
			grpc.ErrServerStopped,
			ErrCredentialValidationRequestFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("ValidateCredential", "some subject").Return(tc.authenticationResponse, tc.authenticationError)

			engine := echo.New()

			engine.Debug = true

			ctx := context.Background()

			ctx = SetContextRuntime(ctx, runtime)

			err := ContextValidateCredential(ctx, &authentication.ValidateCredentialRequest{
				Credential: authsrv.TSignSubject(t, "some subject"),
			})

			if tc.expectError != nil {
				require.Error(t, err, "expected error to be returned")
				assert.ErrorIs(t, err, tc.expectError, "unexpected error returned")
			} else {
				assert.NoError(t, err, "expected no error to be returned")
			}

			runtime.Mock.AssertExpectations(t)
		})
	}
}

func ExampleContextValidateCredential() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	ctx := SetContextRuntime(context.TODO(), runtime)

	someToken := "some token"

	if err := ContextValidateCredential(ctx, &authentication.ValidateCredentialRequest{Credential: someToken}); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			fmt.Println("other credentials are invalid", err)

			return
		}

		fmt.Println("failed to validate credentials", err)
	}

	fmt.Println("Credentials are valid!")
}
