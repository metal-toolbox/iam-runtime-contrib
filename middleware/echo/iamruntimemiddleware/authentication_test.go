package iamruntimemiddleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
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
		expectError            *echo.HTTPError
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
			echo.ErrUnauthorized,
		},
		{
			"failed request",
			nil,
			grpc.ErrServerStopped,
			echo.ErrInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("ValidateCredential", "some subject").Return(tc.authenticationResponse, tc.authenticationError)

			engine := echo.New()

			engine.Debug = true

			ctx := context.Background()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
			require.NoError(t, err)

			resp := httptest.NewRecorder()

			c := engine.NewContext(req, resp)

			c.SetRequest(c.Request().WithContext(iamruntime.SetContextRuntime(c.Request().Context(), runtime)))

			err = ValidateCredential(c, &authentication.ValidateCredentialRequest{
				Credential: authsrv.TSignSubject(t, "some subject"),
			})

			if tc.expectError != nil {
				require.Error(t, err, "expected error to be returned")
				require.IsType(t, tc.expectError, err, "expected echo error")

				echoerr := err.(*echo.HTTPError)

				require.Equal(t, tc.expectError.Code, echoerr.Code, "unexpected echo http code")
			} else {
				assert.NoError(t, err, "expected no error to be returned")
			}

			runtime.Mock.AssertExpectations(t)
		})
	}
}

func ExampleValidateCredential() {
	middleware, _ := NewConfig().ToMiddleware()

	engine := echo.New()

	engine.Use(middleware)

	engine.GET("/user", func(c echo.Context) error {
		otherToken := c.QueryParam("check-token")

		if err := ValidateCredential(c, &authentication.ValidateCredentialRequest{Credential: otherToken}); err != nil {
			if errors.Is(err, iamruntime.ErrInvalidCredentials) {
				return fmt.Errorf("%w: other credentials are invalid", err)
			}

			return err
		}

		return c.String(http.StatusOK, "other token is valid")
	})

	_ = http.ListenAndServe(":8080", engine)
}
