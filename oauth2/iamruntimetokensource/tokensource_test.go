package iamruntimetokensource

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
	"github.com/metal-toolbox/iam-runtime-contrib/internal/testauth"
	"github.com/metal-toolbox/iam-runtime-contrib/mockruntime"
)

func TestToken(t *testing.T) {
	authsrv := testauth.NewServer(t)
	t.Cleanup(authsrv.Stop)

	testCases := []struct {
		name          string
		identityError error
		expectError   error
	}{
		{
			"success",
			nil,
			nil,
		},
		{
			"failed request",
			grpc.ErrServerStopped,
			iamruntime.ErrIdentityTokenRequestFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			var req *identity.GetAccessTokenResponse

			if tc.identityError == nil {
				req = &identity.GetAccessTokenResponse{
					Token: authsrv.TSignSubject(t, "some subject"),
				}
			}

			runtime.Mock.On("GetAccessToken").Return(req, tc.identityError)

			ctx := context.Background()

			tokenSource, err := NewTokenSource(ctx, runtime)
			require.NoError(t, err, "unexpected error creating new token source")

			token, err := tokenSource.Token()

			if tc.expectError != nil {
				require.Error(t, err, "expected error to be returned")
				assert.ErrorIs(t, err, tc.expectError, "unexpected error returned")
			} else {
				assert.NoError(t, err, "expected no error to be returned")

				jwtToken, _, err := jwt.NewParser().ParseUnverified(token.AccessToken, jwt.MapClaims{})
				require.NoError(t, err, "unexpected error parsing jwt token")

				subject, err := jwtToken.Claims.GetSubject()
				require.NoError(t, err, "unexpected error getting subject")

				assert.Equal(t, "some subject", subject, "unexpected subject returned")
			}

			runtime.Mock.AssertExpectations(t)
		})
	}
}

func ExampleNewTokenSource() {
	runtime, _ := iamruntime.NewClient("unix:///tmp/runtime.sock")

	ctx := context.TODO()

	iamtoken, _ := NewTokenSource(ctx, runtime)

	httpClient := oauth2.NewClient(ctx, iamtoken)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://iam.example.com/resource/explten-abc123", nil)

	resp, _ := httpClient.Do(req)

	resp.Body.Close()

	fmt.Println("Status Code:", resp.StatusCode)
}
