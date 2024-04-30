package iamruntimemiddleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/metal-toolbox/iam-runtime-contrib/internal/testauth"
	"github.com/metal-toolbox/iam-runtime-contrib/mockruntime"
)

func TestConfig_ToMiddleware(t *testing.T) {
	authsrv := testauth.NewServer(t)
	t.Cleanup(authsrv.Stop)

	testCases := []struct {
		name                   string
		authenticationResponse authentication.ValidateCredentialResponse_Result
		expectStatus           int
		expectBody             map[string]any
	}{
		{
			"valid",
			authentication.ValidateCredentialResponse_RESULT_VALID,
			http.StatusOK,
			map[string]any{
				"token_subject": "some subject",
				"subject":       "some subject",
			},
		},
		{
			"invalid",
			authentication.ValidateCredentialResponse_RESULT_INVALID,
			http.StatusUnauthorized,
			map[string]any{
				"message": "Unauthorized",
				"error":   "code=401, message=Unauthorized, internal=iam-runtime error: auth: invalid credentials",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("ValidateCredential", "some subject").Return(&authentication.ValidateCredentialResponse{
				Result: tc.authenticationResponse,
			}, nil)

			config := NewConfig().WithRuntime(runtime)

			middleware, err := config.ToMiddleware()
			require.NoError(t, err, "unexpected error building middleware")

			engine := echo.New()

			engine.Debug = true

			engine.Use(middleware)

			engine.GET("/test", func(c echo.Context) error {
				subject, err := ContextToken(c).Claims.GetSubject()
				if err != nil {
					return echo.ErrNotAcceptable.WithInternal(err)
				}

				return c.JSON(http.StatusOK, echo.Map{
					"token_subject": subject,
					"subject":       ContextSubject(c),
				})
			})

			ctx := context.Background()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
			require.NoError(t, err)

			req.Header.Add("Authorization", "Bearer "+authsrv.TSignSubject(t, "some subject"))

			resp := httptest.NewRecorder()

			engine.ServeHTTP(resp, req)

			runtime.Mock.AssertExpectations(t)

			assert.Equal(t, tc.expectStatus, resp.Code, "unexpected status code returned")

			var body map[string]any

			err = json.Unmarshal(resp.Body.Bytes(), &body)
			require.NoError(t, err, "unexpected error decoding body")

			assert.Equal(t, tc.expectBody, body, "unexpected body returned")
		})
	}
}

func ExampleConfig_ToMiddleware() {
	middleware, _ := NewConfig().ToMiddleware()

	engine := echo.New()

	engine.Use(middleware)

	engine.GET("/user", func(c echo.Context) error {
		return c.String(http.StatusOK, "welcome "+ContextSubject(c))
	})

	_ = http.ListenAndServe(":8080", engine)
}
