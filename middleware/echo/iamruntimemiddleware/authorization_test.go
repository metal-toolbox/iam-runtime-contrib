package iamruntimemiddleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
	"github.com/metal-toolbox/iam-runtime-contrib/internal/testauth"
	"github.com/metal-toolbox/iam-runtime-contrib/mockruntime"
)

func TestCheckAccess(t *testing.T) {
	authsrv := testauth.NewServer(t)
	t.Cleanup(authsrv.Stop)

	testCases := []struct {
		name               string
		actions            []*authorization.AccessRequestAction
		returnAccessResult authorization.CheckAccessResponse_Result
		returnAccessError  error
		expectCalled       map[string][]string
		expectStatus       int
		expectBody         map[string]any
	}{
		{
			"permitted",
			[]*authorization.AccessRequestAction{
				{
					ResourceId: "testten-abc123",
					Action:     "action_one",
				},
				{
					ResourceId: "testten-abc123",
					Action:     "action_two",
				},
				{
					ResourceId: "testten-def456",
					Action:     "action_one",
				},
			},
			authorization.CheckAccessResponse_RESULT_ALLOWED,
			nil,
			map[string][]string{
				"testten-abc123": {"action_one", "action_two"},
				"testten-def456": {"action_one"},
			},
			http.StatusOK,
			map[string]any{
				"success": true,
			},
		},
		{
			"denied",
			[]*authorization.AccessRequestAction{
				{
					ResourceId: "testten-abc123",
					Action:     "action_one",
				},
			},
			authorization.CheckAccessResponse_RESULT_DENIED,
			nil,
			map[string][]string{"testten-abc123": {"action_one"}},
			http.StatusForbidden,
			map[string]any{
				"message": "Forbidden",
				"error":   "code=403, message=Forbidden, internal=iam-runtime error: access: denied",
			},
		},
		{
			"error",
			[]*authorization.AccessRequestAction{
				{
					ResourceId: "testten-abc123",
					Action:     "action_one",
				},
			},
			0,
			grpc.ErrServerStopped,
			map[string][]string{"testten-abc123": {"action_one"}},
			http.StatusInternalServerError,
			map[string]any{
				"message": "Internal Server Error",
				"error":   "code=500, message=Internal Server Error, internal=iam-runtime error: access: failed to check access: grpc: the server has been stopped",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("ValidateCredential", "some subject").Return(&authentication.ValidateCredentialResponse{
				Result: authentication.ValidateCredentialResponse_RESULT_VALID,
			}, nil)

			runtime.Mock.On("CheckAccess", tc.expectCalled).Return(tc.returnAccessResult, tc.returnAccessError)

			config := NewConfig().WithRuntime(runtime)

			middleware, err := config.ToMiddleware()
			require.NoError(t, err, "unexpected error building middleware")

			engine := echo.New()

			engine.Debug = true

			engine.Use(middleware)

			engine.GET("/test", func(c echo.Context) error {
				if err := CheckAccess(c, tc.actions); err != nil {
					return err
				}

				return c.JSON(http.StatusOK, echo.Map{
					"success": true,
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

func TestCheckAccessTo(t *testing.T) {
	authsrv := testauth.NewServer(t)
	t.Cleanup(authsrv.Stop)

	testCases := []struct {
		name               string
		actions            []string
		returnAccessResult authorization.CheckAccessResponse_Result
		returnAccessError  error
		expectCalled       map[string][]string
		expectStatus       int
		expectBody         map[string]any
	}{
		{
			"permitted",
			[]string{
				"testten-abc123", "action_one",
				"testten-abc123", "action_two",
				"testten-def456", "action_one",
			},
			authorization.CheckAccessResponse_RESULT_ALLOWED,
			nil,
			map[string][]string{
				"testten-abc123": {"action_one", "action_two"},
				"testten-def456": {"action_one"},
			},
			http.StatusOK,
			map[string]any{
				"success": true,
			},
		},
		{
			"denied",
			[]string{"testten-abc123", "action_one"},
			authorization.CheckAccessResponse_RESULT_DENIED,
			nil,
			map[string][]string{"testten-abc123": {"action_one"}},
			http.StatusForbidden,
			map[string]any{
				"message": "Forbidden",
				"error":   "code=403, message=Forbidden, internal=iam-runtime error: access: denied",
			},
		},
		{
			"error",
			[]string{"testten-abc123", "action_one"},
			0,
			grpc.ErrServerStopped,
			map[string][]string{"testten-abc123": {"action_one"}},
			http.StatusInternalServerError,
			map[string]any{
				"message": "Internal Server Error",
				"error":   "code=500, message=Internal Server Error, internal=iam-runtime error: access: failed to check access: grpc: the server has been stopped",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("ValidateCredential", "some subject").Return(&authentication.ValidateCredentialResponse{
				Result: authentication.ValidateCredentialResponse_RESULT_VALID,
			}, nil)

			runtime.Mock.On("CheckAccess", tc.expectCalled).Return(tc.returnAccessResult, tc.returnAccessError)

			config := NewConfig().WithRuntime(runtime)

			middleware, err := config.ToMiddleware()
			require.NoError(t, err, "unexpected error building middleware")

			engine := echo.New()

			engine.Debug = true

			engine.Use(middleware)

			engine.GET("/test", func(c echo.Context) error {
				if err := CheckAccessTo(c, tc.actions...); err != nil {
					return err
				}

				return c.JSON(http.StatusOK, echo.Map{
					"success": true,
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

func TestCreateRelationships(t *testing.T) {
	testCases := []struct {
		name         string
		request      *authorization.CreateRelationshipsRequest
		requestError error
		expectCalled map[string][]string
		expectError  *echo.HTTPError
	}{
		{
			"created",
			&authorization.CreateRelationshipsRequest{
				ResourceId: "testten-abc123",
				Relationships: []*authorization.Relationship{
					{
						Relation:  "parent",
						SubjectId: "testten-root123",
					},
				},
			},
			nil,
			map[string][]string{
				"parent": {"testten-root123"},
			},
			nil,
		},
		{
			"failed",
			&authorization.CreateRelationshipsRequest{
				ResourceId: "testten-abc123",
				Relationships: []*authorization.Relationship{
					{
						Relation:  "parent",
						SubjectId: "testten-root123",
					},
				},
			},
			grpc.ErrServerStopped,
			map[string][]string{
				"parent": {"testten-root123"},
			},
			echo.ErrInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("CreateRelationships", tc.request.ResourceId, tc.expectCalled).Return(tc.requestError)

			engine := echo.New()

			engine.Debug = true

			ctx := context.Background()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
			require.NoError(t, err)

			resp := httptest.NewRecorder()

			c := engine.NewContext(req, resp)

			c.SetRequest(c.Request().WithContext(iamruntime.SetContextRuntime(c.Request().Context(), runtime)))

			_, err = CreateRelationships(c, tc.request)

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

func TestDeleteRelationships(t *testing.T) {
	testCases := []struct {
		name         string
		request      *authorization.DeleteRelationshipsRequest
		requestError error
		expectCalled map[string][]string
		expectError  *echo.HTTPError
	}{
		{
			"deleted",
			&authorization.DeleteRelationshipsRequest{
				ResourceId: "testten-abc123",
				Relationships: []*authorization.Relationship{
					{
						Relation:  "parent",
						SubjectId: "testten-root123",
					},
				},
			},
			nil,
			map[string][]string{
				"parent": {"testten-root123"},
			},
			nil,
		},
		{
			"failed",
			&authorization.DeleteRelationshipsRequest{
				ResourceId: "testten-abc123",
				Relationships: []*authorization.Relationship{
					{
						Relation:  "parent",
						SubjectId: "testten-root123",
					},
				},
			},
			grpc.ErrServerStopped,
			map[string][]string{
				"parent": {"testten-root123"},
			},
			echo.ErrInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("DeleteRelationships", tc.request.ResourceId, tc.expectCalled).Return(tc.requestError)

			engine := echo.New()

			engine.Debug = true

			ctx := context.Background()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
			require.NoError(t, err)

			resp := httptest.NewRecorder()

			c := engine.NewContext(req, resp)

			c.SetRequest(c.Request().WithContext(iamruntime.SetContextRuntime(c.Request().Context(), runtime)))

			_, err = DeleteRelationships(c, tc.request)

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

func ExampleCheckAccess() {
	middleware, _ := NewConfig().ToMiddleware()

	engine := echo.New()

	engine.Use(middleware)

	engine.GET("/resources/:resource_id", func(c echo.Context) error {
		check := []*authorization.AccessRequestAction{
			{ResourceId: c.Param("resource_id"), Action: "resource_get"},
		}

		if err := CheckAccess(c, check); err != nil {
			return err
		}

		return c.String(http.StatusOK, "user has access to resource")
	})

	_ = http.ListenAndServe(":8080", engine)
}

func ExampleCheckAccessTo() {
	middleware, _ := NewConfig().ToMiddleware()

	engine := echo.New()

	engine.Use(middleware)

	engine.GET("/resources/:resource_id", func(c echo.Context) error {
		if err := CheckAccessTo(c, c.Param("resource_id"), "resource_get"); err != nil {
			return err
		}

		return c.String(http.StatusOK, "user has access to resource")
	})

	_ = http.ListenAndServe(":8080", engine)
}

// StorageResource is used in examples.
type StorageResource struct {
	ID               string
	ParentResourceID string
}

// GetResourceFromRequest is used in examples.
func GetResourceFromRequest(_ echo.Context) StorageResource {
	return StorageResource{
		ID:               "testten-abc123",
		ParentResourceID: "testten-root123",
	}
}

// CreateResourceFromRequest is used in examples.
func CreateResourceFromRequest(_ echo.Context) StorageResource {
	return StorageResource{
		ID:               "testten-abc123",
		ParentResourceID: "testten-root123",
	}
}

// DeleteResourceFromRequest is used in examples.
func DeleteResourceFromRequest(_ echo.Context) error {
	return nil
}

func ExampleCreateRelationships() {
	middleware, _ := NewConfig().ToMiddleware()

	engine := echo.New()

	engine.Use(middleware)

	engine.POST("/resources", func(c echo.Context) error {
		resource := CreateResourceFromRequest(c)

		relationRequest := &authorization.CreateRelationshipsRequest{
			ResourceId: resource.ID,
			Relationships: []*authorization.Relationship{
				{
					Relation:  "parent",
					SubjectId: resource.ParentResourceID,
				},
			},
		}

		if _, err := CreateRelationships(c, relationRequest); err != nil {
			return err
		}

		return c.String(http.StatusOK, "resource created with relationships")
	})

	_ = http.ListenAndServe(":8080", engine)
}

func ExampleDeleteRelationships() {
	middleware, _ := NewConfig().ToMiddleware()

	engine := echo.New()

	engine.Use(middleware)

	engine.DELETE("/resources/:resource_id", func(c echo.Context) error {
		resource := GetResourceFromRequest(c)

		if err := DeleteResourceFromRequest(c); err != nil {
			return err
		}

		relationRequest := &authorization.DeleteRelationshipsRequest{
			ResourceId: resource.ID,
			Relationships: []*authorization.Relationship{
				{
					Relation:  "parent",
					SubjectId: resource.ParentResourceID,
				},
			},
		}

		if _, err := DeleteRelationships(c, relationRequest); err != nil {
			return err
		}

		return c.String(http.StatusOK, "resource created with relationships")
	})

	_ = http.ListenAndServe(":8080", engine)
}
