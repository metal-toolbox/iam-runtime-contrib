package iamruntime

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/metal-toolbox/iam-runtime-contrib/internal/testauth"
	"github.com/metal-toolbox/iam-runtime-contrib/mockruntime"
)

func TestContextCheckAccess(t *testing.T) {
	authsrv := testauth.NewServer(t)
	t.Cleanup(authsrv.Stop)

	testCases := []struct {
		name               string
		actions            []*authorization.AccessRequestAction
		returnAccessResult authorization.CheckAccessResponse_Result
		returnAccessError  error
		expectCalled       map[string][]string
		expectError        error
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
			nil,
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
			ErrAccessDenied,
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
			ErrAccessCheckFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("CheckAccess", tc.expectCalled).Return(tc.returnAccessResult, tc.returnAccessError)

			token, _, err := jwt.NewParser().ParseUnverified(authsrv.TSignSubject(t, "some subject"), jwt.MapClaims{})
			require.NoError(t, err, "unexpected error creating jwt")

			ctx := context.Background()

			ctx = SetContextRuntime(ctx, runtime)
			ctx = SetContextToken(ctx, token)

			err = ContextCheckAccess(ctx, tc.actions)

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

func TestContextCreateRelationships(t *testing.T) {
	testCases := []struct {
		name         string
		request      *authorization.CreateRelationshipsRequest
		requestError error
		expectCalled map[string][]string
		expectError  error
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
			ErrRelationshipRequestFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("CreateRelationships", tc.request.ResourceId, tc.expectCalled).Return(tc.requestError)

			ctx := context.Background()

			ctx = SetContextRuntime(ctx, runtime)

			_, err := ContextCreateRelationships(ctx, tc.request)

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

func TestContextDeleteRelationships(t *testing.T) {
	testCases := []struct {
		name         string
		request      *authorization.DeleteRelationshipsRequest
		requestError error
		expectCalled map[string][]string
		expectError  error
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
			ErrRelationshipRequestFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := new(mockruntime.MockRuntime)

			runtime.Mock.On("DeleteRelationships", tc.request.ResourceId, tc.expectCalled).Return(tc.requestError)

			ctx := context.Background()

			ctx = SetContextRuntime(ctx, runtime)

			_, err := ContextDeleteRelationships(ctx, tc.request)

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

func ExampleContextCheckAccess() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	ctx := SetContextRuntime(context.TODO(), runtime)
	ctx = SetContextToken(ctx, &jwt.Token{Raw: "some token"})

	check := []*authorization.AccessRequestAction{
		{ResourceId: "resctyp-abc123", Action: "resource_get"},
	}

	if err := ContextCheckAccess(ctx, check); err != nil {
		panic("failed to check access: " + err.Error())
	}

	fmt.Println("Token has access to resource!")
}

// StorageResource is used in examples.
type StorageResource struct {
	ID               string
	ParentResourceID string
}

// GetResource is used in examples.
func GetResource() StorageResource {
	return StorageResource{
		ID:               "testten-abc123",
		ParentResourceID: "testten-root123",
	}
}

// CreateResource is used in examples.
func CreateResource() StorageResource {
	return StorageResource{
		ID:               "testten-abc123",
		ParentResourceID: "testten-root123",
	}
}

// DeleteResource is used in examples.
func DeleteResource() error {
	return nil
}

func ExampleContextCreateRelationships() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	ctx := SetContextRuntime(context.TODO(), runtime)

	resource := CreateResource()

	relationRequest := &authorization.CreateRelationshipsRequest{
		ResourceId: resource.ID,
		Relationships: []*authorization.Relationship{
			{
				Relation:  "parent",
				SubjectId: resource.ParentResourceID,
			},
		},
	}

	if _, err := ContextCreateRelationships(ctx, relationRequest); err != nil {
		panic("failed to create relationships: " + err.Error())
	}

	fmt.Println("Relationships created!")
}

func ExampleContextDeleteRelationships() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	ctx := SetContextRuntime(context.TODO(), runtime)

	resource := GetResource()

	if err := DeleteResource(); err != nil {
		panic("failed to delete resource: " + err.Error())
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

	if _, err := ContextDeleteRelationships(ctx, relationRequest); err != nil {
		panic("failed to delete relationships: " + err.Error())
	}

	fmt.Println("Relationships deleted!")
}
