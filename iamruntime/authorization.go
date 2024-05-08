package iamruntime

import (
	"context"
	"fmt"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"google.golang.org/grpc"
)

// ContextCheckAccess executes an access request on the runtime in the context.
// Context must have a token and runtime value.
// The runtime must implement the iam-runtime's AuthorizationClient.
// Use [SetContextToken] and [SetContextRuntime] to set these values.
func ContextCheckAccess(ctx context.Context, actions []*authorization.AccessRequestAction, opts ...grpc.CallOption) error {
	token := ContextToken(ctx)
	if token == nil {
		return ErrTokenNotFound
	}

	runtime := ContextRuntimeAuthorizationClient(ctx)
	if runtime == nil {
		return ErrRuntimeNotFound
	}

	resp, err := runtime.CheckAccess(ctx, &authorization.CheckAccessRequest{
		Credential: token.Raw,
		Actions:    actions,
	}, opts...)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAccessCheckFailed, err)
	}

	if resp.Result == authorization.CheckAccessResponse_RESULT_DENIED {
		return ErrAccessDenied
	}

	return nil
}

// ContextCheckAccessTo builds a check access request and executes it on the runtime in the provided context.
// Arguments must be pairs of Resource ID and Role Actions.
func ContextCheckAccessTo(ctx context.Context, resourceIDActionPairs ...string) error {
	if len(resourceIDActionPairs)%2 != 0 {
		return fmt.Errorf("%w: invalid argument count", ErrResourceIDActionPairsInvalid)
	}

	var checkActions []*authorization.AccessRequestAction

	for i := 0; i < len(resourceIDActionPairs); i += 2 {
		checkActions = append(checkActions, &authorization.AccessRequestAction{
			ResourceId: resourceIDActionPairs[i],
			Action:     resourceIDActionPairs[i+1],
		})
	}

	return ContextCheckAccess(ctx, checkActions)
}

// ContextCreateRelationships executes a create relationship request on the runtime in the context.
// Context must have a runtime value.
// The runtime must implement the iam-runtime's AuthorizationClient.
// Use [SetContextRuntime] to set this value.
func ContextCreateRelationships(ctx context.Context, in *authorization.CreateRelationshipsRequest, opts ...grpc.CallOption) (*authorization.CreateRelationshipsResponse, error) {
	runtime := ContextRuntimeAuthorizationClient(ctx)
	if runtime == nil {
		return nil, ErrRuntimeNotFound
	}

	resp, err := runtime.CreateRelationships(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: create: %w", ErrRelationshipRequestFailed, err)
	}

	return resp, nil
}

// ContextDeleteRelationships executes a delete relationship request on the runtime in the context.
// Context must have a runtime value.
// The runtime must implement the iam-runtime's AuthorizationClient.
// Use [SetContextRuntime] to set this value.
func ContextDeleteRelationships(ctx context.Context, in *authorization.DeleteRelationshipsRequest, opts ...grpc.CallOption) (*authorization.DeleteRelationshipsResponse, error) {
	runtime := ContextRuntimeAuthorizationClient(ctx)
	if runtime == nil {
		return nil, ErrRuntimeNotFound
	}

	resp, err := runtime.DeleteRelationships(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: delete: %w", ErrRelationshipRequestFailed, err)
	}

	return resp, nil
}
