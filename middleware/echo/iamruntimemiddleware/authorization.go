package iamruntimemiddleware

import (
	"context"
	"errors"
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"google.golang.org/grpc"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
)

func setRuntimeContext(r Runtime, c echo.Context) error {
	ctx := iamruntime.SetContextRuntimeAny(c.Request().Context(), r)

	c.SetRequest(c.Request().WithContext(ctx))

	return nil
}

// CheckAccess executes an access request on the runtime in the context with the provided actions.
// If any error is returned, the error is converted to an echo error with a proper status code.
func CheckAccess(c echo.Context, actions []*authorization.AccessRequestAction, opts ...grpc.CallOption) error {
	return ContextCheckAccess(c.Request().Context(), actions, opts...)
}

// ContextCheckAccess same as [CheckAccess] except it works on a context.Context.
func ContextCheckAccess(ctx context.Context, actions []*authorization.AccessRequestAction, opts ...grpc.CallOption) error {
	if err := iamruntime.ContextCheckAccess(ctx, actions, opts...); err != nil {
		switch {
		case errors.Is(err, iamruntime.ErrTokenNotFound):
			return echo.ErrBadRequest.WithInternal(err)
		case errors.Is(err, iamruntime.ErrRuntimeNotFound),
			errors.Is(err, iamruntime.ErrAccessCheckFailed),
			errors.Is(err, iamruntime.ErrResourceIDActionPairsInvalid):
			return echo.ErrInternalServerError.WithInternal(err)
		case errors.Is(err, iamruntime.ErrAccessDenied):
			return echo.ErrForbidden.WithInternal(err)
		default:
			return echo.ErrInternalServerError.WithInternal(fmt.Errorf("unknown error: %w", err))
		}
	}

	return nil
}

// CheckAccessTo builds a check access request and executes it on the runtime in the provided context.
// Arguments must be pairs of Resource ID and Role Actions.
func CheckAccessTo(c echo.Context, resourceIDActionPairs ...string) error {
	return ContextCheckAccessTo(c.Request().Context(), resourceIDActionPairs...)
}

// ContextCheckAccessTo same as [CheckAccessTo] except it works on a context.Context.
func ContextCheckAccessTo(ctx context.Context, resourceIDActionPairs ...string) error {
	if err := iamruntime.ContextCheckAccessTo(ctx, resourceIDActionPairs...); err != nil {
		switch {
		case errors.Is(err, iamruntime.ErrTokenNotFound):
			return echo.ErrBadRequest.WithInternal(err)
		case errors.Is(err, iamruntime.ErrRuntimeNotFound), errors.Is(err, iamruntime.ErrAccessCheckFailed):
			return echo.ErrInternalServerError.WithInternal(err)
		case errors.Is(err, iamruntime.ErrAccessDenied):
			return echo.ErrForbidden.WithInternal(err)
		default:
			return echo.ErrInternalServerError.WithInternal(fmt.Errorf("unknown error: %w", err))
		}
	}

	return nil
}

// CreateRelationships executes a create relationship request on the runtime in the context.
// If any error is returned, the error is converted to an echo error with a proper status code.
func CreateRelationships(c echo.Context, in *authorization.CreateRelationshipsRequest, opts ...grpc.CallOption) (*authorization.CreateRelationshipsResponse, error) {
	return ContextCreateRelationships(c.Request().Context(), in, opts...)
}

// ContextCreateRelationships same as [CreateRelationships] except it works on a context.Context.
func ContextCreateRelationships(ctx context.Context, in *authorization.CreateRelationshipsRequest, opts ...grpc.CallOption) (*authorization.CreateRelationshipsResponse, error) {
	resp, err := iamruntime.ContextCreateRelationships(ctx, in, opts...)
	if err != nil {
		switch {
		case errors.Is(err, iamruntime.ErrRuntimeNotFound), errors.Is(err, iamruntime.ErrRelationshipRequestFailed):
			return nil, echo.ErrInternalServerError.WithInternal(err)
		default:
			return nil, echo.ErrInternalServerError.WithInternal(fmt.Errorf("unknown error: %w", err))
		}
	}

	return resp, nil
}

// DeleteRelationships executes a delete relationship request on the runtime in the context.
// If any error is returned, the error is converted to an echo error with a proper status code.
func DeleteRelationships(c echo.Context, in *authorization.DeleteRelationshipsRequest, opts ...grpc.CallOption) (*authorization.DeleteRelationshipsResponse, error) {
	return ContextDeleteRelationships(c.Request().Context(), in, opts...)
}

// ContextDeleteRelationships same as [DeleteRelationships] except it works on a context.Context.
func ContextDeleteRelationships(ctx context.Context, in *authorization.DeleteRelationshipsRequest, opts ...grpc.CallOption) (*authorization.DeleteRelationshipsResponse, error) {
	resp, err := iamruntime.ContextDeleteRelationships(ctx, in, opts...)
	if err != nil {
		switch {
		case errors.Is(err, iamruntime.ErrRuntimeNotFound), errors.Is(err, iamruntime.ErrRelationshipRequestFailed):
			return nil, echo.ErrInternalServerError.WithInternal(err)
		default:
			return nil, echo.ErrInternalServerError.WithInternal(fmt.Errorf("unknown error: %w", err))
		}
	}

	return resp, nil
}
