package iamruntimemiddleware

import (
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
	if err := iamruntime.ContextCheckAccess(c.Request().Context(), actions, opts...); err != nil {
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
	resp, err := iamruntime.ContextCreateRelationships(c.Request().Context(), in, opts...)
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
	resp, err := iamruntime.ContextDeleteRelationships(c.Request().Context(), in, opts...)
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
