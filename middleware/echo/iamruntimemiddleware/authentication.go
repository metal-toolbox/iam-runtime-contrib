package iamruntimemiddleware

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"google.golang.org/grpc"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
	"github.com/metal-toolbox/iam-runtime-contrib/internal"
)

func setAuthenticationContext(c echo.Context) error {
	bearer, err := internal.GetBearerToken(c.Request())
	if err != nil {
		return echo.ErrUnauthorized.WithInternal(fmt.Errorf("%w: %s", iamruntime.AuthError, err))
	}

	ctx := c.Request().Context()

	token, _, err := jwt.NewParser().ParseUnverified(bearer, jwt.MapClaims{})
	if err != nil {
		return echo.ErrUnauthorized.WithInternal(fmt.Errorf("%w: failed to parse jwt: %w", iamruntime.AuthError, err))
	}

	subject, err := token.Claims.GetSubject()
	if err != nil {
		return echo.ErrUnauthorized.WithInternal(fmt.Errorf("%w: failed to get subject from jwt: %w", iamruntime.AuthError, err))
	}

	ctx = iamruntime.SetContextToken(ctx, token)
	ctx = iamruntime.SetContextSubject(ctx, subject)

	c.SetRequest(c.Request().WithContext(ctx))

	return ValidateCredential(c, &authentication.ValidateCredentialRequest{
		Credential: bearer,
	})
}

// ValidateCredential executes an access request on the runtime in the context with the provided actions.
// If any error is returned, the error is converted to an echo error with a proper status code.
func ValidateCredential(c echo.Context, in *authentication.ValidateCredentialRequest, opts ...grpc.CallOption) error {
	return ContextValidateCredential(c.Request().Context(), in, opts...)
}

// ContextValidateCredential same as [ValidateCredential] except it works off a context.Context.
func ContextValidateCredential(ctx context.Context, in *authentication.ValidateCredentialRequest, opts ...grpc.CallOption) error {
	if err := iamruntime.ContextValidateCredential(ctx, in, opts...); err != nil {
		switch {
		case errors.Is(err, iamruntime.ErrTokenNotFound), errors.Is(err, iamruntime.ErrInvalidCredentials):
			return echo.ErrUnauthorized.WithInternal(err)
		case errors.Is(err, iamruntime.ErrRuntimeNotFound), errors.Is(err, iamruntime.ErrCredentialValidationRequestFailed):
			return echo.ErrInternalServerError.WithInternal(err)
		default:
			return echo.ErrInternalServerError.WithInternal(fmt.Errorf("unknown error: %w", err))
		}
	}

	return nil
}
