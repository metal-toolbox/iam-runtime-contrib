package iamruntime

import (
	"errors"
	"fmt"
)

var (
	// Error is the root error for all iam-runtime related errors.
	Error = errors.New("iam-runtime error")

	// ErrRuntimeNotFound is the error returned when the runtime is not found in the context.
	ErrRuntimeNotFound = fmt.Errorf("%w: runtime not found", Error)

	// AuthError is the root error all auth related errors stem from.
	AuthError = fmt.Errorf("%w: auth", Error) //nolint:revive,stylecheck // not returned directly, but used as a root error.

	// ErrCredentialValidationRequestFailed is the error returned when the credential validation request failed to execute.
	ErrCredentialValidationRequestFailed = fmt.Errorf("%w: failed to execute validation request", AuthError)

	// ErrInvalidCredentials is the error returned when the provided credentials are not valid.
	ErrInvalidCredentials = fmt.Errorf("%w: invalid credentials", AuthError)

	// ErrTokenNotFound is the error returned when the token is not found in the context.
	ErrTokenNotFound = fmt.Errorf("%w: token not found", AuthError)

	// AccessError is the root error for all access related errors.
	AccessError = fmt.Errorf("%w: access", Error) //nolint:revive,stylecheck // not returned directly, but used as a root error.

	// ErrAccessCheckFailed is the error returned when an access request failed to execute.
	ErrAccessCheckFailed = fmt.Errorf("%w: failed to check access", AccessError)

	// ErrAccessDenied is the error returned when an access request is denied.
	ErrAccessDenied = fmt.Errorf("%w: denied", AccessError)

	// RelationshipError is the root error for all relationship related errors.
	RelationshipError = fmt.Errorf("%w: relationship", Error) //nolint:revive,stylecheck // not returned directly, but used as a root error.

	// ErrRelationshipRequestFailed is the error returned when a relationship request failed to execute.
	ErrRelationshipRequestFailed = fmt.Errorf("%w: failed to execute relationship request", RelationshipError)

	// IdentityError is the root error for all identity related errors.
	IdentityError = fmt.Errorf("%w: identity", Error) //nolint:revive,stylecheck // not returned directly, but used as a root error.

	// ErrIdentityTokenRequestFailed is the error returned when an access token request failed to execute.
	ErrIdentityTokenRequestFailed = fmt.Errorf("%w: failed to request access token", IdentityError)

	// ErrAccessTokenInvalid is the error returned when an access token returned is not valid.
	ErrAccessTokenInvalid = fmt.Errorf("%w: invalid access token", IdentityError)
)
