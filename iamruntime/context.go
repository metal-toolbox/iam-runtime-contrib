package iamruntime

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"

	"github.com/metal-toolbox/iam-runtime-contrib/internal"
)

// ContextRuntime retrieves the iam-runtime from the context and ensures it implements all clients.
// If the runtime is not found in the provided context, nil is returned.
// If the stored runtime does not implement all clients, nil is returned. Instead use [GetRuntimeAny].
func ContextRuntime(ctx context.Context) Runtime {
	if runtime, ok := ctx.Value(internal.RuntimeCtxKey).(Runtime); ok {
		return runtime
	}

	return nil
}

// ContextRuntimeAny retrieves the iam-runtime from the context and returns an interface.
// If the runtime is not found in the provided context, nil is returned.
// If the stored runtime implements all client implementations, use [GetRuntime].
func ContextRuntimeAny(ctx context.Context) any {
	return ctx.Value(internal.RuntimeCtxKey)
}

// ContextRuntimeAuthenticationClient retrieves the iam runtime from the context and ensures it has the authorization client interface.
// If the runtime is not found in the provided context or it doesn't implement the authorization client, nil is returned.
func ContextRuntimeAuthenticationClient(ctx context.Context) authentication.AuthenticationClient {
	if runtime, ok := ctx.Value(internal.RuntimeCtxKey).(authentication.AuthenticationClient); ok {
		return runtime
	}

	return nil
}

// ContextRuntimeAuthorizationClient retrieves the iam runtime from the context and ensures it has the authorization client interface.
// If the runtime is not found in the provided context or it doesn't implement the authorization client, nil is returned.
func ContextRuntimeAuthorizationClient(ctx context.Context) authorization.AuthorizationClient {
	if runtime, ok := ctx.Value(internal.RuntimeCtxKey).(authorization.AuthorizationClient); ok {
		return runtime
	}

	return nil
}

// ContextRuntimeIdentityClient retrieves the iam runtime from the context and ensures it has the identity client interface.
// If the runtime is not found in the provided context or it doesn't implement the identity client, nil is returned.
func ContextRuntimeIdentityClient(ctx context.Context) identity.IdentityClient {
	if runtime, ok := ctx.Value(internal.RuntimeCtxKey).(identity.IdentityClient); ok {
		return runtime
	}

	return nil
}

// ContextToken retrieves the decoded jwt token from the provided context.
// If the token is not found in the provided context, nil is returned.
func ContextToken(ctx context.Context) *jwt.Token {
	if token, ok := ctx.Value(internal.TokenCtxKey).(*jwt.Token); ok {
		return token
	}

	return nil
}

// ContextSubject retrieves the subject from the provided context.
// If the subject is not found in the provided context, an empty string is returned.
func ContextSubject(ctx context.Context) string {
	if subject, ok := ctx.Value(internal.SubjectCtxKey).(string); ok {
		return subject
	}

	return ""
}

// SetContextRuntime sets the runtime context key to the provided runtime.
// The provided runtime must implement all iam-runtime clients.
//
// If only a limited number of clients are required, use [SetContextRuntimeAny].
func SetContextRuntime(ctx context.Context, value Runtime) context.Context {
	return context.WithValue(ctx, internal.RuntimeCtxKey, value)
}

// SetContextRuntimeAny sets the runtime context key to the provided runtime.
// No validation is done that the value provided is actually an iam-runtime client
// implementation as different applications may only require a subset of client
// implementations.
//
// Ensure the value provided meets all your requirements before setting the value,
// otherwise context functions will fail.
//
// If the runtime implements all iam-runtime client's, use [SetContextRuntime].
func SetContextRuntimeAny(ctx context.Context, value any) context.Context {
	return context.WithValue(ctx, internal.RuntimeCtxKey, value)
}

// SetContextToken sets the token context key to the provided token.
func SetContextToken(ctx context.Context, value *jwt.Token) context.Context {
	return context.WithValue(ctx, internal.TokenCtxKey, value)
}

// SetContextSubject sets the subject context key to the provided value.
func SetContextSubject(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, internal.SubjectCtxKey, value)
}
