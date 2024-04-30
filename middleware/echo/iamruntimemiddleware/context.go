package iamruntimemiddleware

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
)

// ContextRuntime retrieves the iam runtime from the context.
// If the runtime is not found in the provided context, nil is returned.
//
// Use ContextRuntime() or ContextRuntimeAny() from iamruntime if a stdlib context is being used.
func ContextRuntime(c echo.Context) Runtime {
	if runtime, ok := iamruntime.ContextRuntimeAny(c.Request().Context()).(Runtime); ok {
		return runtime
	}

	return nil
}

// ContextToken retrieves the decoded jwt token from the provided echo context.
// If the token is not found in the provided context, nil is returned.
//
// Use ContextToken() from iamruntime if a stdlib context is being used.
func ContextToken(c echo.Context) *jwt.Token {
	return iamruntime.ContextToken(c.Request().Context())
}

// ContextSubject retrieves the subject from the provided echo context.
// If the subject is not found in the provided context, an empty string is returned.
//
// Use ContextSubject() from iamruntime if a stdlib context is being used.
func ContextSubject(c echo.Context) string {
	return iamruntime.ContextSubject(c.Request().Context())
}
