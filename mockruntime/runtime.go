// Package mockruntime mocks iam-runtime clients.
package mockruntime

import (
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"
	"github.com/stretchr/testify/mock"
)

// MockRuntime mocks iam-runtime clients.
type MockRuntime struct {
	authentication.AuthenticationClient
	authorization.AuthorizationClient
	identity.IdentityClient

	mock.Mock
}
