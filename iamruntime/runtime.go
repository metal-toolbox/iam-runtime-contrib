package iamruntime

import (
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Runtime implements all iam-runtime clients.
type Runtime interface {
	authorization.AuthorizationClient
	authentication.AuthenticationClient
	identity.IdentityClient
}

type runtime struct {
	authorization.AuthorizationClient
	authentication.AuthenticationClient
	identity.IdentityClient
}

// NewClient creates a new iam-runtime which implements all clients.
func NewClient(socket string) (Runtime, error) {
	conn, err := grpc.Dial(socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &runtime{
		AuthorizationClient:  authorization.NewAuthorizationClient(conn),
		AuthenticationClient: authentication.NewAuthenticationClient(conn),
		IdentityClient:       identity.NewIdentityClient(conn),
	}, nil
}
