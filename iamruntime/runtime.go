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
//
// GRPC Insecure transport credentials are configured by default.
// This may be overwritten by providing an alternative TransportCredentials dial option.
func NewClient(target string, dialOpts ...grpc.DialOption) (Runtime, error) {
	dialOpts = append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, dialOpts...)

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, err
	}

	return &runtime{
		AuthorizationClient:  authorization.NewAuthorizationClient(conn),
		AuthenticationClient: authentication.NewAuthenticationClient(conn),
		IdentityClient:       identity.NewIdentityClient(conn),
	}, nil
}
