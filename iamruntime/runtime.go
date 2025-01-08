package iamruntime

import (
	"context"
	"os"
	"time"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
)

const defaultNewClientWaitTimeout = 10 * time.Second

func newClientWaitTimeout() time.Duration {
	if sTimeout := os.Getenv("IAMRUNTIME_NEW_CLIENT_WAIT_TIMEOUT"); sTimeout != "" {
		if timeout, err := time.ParseDuration(sTimeout); err == nil {
			return timeout
		}
	}

	return defaultNewClientWaitTimeout
}

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

	health.HealthClient
	healthyInterval time.Duration
}

// NewClientWithoutWait creates a new iam-runtime which implements all clients.
//
// See [NewClient] for more details.
func NewClientWithoutWait(target string, dialOpts ...grpc.DialOption) (HealthyRuntime, error) {
	dialOpts = append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}, dialOpts...)

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, err
	}

	return &runtime{
		AuthorizationClient:  authorization.NewAuthorizationClient(conn),
		AuthenticationClient: authentication.NewAuthenticationClient(conn),
		IdentityClient:       identity.NewIdentityClient(conn),
		HealthClient:         health.NewHealthClient(conn),
		healthyInterval:      time.Second,
	}, nil
}

// NewClient creates a new iam-runtime which implements all clients.
//
// NewClient blocks for up to 10 seconds waiting for a healthy runtime server response.
// If no healthy response is found within this period, an error is returned.
// Use [runtime.WaitHealthyWithTimeout] after creating a new client to use a configurable timeout.
//
// Use [NewClientWithoutWait] to initialize a new runtime without waiting for the service to report healthy.
//
// Alter the new client wait timeout with setting `IAMRUNTIME_NEW_CLIENT_WAIT_TIMEOUT` environment variable.
// A value of 0 or less will disable waiting.
//
// GRPC Insecure transport credentials are configured by default.
// This may be overwritten by providing an alternative TransportCredentials dial option.
func NewClient(target string, dialOpts ...grpc.DialOption) (HealthyRuntime, error) {
	runtime, err := NewClientWithoutWait(target, dialOpts...)
	if err != nil {
		return nil, err
	}

	if timeout := newClientWaitTimeout(); timeout > 0 {
		err = runtime.WaitHealthyWithTimeout(context.Background(), timeout, &health.HealthCheckRequest{})
		if err != nil {
			return nil, err
		}
	}

	return runtime, nil
}
