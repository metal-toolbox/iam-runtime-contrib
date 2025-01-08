package iamruntime

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// HealthyRuntime extends [Runtime] adding grpc Health Client.
type HealthyRuntime interface {
	Runtime

	// HealthCheck calls the health service Check call.
	HealthCheck(ctx context.Context, in *health.HealthCheckRequest, opts ...grpc.CallOption) (*health.HealthCheckResponse, error)

	// HealthWatch calls the health service Watch call.
	HealthWatch(ctx context.Context, in *health.HealthCheckRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[health.HealthCheckResponse], error)

	// WaitHealthy calls the health service check waiting for a SERVING status.
	// If the backend returns an unimplemented status code, no error is returned.
	WaitHealthy(ctx context.Context, in *health.HealthCheckRequest, opts ...grpc.CallOption) error

	// WaitHealthyWithTimeout calls WaitHealthy with a timeout.
	// [ErrHealthCheckTimedout] is returned if a healthy response is not received within the provided timeout.
	WaitHealthyWithTimeout(ctx context.Context, timeout time.Duration, in *health.HealthCheckRequest, opts ...grpc.CallOption) error
}

// HealthCheck calls the health service Check call.
func (r *runtime) HealthCheck(ctx context.Context, in *health.HealthCheckRequest, opts ...grpc.CallOption) (*health.HealthCheckResponse, error) {
	return r.HealthClient.Check(ctx, in, opts...)
}

// HealthWatch calls the health service Watch call.
func (r *runtime) HealthWatch(ctx context.Context, in *health.HealthCheckRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[health.HealthCheckResponse], error) {
	return r.HealthClient.Watch(ctx, in, opts...)
}

// healthy returns true when a successful serving response is received from the runtime.
func (r *runtime) healthy(ctx context.Context, in *health.HealthCheckRequest, opts ...grpc.CallOption) error {
	resp, err := r.HealthCheck(ctx, in, opts...)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil
		}

		return fmt.Errorf("%w: health check error: %w", ErrNotReady, err)
	}

	if resp.Status == health.HealthCheckResponse_SERVING {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrNotReady, resp.Status)
}

// WaitHealthy calls the health service check waiting for a SERVING status.
// If the backend returns an unimplemented status code, no error is returned.
func (r *runtime) WaitHealthy(ctx context.Context, in *health.HealthCheckRequest, opts ...grpc.CallOption) error {
	ticker := time.NewTicker(r.healthyInterval)
	defer ticker.Stop()

	err := r.healthy(ctx, in, opts...)
	if err == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", err, ctx.Err())
		case <-ticker.C:
			err = r.healthy(ctx, in, opts...)
			if err == nil {
				return nil
			}
		}
	}
}

// WaitHealthyWithTimeout calls WaitHealthy with a timeout.
func (r *runtime) WaitHealthyWithTimeout(ctx context.Context, timeout time.Duration, in *health.HealthCheckRequest, opts ...grpc.CallOption) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return r.WaitHealthy(ctx, in, opts...)
}
