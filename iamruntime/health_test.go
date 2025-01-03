package iamruntime

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

var _ grpc_health_v1.HealthClient = (*mockHealthClient)(nil)

type mockHealthClient struct {
	mu sync.Mutex

	checkCalled bool
	watchCalled bool

	checkReturnResponse *grpc_health_v1.HealthCheckResponse
	checkReturnError    error
}

func (c *mockHealthClient) setCheckReturn(response *grpc_health_v1.HealthCheckResponse, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.checkReturnResponse = response
	c.checkReturnError = err
}

// Check implements a mock HealthClient Check.
func (c *mockHealthClient) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest, _ ...grpc.CallOption) (*grpc_health_v1.HealthCheckResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.checkCalled = true

	return c.checkReturnResponse, c.checkReturnError
}

// Watch implements a mock HealthClient Watch.
func (c *mockHealthClient) Watch(_ context.Context, _ *grpc_health_v1.HealthCheckRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[grpc_health_v1.HealthCheckResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.watchCalled = true

	return nil, status.Error(codes.Unimplemented, "method Watch not implemented")
}

func TestHealthy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		checkResponse *grpc_health_v1.HealthCheckResponse
		checkError    error
		expectError   error
	}{
		{
			"healthy",
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_SERVING,
			},
			nil,
			nil,
		},
		{
			"unhealthy: not serving",
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			},
			nil,
			ErrNotReady,
		},
		{
			"unhealthy: error",
			nil,
			grpc.ErrServerStopped,
			ErrNotReady,
		},
		{
			"healthy: unimplemented",
			nil,
			status.Error(codes.Unimplemented, "method Check not implemented"),
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockHealth := &mockHealthClient{
				checkReturnResponse: tc.checkResponse,
				checkReturnError:    tc.checkError,
			}

			runtime := &runtime{
				HealthClient: mockHealth,
			}

			ctx := context.Background()

			err := runtime.healthy(ctx, &grpc_health_v1.HealthCheckRequest{})

			if tc.expectError != nil {
				require.Error(t, err, "expected error to be returned")
				assert.ErrorIs(t, err, tc.expectError, "unexpected error returned")
			} else {
				assert.NoError(t, err, "expected no error to be returned")
			}

			assert.True(t, mockHealth.checkCalled, "expected Check to be called")
			assert.False(t, mockHealth.watchCalled, "expected Watch to not be called")
		})
	}
}

func TestWaitHealthy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		startupDelay  time.Duration
		checkResponse *grpc_health_v1.HealthCheckResponse
		checkError    error
		expectErrors  []error
	}{
		{
			"healthy",
			0,
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_SERVING,
			},
			nil,
			nil,
		},
		{
			"healthy delayed",
			20 * time.Millisecond,
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_SERVING,
			},
			nil,
			nil,
		},
		{
			"unhealthy: not serving: context canceled",
			0,
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			},
			nil,
			[]error{
				context.DeadlineExceeded,
				ErrNotReady,
			},
		},
		{
			"unhealthy: error: context canceled",
			20 * time.Millisecond,
			nil,
			grpc.ErrServerStopped,
			[]error{
				context.DeadlineExceeded,
				ErrNotReady,
				grpc.ErrServerStopped,
			},
		},
		{
			"healthy: unimplemented",
			20 * time.Millisecond,
			nil,
			status.Error(codes.Unimplemented, "method Check not implemented"),
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockHealth := &mockHealthClient{}

			runtime := &runtime{
				HealthClient:    mockHealth,
				healthyInterval: time.Millisecond,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			if tc.startupDelay != 0 {
				mockHealth.checkReturnError = io.ErrUnexpectedEOF

				defer time.AfterFunc(tc.startupDelay, func() {
					mockHealth.setCheckReturn(tc.checkResponse, tc.checkError)
				}).Stop()
			} else {
				mockHealth.checkReturnResponse = tc.checkResponse
				mockHealth.checkReturnError = tc.checkError
			}

			err := runtime.WaitHealthy(ctx, &grpc_health_v1.HealthCheckRequest{})

			if len(tc.expectErrors) != 0 {
				require.Error(t, err, "expected error to be returned")

				for _, expectError := range tc.expectErrors {
					assert.ErrorIs(t, err, expectError, "unexpected error returned")
				}
			} else {
				assert.NoError(t, err, "expected no error to be returned")
			}

			assert.True(t, mockHealth.checkCalled, "expected Check to be called")
			assert.False(t, mockHealth.watchCalled, "expected Watch to not be called")
		})
	}
}

func TestWaitHealthyWithTimeout(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		startupDelay  time.Duration
		checkResponse *grpc_health_v1.HealthCheckResponse
		checkError    error
		expectErrors  []error
	}{
		{
			"healthy",
			0,
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_SERVING,
			},
			nil,
			nil,
		},
		{
			"healthy delayed",
			20 * time.Millisecond,
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_SERVING,
			},
			nil,
			nil,
		},
		{
			"unhealthy: not serving: timed out",
			0,
			&grpc_health_v1.HealthCheckResponse{
				Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			},
			nil,
			[]error{
				context.DeadlineExceeded,
				ErrNotReady,
			},
		},
		{
			"unhealthy: error: timed out",
			20 * time.Millisecond,
			nil,
			grpc.ErrServerStopped,
			[]error{
				context.DeadlineExceeded,
				ErrNotReady,
				grpc.ErrServerStopped,
			},
		},
		{
			"healthy: unimplemented",
			20 * time.Millisecond,
			nil,
			status.Error(codes.Unimplemented, "method Check not implemented"),
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockHealth := &mockHealthClient{}

			runtime := &runtime{
				HealthClient:    mockHealth,
				healthyInterval: time.Millisecond,
			}

			// ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			// defer cancel()

			ctx := context.Background()

			if tc.startupDelay != 0 {
				mockHealth.checkReturnError = io.ErrUnexpectedEOF

				defer time.AfterFunc(tc.startupDelay, func() {
					mockHealth.setCheckReturn(tc.checkResponse, tc.checkError)
				}).Stop()
			} else {
				mockHealth.checkReturnResponse = tc.checkResponse
				mockHealth.checkReturnError = tc.checkError
			}

			err := runtime.WaitHealthyWithTimeout(ctx, 100*time.Millisecond, &grpc_health_v1.HealthCheckRequest{})

			if len(tc.expectErrors) != 0 {
				require.Error(t, err, "expected error to be returned")

				for _, expectError := range tc.expectErrors {
					assert.ErrorIs(t, err, expectError, "unexpected error returned")
				}
			} else {
				assert.NoError(t, err, "expected no error to be returned")
			}

			assert.True(t, mockHealth.checkCalled, "expected Check to be called")
			assert.False(t, mockHealth.watchCalled, "expected Watch to not be called")
		})
	}
}

func ExampleHealthyRuntime_HealthCheck() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	health, err := runtime.HealthCheck(context.TODO(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		panic("health check failed: " + err.Error())
	}

	fmt.Println("Health status:", health.Status)
}

func ExampleHealthyRuntime_WaitHealthy() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	err := runtime.WaitHealthy(context.TODO(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		panic("health check failed: " + err.Error())
	}

	// use healthy runtime
}

func ExampleHealthyRuntime_WaitHealthyWithTimeout() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	err := runtime.WaitHealthyWithTimeout(context.TODO(), time.Minute, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		panic("health check failed: " + err.Error())
	}

	// use healthy runtime
}
