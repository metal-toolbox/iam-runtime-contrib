package iamruntime

import (
	"context"
	"fmt"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"google.golang.org/grpc"
)

// ContextValidateCredential executes a credential validation request on the runtime in the context.
// Context must have a runtime value.
// The runtime must implement the iam-runtime's AuthenticationClient.
// Use [SetContextRuntime] to set this value.
func ContextValidateCredential(ctx context.Context, in *authentication.ValidateCredentialRequest, opts ...grpc.CallOption) error {
	runtime := ContextRuntimeAuthenticationClient(ctx)
	if runtime == nil {
		return ErrRuntimeNotFound
	}

	resp, err := runtime.ValidateCredential(ctx, in, opts...)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialValidationRequestFailed, err)
	}

	if resp.Result == authentication.ValidateCredentialResponse_RESULT_INVALID {
		return ErrInvalidCredentials
	}

	return nil
}
