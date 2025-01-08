package iamruntime

import (
	"context"
	"fmt"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func ExampleNewClient() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	resp, _ := runtime.ValidateCredential(context.TODO(), &authentication.ValidateCredentialRequest{
		Credential: "some credential",
	})

	fmt.Println("Result:", resp.Result.String())
	fmt.Println("Subject:", resp.Subject.SubjectId)
}

func ExampleNewClientWithoutWait() {
	runtime, _ := NewClientWithoutWait("unix:///tmp/runtime.sock")

	if err := runtime.WaitHealthy(context.Background(), &grpc_health_v1.HealthCheckRequest{}); err != nil {
		panic(err)
	}

	resp, _ := runtime.ValidateCredential(context.TODO(), &authentication.ValidateCredentialRequest{
		Credential: "some credential",
	})

	fmt.Println("Result:", resp.Result.String())
	fmt.Println("Subject:", resp.Subject.SubjectId)
}
