package iamruntime

import (
	"context"
	"fmt"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
)

func ExampleNewClient() {
	runtime, _ := NewClient("unix:///tmp/runtime.sock")

	resp, _ := runtime.ValidateCredential(context.TODO(), &authentication.ValidateCredentialRequest{
		Credential: "some credential",
	})

	fmt.Println("Result:", resp.Result.String())
	fmt.Println("Subject:", resp.Subject.SubjectId)
}
