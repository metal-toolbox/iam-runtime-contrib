package mockruntime

import (
	"context"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"google.golang.org/grpc"
)

// CheckAccess mocks iam-runtime authorization.CheckAccess
func (r *MockRuntime) CheckAccess(_ context.Context, in *authorization.CheckAccessRequest, _ ...grpc.CallOption) (*authorization.CheckAccessResponse, error) {
	actions := make(map[string][]string)

	for _, request := range in.Actions {
		actions[request.ResourceId] = append(actions[request.ResourceId], request.Action)
	}

	args := r.Mock.Called(actions)

	if err := args.Error(1); err != nil {
		return nil, err
	}

	result := args.Get(0).(authorization.CheckAccessResponse_Result)

	return &authorization.CheckAccessResponse{Result: result}, nil
}

// CreateRelationships mocks iam-runtime authorization.CreateRelationships
func (r *MockRuntime) CreateRelationships(_ context.Context, in *authorization.CreateRelationshipsRequest, _ ...grpc.CallOption) (*authorization.CreateRelationshipsResponse, error) {
	relations := make(map[string][]string)

	for _, rel := range in.Relationships {
		relations[rel.Relation] = append(relations[rel.Relation], rel.SubjectId)
	}

	args := r.Mock.Called(in.ResourceId, relations)

	if err := args.Error(0); err != nil {
		return nil, err
	}

	return &authorization.CreateRelationshipsResponse{}, nil
}

// DeleteRelationships mocks iam-runtime authorization.DeleteRelationships
func (r *MockRuntime) DeleteRelationships(_ context.Context, in *authorization.DeleteRelationshipsRequest, _ ...grpc.CallOption) (*authorization.DeleteRelationshipsResponse, error) {
	relations := make(map[string][]string)

	for _, rel := range in.Relationships {
		relations[rel.Relation] = append(relations[rel.Relation], rel.SubjectId)
	}

	args := r.Mock.Called(in.ResourceId, relations)

	if err := args.Error(0); err != nil {
		return nil, err
	}

	return &authorization.DeleteRelationshipsResponse{}, nil
}
