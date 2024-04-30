package internal

type (
	runtimeCtxKey struct{}
	tokenCtxKey   struct{}
	subjectCtxKey struct{}
)

var (
	// RuntimeCtxKey is the context key used to retrieve the iam-runtime from the context.
	RuntimeCtxKey = runtimeCtxKey{}

	// TokenCtxKey is the context key used to retrieve the decoded jwt token from a context.
	TokenCtxKey = tokenCtxKey{}

	// SubjectCtxKey is the context key used to retrieve just the subject from a context.
	SubjectCtxKey = subjectCtxKey{}
)
