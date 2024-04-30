package iamruntimemiddleware

import (
	"github.com/labstack/echo/v4/middleware"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
)

const defaultRuntimePath = "/tmp/runtime.sock"

// Runtime defines the required methods for a supported runtime.
type Runtime interface {
	authentication.AuthenticationClient
	authorization.AuthorizationClient
}

// Config defines configuration for the iam-runtime middleware.
// Build the echo middleware by calling [Config.ToMiddleware]()
type Config struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper

	// Socket defines the iam runtime socket path.
	// Default is /tmp/runtime.sock
	// Not used if Runtime is defined.
	Socket string

	// Runtime specifies the middleware will use.
	// If no runtime is provided, a new runtime client is created using the Socket path.
	Runtime Runtime

	runtime Runtime
}

// WithSkipper returns a new [Config] with the provided skipper set.
func (c Config) WithSkipper(value middleware.Skipper) Config {
	c.Skipper = value

	return c
}

// WithSocket returns a new [Config] with the provided socket set.
func (c Config) WithSocket(value string) Config {
	c.Socket = value

	return c
}

// WithRuntime returns a new [Config] with the provided runtime set.
func (c Config) WithRuntime(value Runtime) Config {
	c.Runtime = value

	return c
}

// NewConfig returns a new empty config.
func NewConfig() Config {
	return Config{}
}
