package iamruntimemiddleware

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
)

// ToMiddleware builds a new echo middleware function from the defined config.
// If no runtime client is defined, a default one is initialized.
// The default runtime will use the configured Socket path to connect to the runtime server.
// If no Socket is provided, the default socket path is used (/tmp/runtime.sock)
func (c Config) ToMiddleware() (echo.MiddlewareFunc, error) {
	if c.Skipper == nil {
		c.Skipper = middleware.DefaultSkipper
	}

	c.runtime = c.Runtime

	if c.Runtime == nil {
		if c.Socket == "" {
			c.Socket = defaultRuntimePath
		}

		runtime, err := iamruntime.NewClient(c.Socket)
		if err != nil {
			return nil, err
		}

		c.runtime = runtime
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			if c.Skipper(ctx) {
				return next(ctx)
			}

			if err := setRuntimeContext(c.runtime, ctx); err != nil {
				ctx.Error(err)

				return err
			}

			if err := setAuthenticationContext(ctx); err != nil {
				ctx.Error(err)

				return err
			}

			return next(ctx)
		}
	}, nil
}
