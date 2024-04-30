package internal

import (
	"errors"
	"net/http"
	"strings"
)

// ErrInvalidAuthToken is the error returned when the auth token is not the expected value.
var ErrInvalidAuthToken = errors.New("invalid auth token")

const (
	authHeader   = "Authorization"
	bearerPrefix = "Bearer "
)

// GetBearerToken parses the Authorization header returning just the Bearer token without the Bearer prefix.
func GetBearerToken(req *http.Request) (string, error) {
	authHeader := strings.TrimSpace(req.Header.Get(authHeader))

	if len(authHeader) <= len(bearerPrefix) {
		return "", ErrInvalidAuthToken
	}

	if !strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
		return "", ErrInvalidAuthToken
	}

	token := authHeader[len(bearerPrefix):]

	return token, nil
}
