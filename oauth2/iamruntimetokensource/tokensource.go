// Package iamruntimetokensource implements oauth2.TokenSource for iam-runtime identity access token.
package iamruntimetokensource

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"
	"golang.org/x/oauth2"

	"github.com/metal-toolbox/iam-runtime-contrib/iamruntime"
)

// TokenSource handles token exchanges by taking an upstream token
// and exchanging it with an token issuer and returning the new token.
type TokenSource struct {
	ctx     context.Context
	runtime identity.IdentityClient
	token   *oauth2.Token
	mu      sync.Mutex
}

// Token requests an access token from the configured runtime.
// Tokens are reused as long as they are valid.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token.Valid() {
		return s.token, nil
	}

	resp, err := s.runtime.GetAccessToken(s.ctx, &identity.GetAccessTokenRequest{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", iamruntime.ErrIdentityTokenRequestFailed, err)
	}

	token, _, err := jwt.NewParser().ParseUnverified(resp.Token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", iamruntime.ErrAccessTokenInvalid, err)
	}

	expiry, err := token.Claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", iamruntime.ErrAccessTokenInvalid, err)
	}

	var expiryTime time.Time

	if expiry != nil {
		expiryTime = expiry.Time
	}

	s.token = &oauth2.Token{
		AccessToken: resp.Token,
		TokenType:   "Bearer",
		Expiry:      expiryTime,
	}

	return s.token, nil
}

// NewTokenSource creates a new TokenSource using the provided upstream token source and runtime to generate new tokens.
func NewTokenSource(ctx context.Context, runtime identity.IdentityClient) (*TokenSource, error) {
	return &TokenSource{
		ctx:     ctx,
		runtime: runtime,
	}, nil
}
