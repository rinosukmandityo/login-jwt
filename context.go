package login

import (
	"context"
)

type (
	// jwtClaimsContextKey is a special type used as a key for accessing jwt claims in a context.
	jwtClaimsContextKey struct{}
	// jwtTokenContextKey is a special type used as a key for accessing jwt token in a context.
	jwtTokenContextKey struct{}
)

// SetClaimsToContext set jwt claim to context
func SetClaimsToContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, jwtClaimsContextKey{}, claims)
}

// GetClaimsFromContext get jwt claim from context
func GetClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(jwtClaimsContextKey{}).(*Claims)

	return claims
}

// SetTokenToContext set jwt token to context
func SetTokenToContext(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, jwtTokenContextKey{}, token)
}

// GetTokenFromContext get jwt token from context
func GetTokenFromContext(ctx context.Context) string {
	claims, _ := ctx.Value(jwtTokenContextKey{}).(string)

	return claims
}
