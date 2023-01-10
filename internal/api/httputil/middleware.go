package httputil

import (
	"fmt"
	"net/http"
	"strings"

	lg "github.com/rinosukmandityo/login-jwt"
)

// ExtractJWTString is a helper that extracts jwt token from HTTP header
func ExtractJWTString(r *http.Request) (string, error) {
	jwtToken := r.Header.Get(HTTPHeaderAuthorization)

	// the format is Bearer <jwt_token>, so we need to split it by "Bearer "
	splitter := "Bearer "
	if jwtToken == "" {
		tokenCookie, err := r.Cookie(CookiesAuthToken)
		if err != nil {
			return "", err
		}
		jwtToken = tokenCookie.String()
		if jwtToken == "" {
			return "", lg.ErrTokenNotFound
		}
		// the format is kg_jwt=<jwt_token>, so we need to split it by "kg_jwt" cookies key
		splitter = fmt.Sprintf("%s=", CookiesAuthToken)
	}

	splitToken := strings.SplitN(jwtToken, splitter, 2)
	if len(splitToken) < 2 {
		return "", lg.ErrTokenNotFound
	}

	return splitToken[1], nil
}

// ExtractJWT is a middleware that extracts jwt token from HTTP header
// and stores it in a context.
func ExtractJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := ExtractJWTString(r)
		if err != nil {
			EncodeErrorResp(w, err)

			return
		}
		r = r.WithContext(lg.SetTokenToContext(r.Context(), token))

		next.ServeHTTP(w, r)
	})
}

// WithAuthMiddleware provides authentication using JWT.
func WithAuthMiddleware(authSvc lg.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := lg.GetTokenFromContext(r.Context())
			if token == "" {
				EncodeErrorResp(w, lg.ErrTokenNotFound)

				return
			}

			var claims *lg.Claims
			claims, err := authSvc.ParseToken(r.Context(), token)
			if err != nil {
				EncodeErrorResp(w, err)

				return
			}
			r = r.WithContext(lg.SetClaimsToContext(r.Context(), claims))

			next.ServeHTTP(w, r)
		})
	}
}
