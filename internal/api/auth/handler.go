package auth

import (
	"context"
	"log"
	"net/http"

	lg "github.com/rinosukmandityo/login-jwt"
	"github.com/rinosukmandityo/login-jwt/internal/api/httputil"
)

const totalSecondsInYear = 3600 * 24 * 365

type loginUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type refreshResponse struct {
	Token string `json:"token"`
}

// LoginHandler is a handler for login request.
func LoginHandler(
	ctx context.Context,
	logger log.Logger,
	svc lg.AuthService,
	isHTTPOnly bool,
	sameSiteMode http.SameSite,
	cookiePath string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loginReq, err := decodeLoginRequest(logger, r)
		if err != nil {
			httputil.EncodeErrorResp(w, err)

			return
		}

		ctx = r.Context()
		claims, err := svc.LoginUser(ctx, loginReq)
		// to avoid enumeration, we throw our user not found and password error in the same error messages
		// this also cover user that not linked to any organization
		if lg.IsErrorCode(err, lg.ErrNotFound) || lg.IsErrorCode(err, lg.ErrUnauthorized) {
			httputil.EncodeErrorResp(w, err)

			return
		} else if err != nil {
			httputil.EncodeErrorResp(w, err)

			return
		}

		token, err := svc.BuildJWT(ctx, claims)
		if err != nil {
			httputil.EncodeErrorResp(w, err)

			return
		}

		// set cookie
		cookie := &http.Cookie{
			Name:     httputil.CookiesAuthToken,
			MaxAge:   totalSecondsInYear,
			Value:    token,
			HttpOnly: isHTTPOnly,
			Secure:   true,
			SameSite: sameSiteMode,
			Path:     cookiePath,
		}
		http.SetCookie(w, cookie)

		// set json response
		jsonResp := loginResponse{
			Token: token,
		}

		httputil.EncodeResponse(ctx, w, http.StatusOK, jsonResp)
	}
}

// ValidateHandler is a handler for validate request.
func ValidateHandler(ctx context.Context, svc lg.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		valid, err := svc.ValidateToken(ctx)
		if err != nil || !valid {
			httputil.EncodeErrorResp(w, err)

			return
		}

		httputil.EncodeResponse(ctx, w, http.StatusOK, map[string]bool{"valid": true})
	}
}

// RefreshHandler is a handler for refresh token request.
func RefreshHandler(
	ctx context.Context,
	logger log.Logger,
	svc lg.AuthService,
	isHTTPOnly bool,
	sameSiteMode http.SameSite,
	cookiePath string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		claims, err := svc.RefreshToken(ctx)
		if err != nil {
			httputil.EncodeErrorResp(w, err)

			return
		}

		refreshToken, err := svc.BuildJWT(ctx, claims)
		if err != nil {
			httputil.EncodeErrorResp(w, err)

			return
		}

		// set cookie
		cookie := &http.Cookie{
			Name:     httputil.CookiesAuthToken,
			MaxAge:   totalSecondsInYear,
			Value:    lg.GetTokenFromContext(ctx),
			HttpOnly: isHTTPOnly,
			Secure:   true,
			SameSite: sameSiteMode,
			Path:     cookiePath,
		}
		http.SetCookie(w, cookie)

		// set json response
		jsonResp := refreshResponse{
			Token: refreshToken,
		}

		httputil.EncodeResponse(ctx, w, http.StatusOK, jsonResp)
	}
}

// LogoutHandler is a handler for logout request.
func LogoutHandler(
	ctx context.Context,
	svc lg.AuthService,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		if err := svc.Logout(ctx); err != nil {
			httputil.EncodeErrorResp(w, err)

			return
		}

		httputil.EncodeResponse(ctx, w, http.StatusOK, nil)
	}
}
