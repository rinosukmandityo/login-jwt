package api

import (
	"context"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	lg "github.com/rinosukmandityo/login-jwt"
	"github.com/rinosukmandityo/login-jwt/internal/api/auth"
	"github.com/rinosukmandityo/login-jwt/internal/api/httputil"
	"github.com/rinosukmandityo/login-jwt/internal/api/user"
)

// AttachAuthRouter attach Auth API handler.
func AttachAuthHandler(
	ctx context.Context,
	r *mux.Router,
	svc lg.AuthService,
	logger log.Logger,
	isHTTPOnly bool,
	sameSiteMode http.SameSite,
	cookiePath string,
) {
	r.Methods(http.MethodPost).Path("/api/auth/login").
		HandlerFunc(auth.LoginHandler(ctx, logger, svc, isHTTPOnly, sameSiteMode, cookiePath))

	// create sub router for handler that needs auth middleware
	sub := r.PathPrefix("/api/auth").Subrouter()
	sub.Use(httputil.ExtractJWT, httputil.WithAuthMiddleware(svc))
	sub.Methods(http.MethodGet).Path("/validate").HandlerFunc(auth.ValidateHandler(ctx, svc))
	sub.Methods(http.MethodPost).Path("/refresh").
		HandlerFunc(auth.RefreshHandler(ctx, logger, svc, isHTTPOnly, sameSiteMode, cookiePath))
	sub.Methods(http.MethodPost).Path("/logout").HandlerFunc(auth.LogoutHandler(ctx, svc))
}

// AttachUserHandler attach User API handler.
func AttachUserHandler(
	ctx context.Context,
	r *mux.Router,
	svc lg.AuthService,
) {
	// create sub router for handler that needs auth middleware
	sub := r.PathPrefix("/api/users").Subrouter()
	sub.Use(httputil.ExtractJWT, httputil.WithAuthMiddleware(svc))
	sub.Methods(http.MethodPost).Path("").HandlerFunc(user.AddUserHandler(ctx))
	sub.Methods(http.MethodGet).Path("/{email}").HandlerFunc(user.GetUserHandler(ctx))
	sub.Methods(http.MethodPut).Path("/{email}").HandlerFunc(user.UpdateUserHandler(ctx))
	sub.Methods(http.MethodDelete).Path("/{email}").HandlerFunc(user.DeleteUserHandler(ctx))
}
