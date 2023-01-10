package user

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rinosukmandityo/login-jwt/internal/api/httputil"
)

// AddUserHandler is a handler for add user request.
func AddUserHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("add user handler")

		httputil.EncodeResponse(ctx, w, http.StatusNoContent, nil)
	}
}

// GetUserHandler is a handler for get user request.
func GetUserHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		httputil.EncodeResponse(ctx, w, http.StatusOK, map[string]interface{}{"email": vars["email"]})
	}
}

// UpdateUserHandler is a handler for update user request.
func UpdateUserHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httputil.EncodeResponse(ctx, w, http.StatusOK, nil)
	}
}

// DeleteUserHandler is a handler for delete user request.
func DeleteUserHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httputil.EncodeResponse(ctx, w, http.StatusOK, nil)
	}
}
