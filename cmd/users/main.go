package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"github.com/rinosukmandityo/login-jwt/internal/api"
	"github.com/rinosukmandityo/login-jwt/internal/auth"
	"github.com/rinosukmandityo/login-jwt/internal/repo/memory"
)

const (
	serverPort = "8080"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	router := mux.NewRouter()
	ctx := context.Background()
	secretKey := os.Getenv("jwt_secret")
	if secretKey == "" {
		secretKey = "secretkey"
	}

	repo := memory.NewUserRepository()
	svc := auth.NewService(
		*logger,
		repo,
		time.Minute*5,
		secretKey,
	)

	// attach user http routes.
	api.AttachUserHandler(
		ctx,
		router,
		svc,
	)

	logger.Println("server started at", fmt.Sprintf("localhost:%s", serverPort))
	http.ListenAndServe(fmt.Sprintf(":%s", serverPort), router)
}
