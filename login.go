package login

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/oklog/ulid/v2"
)

// Claims the representation of JWT Claims
type Claims struct {
	// current user id.
	UserID string `json:"user_id"`
	// a structured version of the JWT Claims Set.
	jwt.RegisteredClaims
}

// Issue issues claims by filling RegisteredClaims
func (c *Claims) Issue(now time.Time, sessionTTL time.Duration, claimID string) *Claims {
	return &Claims{
		UserID: c.UserID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        claimID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTTL)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "login_jwt",
		},
	}
}

// LoginUserRequest login request
type LoginUserRequest struct {
	Email    string
	Password string
}

// AuthService auth service.
//
//go:generate moq -out ./internal/mock/auth_service.go -pkg mock -fmt goimports . AuthService
type AuthService interface {
	// LoginUser logins the user using creds provided to get back a token
	LoginUser(ctx context.Context, req *LoginUserRequest) (*Claims, error)
	// ValidateToken validates JWT token string. This method is a part of auth service.
	// it will be called before we call login endpoint, usually when we load a page
	// to check whether the jwt is still valid or not.
	ValidateToken(ctx context.Context) (bool, error)
	// ParseToken parses JWT token string into claims.
	// This method runs within each service which needs an auth.
	// It works as a HTTP middleware, parses, and decodes jwt token into Claims
	ParseToken(ctx context.Context, token string) (*Claims, error)
	// BuildJWT build a new jwt token string from claims
	BuildJWT(ctx context.Context, claims *Claims) (token string, err error)
	// RefreshToken validates current token then extends its expiration time
	RefreshToken(ctx context.Context) (*Claims, error)
	// Logout removes token from cache
	Logout(ctx context.Context) error
}

// UserRepository repo for user.
//
//go:generate moq -out ./internal/mock/user_repo.go -pkg mock -fmt goimports . UserRepository
type UserRepository interface {
	// FindByEmail finds user by email for login
	FindByEmail(ctx context.Context, email string) (*User, error)
}

// User is user entity in Login account
type User struct {
	ID                ulid.ULID // user ID. ulid
	CreatedAt         time.Time // entity creation timestamp
	UpdatedAt         time.Time // entity update timestamp
	IsDeleted         bool      // flag for soft deletion
	FirstName         string    // user first name
	LastName          string    // user last name
	Email             string    // user email address
	PasswordHash      string    // Password hash. We use bcrypt algorithm with cost 10
	PasswordUpdatedAt time.Time // Time when password was last set
}
