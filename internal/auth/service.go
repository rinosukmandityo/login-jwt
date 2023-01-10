package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"

	lg "github.com/rinosukmandityo/login-jwt"
	"github.com/rinosukmandityo/login-jwt/internal"
)

const (
	// a cache key for auth token, the format will be kg:auth:token:<token_claim_id>
	// this key used for storing the claim ID and checking whether particular token is valid or not
	// the data stored example will be: kg:auth:token:claim_id_1, kg:auth:token:claim_id_2, so on
	// the key will be removed if the key is expired
	authTokenKey = "kg:auth:token:%s"
)

// Service is a kg.AuthService implementation
type Service struct {
	logger         log.Logger
	userRepo       lg.UserRepository
	cacheRepo      map[string]bool
	userSessionTTL time.Duration // TTL for single user session
	jwtSecret      string
}

// NewService created new auth instance
func NewService(
	logger log.Logger,
	userRepo lg.UserRepository,
	userSessionTTL time.Duration,
	jwtSecret string,
) *Service {
	svc := &Service{
		logger:         logger,
		userRepo:       userRepo,
		cacheRepo:      make(map[string]bool),
		userSessionTTL: userSessionTTL,
		jwtSecret:      jwtSecret,
	}

	return svc
}

// LoginUser logins the user using creds provided to get back a token
func (s *Service) LoginUser(ctx context.Context, req *lg.LoginUserRequest) (*lg.Claims, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	// compare hashed password with password from client request
	if err = internal.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		return nil, err
	}

	claims := &lg.Claims{
		UserID: user.ID.String(),
	}
	claims = claims.Issue(time.Now(), s.userSessionTTL, internal.GenerateULID().String())

	return claims, nil
}

// ValidateToken validates JWT token string. This method is a part of auth service.
// it will be called before we call login endpoint, usually when we load a page
// to check whether the jwt is still valid or not.
func (s *Service) ValidateToken(ctx context.Context) (bool, error) {
	claims := lg.GetClaimsFromContext(ctx)

	// validate token in cache
	key := fmt.Sprintf(authTokenKey, claims.ID)
	if !s.isSessionExists(key) {
		return false, lg.ErrTokenNotFound
	}

	return true, nil
}

// ParseToken parses JWT token string into claims.
// This method runs within each service which needs an auth.
// It works as a HTTP middleware, parses, and decodes jwt token into Claims
func (s *Service) ParseToken(ctx context.Context, token string) (*lg.Claims, error) {
	claims, err := s.parseTokenToClaims(ctx, token)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// BuildJWT build a new jwt token string from claims
func (s *Service) BuildJWT(ctx context.Context, claims *lg.Claims) (string, error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := jwtToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", err
	}

	// store claims ID in cache
	key := fmt.Sprintf(authTokenKey, claims.ID)
	s.cacheRepo[key] = true

	return token, nil
}

// RefreshToken validates current token then extends its expiration time
func (s *Service) RefreshToken(ctx context.Context) (*lg.Claims, error) {
	claims := lg.GetClaimsFromContext(ctx)
	if err := s.revokeToken(ctx, claims); err != nil {
		return nil, err
	}

	// create a new claims based on previous claims
	refreshClaims := createRefreshClaims(claims, s.userSessionTTL)

	return refreshClaims, nil
}

// revokeToken revokes token from cache
func (s *Service) revokeToken(ctx context.Context, claims *lg.Claims) error {
	key := fmt.Sprintf(authTokenKey, claims.ID)
	// remove current active session
	if !s.isSessionExists(key) {
		return lg.ErrTokenNotFound
	}
	delete(s.cacheRepo, key)

	return nil
}

// Logout removes token from cache
func (s *Service) Logout(ctx context.Context) error {
	return s.revokeToken(ctx, lg.GetClaimsFromContext(ctx))
}

func (s *Service) parseTokenToClaims(ctx context.Context, tokenStr string) (*lg.Claims, error) {
	claims := new(lg.Claims)
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, lg.ErrTokenSignatureInvalid
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			delete(s.cacheRepo, fmt.Sprintf(authTokenKey, claims.ID))

			return nil, lg.ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, lg.ErrTokenInvalid
		}

		return nil, lg.Error{
			Code:    lg.ErrUnauthorized,
			Message: err.Error(),
		}
	}

	return claims, nil
}

func (s *Service) isSessionExists(sessKey string) bool {
	if _, ok := s.cacheRepo[sessKey]; !ok {
		return false
	}

	return true
}

// createRefreshClaims creates a new claims based on previous claims, with different claims ID and the time data
func createRefreshClaims(c *lg.Claims, extendedPeriod time.Duration) *lg.Claims {
	tNow := time.Now().UTC()

	return &lg.Claims{
		UserID: c.UserID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        internal.GenerateULID().String(),
			IssuedAt:  jwt.NewNumericDate(tNow),
			ExpiresAt: jwt.NewNumericDate(tNow.Add(extendedPeriod)),
			NotBefore: jwt.NewNumericDate(tNow),
			Issuer:    c.Issuer,
		},
	}
}
