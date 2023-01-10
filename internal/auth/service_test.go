package auth_test

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	lg "github.com/rinosukmandityo/login-jwt"
	"github.com/rinosukmandityo/login-jwt/internal"
	"github.com/rinosukmandityo/login-jwt/internal/auth"
	"github.com/rinosukmandityo/login-jwt/internal/mock"
	"golang.org/x/crypto/bcrypt"
)

const (
	secretKey    = "super_secret_key"
	passwordCost = bcrypt.DefaultCost
)

var (
	userSessionTTL = time.Second * 5
)

func loginProcess(t *testing.T) (*auth.Service, *lg.Claims, string) {
	passHash, err := generatePasswordHash("password", passwordCost)
	require.NoError(t, err)

	user := &lg.User{
		ID:           ulid.MustParse("00000000000000000000000000"),
		Email:        "user1@email.com",
		PasswordHash: passHash,
	}
	userRepo := &mock.UserRepositoryMock{
		FindByEmailFunc: func(ctx context.Context, email string) (*lg.User, error) {
			return user, nil
		},
	}

	logger := log.Default()
	svc := auth.NewService(
		*logger,
		userRepo,
		userSessionTTL,
		secretKey,
	)

	ctx := context.Background()
	claims, err := svc.LoginUser(ctx, &lg.LoginUserRequest{
		Email:    "user1@email.com",
		Password: "password",
	})
	require.NoError(t, err)

	token, err := svc.BuildJWT(ctx, claims)
	require.NoError(t, err)

	return svc, claims, token
}

// generatePasswordHash returns the bcrypt hash of the password at the given cost
func generatePasswordHash(password string, cost int) (string, error) {
	pass, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}

	return string(pass), nil
}

func getDefaultClaims(tNow time.Time) *lg.Claims {
	return &lg.Claims{
		UserID: ulid.MustParse("00000000000000000000000000").String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        internal.GenerateULID().String(),
			IssuedAt:  jwt.NewNumericDate(tNow),
			ExpiresAt: jwt.NewNumericDate(tNow.Add(userSessionTTL)),
			NotBefore: jwt.NewNumericDate(tNow),
			Issuer:    "login_jwt",
		},
	}
}

func TestLoginUser_Success(t *testing.T) {
	passHash, err := generatePasswordHash("password", passwordCost)
	require.NoError(t, err)

	user := lg.User{
		ID:           ulid.MustParse("00000000000000000000000000"),
		Email:        "user1@email.com",
		PasswordHash: passHash,
	}

	userRepo := &mock.UserRepositoryMock{
		FindByEmailFunc: func(ctx context.Context, email string) (*lg.User, error) {
			return &user, nil
		},
	}

	tNow := time.Now().UTC()
	expectedClaims := getDefaultClaims(tNow)

	testTable := []struct {
		name string
	}{
		{
			name: "no_error_in_cache",
		},
	}

	logger := log.Default()
	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			svc := auth.NewService(
				*logger,
				userRepo,
				userSessionTTL,
				secretKey,
			)

			req := &lg.LoginUserRequest{
				Email:    "user1@email.com",
				Password: "password",
			}

			actualClaims, err := svc.LoginUser(context.Background(), req)
			require.NoError(t, err)
			require.Equal(t, expectedClaims.UserID, actualClaims.UserID)
			require.Equal(t, expectedClaims.Issuer, actualClaims.Issuer)
		})
	}
}

func TestLoginUser_Failed(t *testing.T) {
	testTable := []struct {
		name        string
		userRepo    *mock.UserRepositoryMock
		loginReq    *lg.LoginUserRequest
		expErrorMsg string
	}{
		{
			name: "user_repository_error",
			userRepo: &mock.UserRepositoryMock{
				FindByEmailFunc: func(ctx context.Context, email string) (*lg.User, error) {
					return nil, lg.Error{
						Code:    lg.ErrInternal,
						Message: "unable to get user by email",
					}
				},
			},
			loginReq: &lg.LoginUserRequest{
				Email:    "wrong_email@email.com",
				Password: "random_password",
			},
			expErrorMsg: "internal unable to get user by email",
		},
		{
			name: "password_does_not_match",
			userRepo: &mock.UserRepositoryMock{
				FindByEmailFunc: func(ctx context.Context, email string) (*lg.User, error) {
					passHash, err := generatePasswordHash("password", passwordCost)
					require.NoError(t, err)

					return &lg.User{
						Email:        "user1@email.com",
						PasswordHash: passHash,
					}, nil
				},
			},
			loginReq: &lg.LoginUserRequest{
				Email:    "user1@email.com",
				Password: "wrong_password",
			},
			expErrorMsg: lg.ErrPasswordsDoesntMatch.Error(),
		},
		{
			name: "empty_password",
			userRepo: &mock.UserRepositoryMock{
				FindByEmailFunc: func(ctx context.Context, email string) (*lg.User, error) {
					return &lg.User{
						Email:        "user1@email.com",
						PasswordHash: "password",
					}, nil
				},
			},
			loginReq: &lg.LoginUserRequest{
				Email:    "user1@email.com",
				Password: "",
			},
			expErrorMsg: lg.ErrEmptyPassword.Error(),
		},
		{
			name: "empty_hashed_password",
			userRepo: &mock.UserRepositoryMock{
				FindByEmailFunc: func(ctx context.Context, email string) (*lg.User, error) {
					return &lg.User{
						Email:        "user1@email.com",
						PasswordHash: "",
					}, nil
				},
			},
			loginReq:    &lg.LoginUserRequest{},
			expErrorMsg: lg.ErrEmptyPasswordHash.Error(),
		},
	}

	logger := log.Default()
	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			svc := auth.NewService(
				*logger,
				tt.userRepo,
				userSessionTTL,
				secretKey,
			)

			ctx := context.Background()
			actualClaims, err := svc.LoginUser(ctx, tt.loginReq)
			require.Contains(t, err.Error(), tt.expErrorMsg)
			require.Nil(t, actualClaims)
		})
	}
}

func TestBuildJWT_Success(t *testing.T) {
	// create claims and sign token
	tNow := time.Now().UTC()
	claims := getDefaultClaims(tNow)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	expectedToken, err := jwtToken.SignedString([]byte(secretKey))
	require.NoError(t, err)

	logger := log.Default()
	svc := auth.NewService(
		*logger,
		nil,
		userSessionTTL,
		secretKey,
	)

	actualToken, err := svc.BuildJWT(context.Background(), claims)
	require.NoError(t, err)
	require.Equal(t, expectedToken, actualToken)
}

func TestValidateToken_Success(t *testing.T) {
	// create claim and token first via login process
	svc, claims, _ := loginProcess(t)
	ctx := lg.SetClaimsToContext(context.Background(), claims)

	valid, err := svc.ValidateToken(ctx)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestValidateToken_Failed(t *testing.T) {
	logger := log.Default()
	svc := auth.NewService(
		*logger,
		nil,
		userSessionTTL,
		secretKey,
	)

	// create claims and sign token
	claims := getDefaultClaims(time.Now().UTC())
	ctx := lg.SetClaimsToContext(context.Background(), claims)

	valid, err := svc.ValidateToken(ctx)
	require.EqualError(t, err, lg.ErrTokenNotFound.Error())
	require.False(t, valid)
}

func TestParseToken_Success(t *testing.T) {
	logger := log.Default()
	svc := auth.NewService(
		*logger,
		nil,
		userSessionTTL,
		secretKey,
	)

	// create claims and sign token
	expectedClaims := getDefaultClaims(time.Now().UTC())
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expectedClaims)
	token, err := jwtToken.SignedString([]byte(secretKey))
	require.NoError(t, err)

	actualClaims, err := svc.ParseToken(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, expectedClaims.UserID, actualClaims.UserID)
	require.Equal(t, expectedClaims.Issuer, actualClaims.Issuer)
}

func TestParseToken_Failed(t *testing.T) {
	testTable := []struct {
		name          string
		signedAt      time.Time
		signingMethod jwt.SigningMethod
		secretKey     interface{}
		expErrorMsg   string
	}{
		{
			name:          "token_expired",
			signedAt:      time.Now().UTC().Add(userSessionTTL * -1),
			signingMethod: jwt.SigningMethodHS256,
			secretKey:     []byte(secretKey),
			expErrorMsg:   fmt.Sprintf("%s token has been expired", lg.ErrUnauthorized),
		},
		{
			name:          "token_expired_too_long",
			signedAt:      time.Now().UTC().Add(time.Second * 24 * 7),
			signingMethod: jwt.SigningMethodHS256,
			secretKey:     []byte(secretKey),
			expErrorMsg:   fmt.Sprintf("%s token is not valid yet", lg.ErrUnauthorized),
		},
		{
			name:          "jwt_tampered_by_changing_the_role_and_signing_it_with_wrong_secret_key",
			signedAt:      time.Now().UTC(),
			signingMethod: jwt.SigningMethodHS256,
			secretKey:     []byte("wrong_secret_key"),
			expErrorMsg:   fmt.Sprintf("%s token signature is invalid", lg.ErrUnauthorized),
		},
		{
			name:          "secret_key_changed",
			signedAt:      time.Now().UTC(),
			signingMethod: jwt.SigningMethodHS256,
			secretKey:     []byte("old_secret_key"),
			expErrorMsg:   fmt.Sprintf("%s token signature is invalid", lg.ErrUnauthorized),
		},
		{
			name:          "none_signing_method",
			signedAt:      time.Now().UTC(),
			signingMethod: jwt.SigningMethodNone,
			secretKey:     jwt.UnsafeAllowNoneSignatureType,
			expErrorMsg:   fmt.Sprintf("%s 'none' signature type is not allowed", lg.ErrUnauthorized),
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			logger := log.Default()
			svc := auth.NewService(
				*logger,
				nil,
				userSessionTTL,
				secretKey,
			)

			// create claims and sign token
			expectedClaims := getDefaultClaims(tt.signedAt)

			jwtToken := jwt.NewWithClaims(tt.signingMethod, expectedClaims)
			token, err := jwtToken.SignedString(tt.secretKey)
			require.NoError(t, err)

			actualClaims, err := svc.ParseToken(context.Background(), token)
			require.Equal(t, err.Error(), tt.expErrorMsg)
			require.Nil(t, actualClaims)
		})
	}
}

func TestRefreshToken_Success(t *testing.T) {
	// create claim and token first via login process
	svc, previousClaims, _ := loginProcess(t)
	ctx := context.Background()
	ctx = lg.SetClaimsToContext(ctx, previousClaims)

	refreshedClaims, err := svc.RefreshToken(ctx)
	require.NoError(t, err)
	require.NotEqual(t, previousClaims.ID, refreshedClaims.ID)
	require.NotEqual(t, previousClaims.IssuedAt, refreshedClaims.IssuedAt)
	require.NotEqual(t, previousClaims.ExpiresAt, refreshedClaims.ExpiresAt)
	require.NotEqual(t, previousClaims.NotBefore, refreshedClaims.NotBefore)
	require.Equal(t, previousClaims.UserID, refreshedClaims.UserID)
	require.Equal(t, previousClaims.Issuer, refreshedClaims.Issuer)
}

func TestRefreshToken_Failed(t *testing.T) {
	logger := log.Default()
	svc := auth.NewService(
		*logger,
		nil,
		userSessionTTL,
		secretKey,
	)
	// create claims and sign token
	previousClaims := getDefaultClaims(time.Now().UTC())
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, previousClaims)
	_, err := jwtToken.SignedString([]byte(secretKey))
	require.NoError(t, err)
	ctx := context.Background()
	ctx = lg.SetClaimsToContext(ctx, previousClaims)

	refreshedClaims, err := svc.RefreshToken(ctx)
	require.EqualError(t, err, lg.ErrTokenNotFound.Error())
	require.Nil(t, refreshedClaims)
}

func TestLogout_Success(t *testing.T) {
	svc, claims, _ := loginProcess(t)

	ctx := lg.SetClaimsToContext(context.Background(), claims)
	require.NoError(t, svc.Logout(ctx))

	// validate logout token on ValidateToken method should be failed
	valid, err := svc.ValidateToken(ctx)
	require.Error(t, err)
	require.False(t, valid)

	// validate logout token on RefreshToken method should be failed
	refreshedClaims, err := svc.RefreshToken(ctx)
	require.Error(t, err)
	require.Nil(t, refreshedClaims)
}

func TestLogout_Failed(t *testing.T) {
	logger := log.Default()
	svc := auth.NewService(
		*logger,
		nil,
		userSessionTTL,
		secretKey,
	)

	// create claims and sign token
	claims := getDefaultClaims(time.Now().UTC())
	ctx := lg.SetClaimsToContext(context.Background(), claims)

	require.EqualError(t, svc.Logout(ctx), lg.ErrTokenNotFound.Error())
}
