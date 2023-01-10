package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	lg "github.com/rinosukmandityo/login-jwt"
	"github.com/rinosukmandityo/login-jwt/internal"
	"github.com/rinosukmandityo/login-jwt/internal/api"
	"github.com/rinosukmandityo/login-jwt/internal/api/httputil"
	"github.com/rinosukmandityo/login-jwt/internal/mock"
)

const (
	defaultValidJWTToken = "trustme.its.validtoken"
	validateURL          = "http://localhost/api/auth/validate"
	loginURL             = "http://localhost/api/auth/login"
	refreshURL           = "http://localhost/api/auth/refresh"
	logoutURL            = "http://localhost/api/auth/logout"
)

var (
	userSessionTTL = time.Second * 5
	defaultClaims  = getDefaultClaims(time.Now().UTC())
)

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

type httpRequestParams struct {
	url    string
	body   []byte
	method string
}

type httpResponse struct {
	statusCode int
	body       interface{}
}

func makeRequest(t *testing.T, handlers http.Handler, addr, httpMethod string,
	headers map[string]string, payload []byte) (*http.Response, []byte) {
	t.Helper()

	var req *http.Request
	if payload != nil {
		reqBody := bytes.NewBuffer(payload)
		req, _ = http.NewRequest(httpMethod, addr, reqBody)
	} else {
		req, _ = http.NewRequest(httpMethod, addr, nil)
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	recorder := httptest.NewRecorder()
	handlers.ServeHTTP(recorder, req)
	resp := recorder.Result()

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		t.Fatalf("error on read body %s", err)
	}

	return recorder.Result(), body
}

func createHTTPHandler(authSvc lg.AuthService) http.Handler {
	logger := log.Default()

	ctx := context.Background()
	router := mux.NewRouter()
	api.AttachAuthHandler(
		ctx,
		router,
		authSvc,
		*logger,
		false,
		http.SameSiteNoneMode,
		"/api",
	)

	return router
}

func TestLogin_Success(t *testing.T) {
	testTable := []struct {
		name       string                // name of the test case
		apiReq     httpRequestParams     // api request like url, body and method
		authClient *mock.AuthServiceMock // mocked authClient
		apiResp    httpResponse          // api response like http status code and response body
		headersReq map[string]string     // request headers
		cookiesReq []*http.Cookie        // request cookies
	}{
		{
			name: "success",
			apiReq: httpRequestParams{
				url: loginURL,
				body: []byte(`{
					"email": "user@email.com",
					"password": "password"
				}`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{
				LoginUserFunc: func(ctx context.Context, req *lg.LoginUserRequest) (*lg.Claims, error) {
					return &lg.Claims{}, nil
				},
				BuildJWTFunc: func(ctx context.Context, claims *lg.Claims) (token string, err error) {
					return defaultValidJWTToken, err
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusOK,
				body: map[string]interface{}{
					"token": defaultValidJWTToken,
				},
			},
			headersReq: map[string]string{},
			cookiesReq: make([]*http.Cookie, 0),
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			// create handlers
			handlers := createHTTPHandler(tt.authClient)

			// send login request
			respLogin, bodyLogin := makeRequest(t, handlers, tt.apiReq.url, tt.apiReq.method, tt.headersReq, tt.apiReq.body)
			defer respLogin.Body.Close()
			require.Equal(t, tt.apiResp.statusCode, respLogin.StatusCode)
			require.Len(t, respLogin.Cookies(), 1) // should contain jwt token cookie

			actualBody := make(map[string]interface{})
			err := json.Unmarshal(bodyLogin, &actualBody)
			require.NoError(t, err)
			respBody, _ := tt.apiResp.body.(map[string]interface{})
			require.Equal(t, respBody["token"], actualBody["token"])
		})
	}
}

func TestProtectedResource_Success(t *testing.T) {
	testTable := []struct {
		name         string
		apiReq       httpRequestParams
		authClient   *mock.AuthServiceMock
		cookieNumber int
		apiResp      httpResponse
	}{
		{
			name: "refresh",
			apiReq: httpRequestParams{
				url:    refreshURL,
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{
				BuildJWTFunc: func(ctx context.Context, claims *lg.Claims) (token string, err error) {
					return defaultValidJWTToken, nil
				},
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					require.Equal(t, defaultValidJWTToken, token)

					return defaultClaims, nil
				},
				RefreshTokenFunc: func(ctx context.Context) (*lg.Claims, error) {
					require.Equal(t, defaultClaims, lg.GetClaimsFromContext(ctx))

					return &lg.Claims{}, nil
				},
			},
			cookieNumber: 1, // should contain jwt token cookie
			apiResp: httpResponse{
				statusCode: http.StatusOK,
				body:       map[string]interface{}{"token": defaultValidJWTToken},
			},
		},
		{
			name: "validate",
			apiReq: httpRequestParams{
				url:    validateURL,
				method: http.MethodGet,
			},
			authClient: &mock.AuthServiceMock{
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					require.Equal(t, defaultValidJWTToken, token)

					return &lg.Claims{}, nil
				},
				ValidateTokenFunc: func(ctx context.Context) (bool, error) {
					return true, nil
				},
			},
			cookieNumber: 0,
			apiResp: httpResponse{
				statusCode: http.StatusOK,
				body:       map[string]interface{}{"valid": true},
			},
		},
		{
			name: "logout",
			apiReq: httpRequestParams{
				url:    logoutURL,
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					require.Equal(t, defaultValidJWTToken, token)

					return &lg.Claims{}, nil
				},
				LogoutFunc: func(ctx context.Context) error {
					return nil
				},
			},
			cookieNumber: 0,
			apiResp: httpResponse{
				statusCode: http.StatusOK,
				body:       nil,
			},
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			// create handlers
			handlers := createHTTPHandler(tt.authClient)

			// set JWT token to request header
			headerReq := map[string]string{
				httputil.HTTPHeaderAuthorization: fmt.Sprintf("Bearer %s", defaultValidJWTToken),
			}

			// send refresh request
			resp, body := makeRequest(t, handlers, tt.apiReq.url, tt.apiReq.method, headerReq, nil)
			defer resp.Body.Close()
			require.Equal(t, tt.apiResp.statusCode, resp.StatusCode)
			require.Len(t, resp.Cookies(), tt.cookieNumber)

			if tt.apiResp.body != nil {
				var actualBody interface{}
				err := json.Unmarshal(body, &actualBody)
				require.NoError(t, err)
				require.Equal(t, tt.apiResp.body, actualBody)
			}
		})
	}
}

func TestLogin_Failed(t *testing.T) {
	testTable := []struct {
		name       string                // name of the test case
		apiReq     httpRequestParams     // api request like url, body and method
		authClient *mock.AuthServiceMock // mocked authClient
		apiResp    httpResponse          // api response like http status code and response body
		cookiesReq []*http.Cookie        // request cookies
	}{
		{
			name: "invalid_request_body",
			apiReq: httpRequestParams{
				url:    loginURL,
				body:   []byte(`invalid request`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusBadRequest,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrReqBodyInvalid.Code,
						"message": lg.ErrReqBodyInvalid.Message,
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
		{
			name: "nil_request_body",
			apiReq: httpRequestParams{
				url:    loginURL,
				body:   nil,
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusBadRequest,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrReqBodyInvalid.Code,
						"message": lg.ErrReqBodyInvalid.Message,
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
		{
			name: "empty_object_request_body",
			apiReq: httpRequestParams{
				url:    loginURL,
				body:   []byte(`{}`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusBadRequest,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrReqBodyInvalid.Code,
						"message": lg.ErrReqBodyInvalid.Message,
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
		{
			name: "empty_email",
			apiReq: httpRequestParams{
				url: loginURL,
				body: []byte(`{
					"email": "",
					"password": "secret"
				}`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusBadRequest,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrReqBodyInvalid.Code,
						"message": lg.ErrReqBodyInvalid.Message,
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
		{
			name: "empty_password",
			apiReq: httpRequestParams{
				url: loginURL,
				body: []byte(`{
					"email": "user@email.com",
					"password": ""
				}`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusBadRequest,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrReqBodyInvalid.Code,
						"message": lg.ErrReqBodyInvalid.Message,
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
		{
			name: "login_user_password_doesnt_match",
			apiReq: httpRequestParams{
				url: loginURL,
				body: []byte(`{
					"email": "user@email.com",
					"password": "secret"
				}`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{
				LoginUserFunc: func(ctx context.Context, req *lg.LoginUserRequest) (*lg.Claims, error) {
					return nil, lg.ErrPasswordsDoesntMatch
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusUnauthorized,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrPasswordsDoesntMatch.Code,
						"message": lg.ErrPasswordsDoesntMatch.Message,
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
		{
			name: "login_user_internal_error",
			apiReq: httpRequestParams{
				url: loginURL,
				body: []byte(`{
					"email": "user@email.com",
					"password": "secret"
				}`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{
				LoginUserFunc: func(ctx context.Context, req *lg.LoginUserRequest) (*lg.Claims, error) {
					return nil, lg.Error{
						Code:    lg.ErrInternal,
						Message: "something went wrong",
					}
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusInternalServerError,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrInternal,
						"message": "something went wrong",
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
		{
			name: "build_jwt_failed",
			apiReq: httpRequestParams{
				url: loginURL,
				body: []byte(`{
					"email": "user@email.com",
					"password": "secret"
				}`),
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{
				LoginUserFunc: func(ctx context.Context, req *lg.LoginUserRequest) (*lg.Claims, error) {
					return &lg.Claims{}, nil
				},
				BuildJWTFunc: func(ctx context.Context, claims *lg.Claims) (token string, err error) {
					return "", lg.Error{
						Code:    lg.ErrInternal,
						Message: "unable to build jwt token",
					}
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusInternalServerError,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrInternal,
						"message": "unable to build jwt token",
					},
				},
			},
			cookiesReq: make([]*http.Cookie, 0),
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			// create handlers
			handlers := createHTTPHandler(tt.authClient)

			// send login request
			respLogin, bodyLogin := makeRequest(t, handlers, tt.apiReq.url, tt.apiReq.method, nil, tt.apiReq.body)
			defer respLogin.Body.Close()
			require.Equal(t, tt.apiResp.statusCode, respLogin.StatusCode)
			require.Len(t, respLogin.Cookies(), 0)

			actualBody := make(map[string]interface{})
			err := json.Unmarshal(bodyLogin, &actualBody)
			require.NoError(t, err)
			require.Equal(t, tt.apiResp.body, actualBody)
		})
	}
}

func TestProtectedResource_Failed(t *testing.T) {
	testTable := []struct {
		name           string
		apiReq         httpRequestParams
		jwtTokenHeader string
		authClient     *mock.AuthServiceMock
		apiResp        httpResponse
		totalCookies   int
	}{
		{
			name: "endpoint_not_found",
			apiReq: httpRequestParams{
				url:    "/api/v1/auth/notfound",
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusNotFound,
				body:       nil,
			},
		},
		{
			name: "refresh_token_not_found",
			apiReq: httpRequestParams{
				url:    refreshURL,
				method: http.MethodPost,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusUnauthorized,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrTokenNotFound.Code,
						"message": lg.ErrTokenNotFound.Message,
					},
				},
			},
		},
		{
			name: "validate_token_not_found",
			apiReq: httpRequestParams{
				url:    validateURL,
				method: http.MethodGet,
			},
			authClient: &mock.AuthServiceMock{},
			apiResp: httpResponse{
				statusCode: http.StatusUnauthorized,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrTokenNotFound.Code,
						"message": lg.ErrTokenNotFound.Message,
					},
				},
			},
		},
		{
			name: "refresh_token_failed",
			apiReq: httpRequestParams{
				url:    refreshURL,
				method: http.MethodPost,
			},
			jwtTokenHeader: defaultValidJWTToken,
			authClient: &mock.AuthServiceMock{
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					return &lg.Claims{}, nil
				},
				RefreshTokenFunc: func(ctx context.Context) (*lg.Claims, error) {
					return &lg.Claims{}, lg.Error{
						Code:    lg.ErrInternal,
						Message: "unable to refresh token",
					}
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusInternalServerError,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrInternal,
						"message": "unable to refresh token",
					},
				},
			},
		},
		{
			name: "refresh_token_build_jwt_failed",
			apiReq: httpRequestParams{
				url:    refreshURL,
				method: http.MethodPost,
			},
			jwtTokenHeader: defaultValidJWTToken,
			authClient: &mock.AuthServiceMock{
				BuildJWTFunc: func(ctx context.Context, claims *lg.Claims) (token string, err error) {
					return "", lg.Error{
						Code:    lg.ErrInternal,
						Message: "unable to build jwt",
					}
				},
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					return &lg.Claims{}, nil
				},
				RefreshTokenFunc: func(ctx context.Context) (*lg.Claims, error) {
					return &lg.Claims{}, nil
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusInternalServerError,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrInternal,
						"message": "unable to build jwt",
					},
				},
			},
		},
		{
			name: "logout_failed",
			apiReq: httpRequestParams{
				url:    logoutURL,
				method: http.MethodPost,
			},
			jwtTokenHeader: defaultValidJWTToken,
			authClient: &mock.AuthServiceMock{
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					return &lg.Claims{}, nil
				},
				LogoutFunc: func(ctx context.Context) error {
					return lg.Error{
						Code:    lg.ErrInternal,
						Message: "unable to revoke token",
					}
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusInternalServerError,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrInternal,
						"message": "unable to revoke token",
					},
				},
			},
		},
		{
			name: "validate_parse_token_error",
			apiReq: httpRequestParams{
				url:    validateURL,
				method: http.MethodGet,
			},
			jwtTokenHeader: defaultValidJWTToken,
			authClient: &mock.AuthServiceMock{
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					return nil, lg.Error{
						Code:    lg.ErrInternal,
						Message: "unable to parse token",
					}
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusInternalServerError,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrInternal,
						"message": "unable to parse token",
					},
				},
			},
		},
		{
			name: "validate_internal_error",
			apiReq: httpRequestParams{
				url:    validateURL,
				method: http.MethodGet,
			},
			jwtTokenHeader: defaultValidJWTToken,
			authClient: &mock.AuthServiceMock{
				ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
					return defaultClaims, nil
				},
				ValidateTokenFunc: func(ctx context.Context) (bool, error) {
					return false, lg.Error{
						Code:    lg.ErrInternal,
						Message: "unable to validate token",
					}
				},
			},
			apiResp: httpResponse{
				statusCode: http.StatusInternalServerError,
				body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    lg.ErrInternal,
						"message": "unable to validate token",
					},
				},
			},
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			// create handlers
			handlers := createHTTPHandler(tt.authClient)

			// set JWT token to request header
			headerReq := map[string]string{httputil.HTTPHeaderAuthorization: fmt.Sprintf("Bearer %s", tt.jwtTokenHeader)}

			// send request
			resp, body := makeRequest(t, handlers, tt.apiReq.url, tt.apiReq.method, headerReq, nil)
			defer resp.Body.Close()
			require.Equal(t, tt.apiResp.statusCode, resp.StatusCode)
			require.Len(t, resp.Cookies(), tt.totalCookies)

			if tt.apiResp.body != nil {
				var actualBody interface{}
				err := json.Unmarshal(body, &actualBody)
				require.NoError(t, err)
				require.Equal(t, tt.apiResp.body, actualBody)
			}
		})
	}
}
