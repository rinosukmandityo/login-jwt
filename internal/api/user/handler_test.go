package user_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	userURL              = "http://localhost/api/users"
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

func createHTTPHandler(authSvc lg.AuthService) http.Handler {
	ctx := context.Background()
	router := mux.NewRouter()
	api.AttachUserHandler(
		ctx,
		router,
		authSvc,
	)

	return router
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

func TestUsersHandler_Success(t *testing.T) {
	testTable := []struct {
		name    string            // name of the test case
		apiReq  httpRequestParams // api request like url, body and method
		apiResp httpResponse      // api response like http status code and response body
	}{
		{
			name: "insert",
			apiReq: httpRequestParams{
				url:    userURL,
				body:   []byte(`{"email": "user@email.com"}`),
				method: http.MethodPost,
			},
			apiResp: httpResponse{
				statusCode: http.StatusNoContent,
			},
		},
		{
			name: "get",
			apiReq: httpRequestParams{
				url:    userURL + "/user@email.com",
				body:   nil,
				method: http.MethodGet,
			},
			apiResp: httpResponse{
				statusCode: http.StatusOK,
				body:       map[string]interface{}{"email": "user@email.com"},
			},
		},
		{
			name: "update",
			apiReq: httpRequestParams{
				url:    userURL + "/user@email.com",
				body:   []byte(`{"email": "user@email.com"}`),
				method: http.MethodPut,
			},
			apiResp: httpResponse{
				statusCode: http.StatusOK,
				body:       nil,
			},
		},
		{
			name: "delete",
			apiReq: httpRequestParams{
				url:    userURL + "/user@email.com",
				body:   nil,
				method: http.MethodDelete,
			},
			apiResp: httpResponse{
				statusCode: http.StatusOK,
				body:       nil,
			},
		},
	}

	authClient := &mock.AuthServiceMock{
		ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
			require.Equal(t, defaultValidJWTToken, token)

			return defaultClaims, nil
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			// create handlers
			handlers := createHTTPHandler(authClient)
			// set JWT token to request header
			headerReq := map[string]string{
				httputil.HTTPHeaderAuthorization: fmt.Sprintf("Bearer %s", defaultValidJWTToken),
			}

			// send request
			resp, body := makeRequest(t, handlers, tt.apiReq.url, tt.apiReq.method, headerReq, tt.apiReq.body)
			defer resp.Body.Close()
			require.Equal(t, tt.apiResp.statusCode, resp.StatusCode)

			if tt.apiReq.method == http.MethodGet {
				actualBody := make(map[string]interface{})
				err := json.Unmarshal(body, &actualBody)
				require.NoError(t, err)
				respBody, _ := tt.apiResp.body.(map[string]interface{})
				require.Equal(t, respBody, actualBody)
			}
		})
	}
}

func TestUsersHandler_Failed(t *testing.T) {
	testTable := []struct {
		name    string            // name of the test case
		apiReq  httpRequestParams // api request like url, body and method
		apiResp httpResponse      // api response like http status code and response body
	}{
		{
			name: "insert",
			apiReq: httpRequestParams{
				url:    userURL,
				body:   []byte(`{"email": "user@email.com"}`),
				method: http.MethodPost,
			},
			apiResp: httpResponse{
				statusCode: http.StatusUnauthorized,
			},
		},
		{
			name: "get",
			apiReq: httpRequestParams{
				url:    userURL + "/user@email.com",
				method: http.MethodGet,
			},
			apiResp: httpResponse{
				statusCode: http.StatusUnauthorized,
			},
		},
		{
			name: "update",
			apiReq: httpRequestParams{
				url:    userURL + "/user@email.com",
				body:   []byte(`{"email": "user@email.com"}`),
				method: http.MethodPut,
			},
			apiResp: httpResponse{
				statusCode: http.StatusUnauthorized,
			},
		},
		{
			name: "delete",
			apiReq: httpRequestParams{
				url:    userURL + "/user@email.com",
				body:   nil,
				method: http.MethodDelete,
			},
			apiResp: httpResponse{
				statusCode: http.StatusUnauthorized,
			},
		},
	}

	authClient := &mock.AuthServiceMock{
		ParseTokenFunc: func(ctx context.Context, token string) (*lg.Claims, error) {
			require.Equal(t, defaultValidJWTToken, token)

			return defaultClaims, nil
		},
	}

	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			// create handlers
			handlers := createHTTPHandler(authClient)
			// set JWT token to request header
			headerReq := map[string]string{
				httputil.HTTPHeaderAuthorization: "Bearer",
			}

			// send request
			resp, _ := makeRequest(t, handlers, tt.apiReq.url, tt.apiReq.method, headerReq, tt.apiReq.body)
			require.Equal(t, tt.apiResp.statusCode, resp.StatusCode)
		})
	}
}
