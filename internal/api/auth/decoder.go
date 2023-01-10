package auth

import (
	"encoding/json"
	"log"
	"net/http"

	lg "github.com/rinosukmandityo/login-jwt"
)

func decodeLoginRequest(logger log.Logger, r *http.Request) (*lg.LoginUserRequest, error) {
	if r.Body == nil {
		return nil, lg.ErrReqBodyInvalid
	}

	var req loginUserRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Email == "" {
		return nil, lg.ErrReqBodyInvalid
	}

	// reject empty email and password
	if req.Email == "" || req.Password == "" {
		logger.Println("empty email/password body")

		return nil, lg.ErrReqBodyInvalid
	}

	return &lg.LoginUserRequest{
		Email:    req.Email,
		Password: req.Password,
	}, nil
}
