package httputil

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	lg "github.com/rinosukmandityo/login-jwt"
)

type errorResp struct {
	Error lg.Error `json:"error"`
}

// EncodeErrorResp error response encoder.
func EncodeErrorResp(w http.ResponseWriter, err error) {
	var ownErr lg.Error
	var statusCode int

	if !errors.As(err, &ownErr) {
		log.Println(err.Error())
		ownErr = lg.Error{
			Code:    lg.ErrInternal,
			Message: "Internal error",
		}
	}
	resp := &errorResp{Error: ownErr}

	statusCode = ownErr.ToHTTPStatus()
	w.WriteHeader(statusCode)

	if err = json.NewEncoder(w).Encode(resp); err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	return
}

// EncodeResponse encode json response with http status code.
func EncodeResponse(
	ctx context.Context,
	w http.ResponseWriter,
	statusCode int,
	data interface{},
) {
	w.WriteHeader(statusCode)
	if data == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Println(err.Error())
	}
}
