package login

import (
	"errors"
	"fmt"
	"net/http"
)

const (
	// ErrInternal is an internal error.
	ErrInternal = "internal"
	// ErrBadParameter is an bad parameter in request.
	ErrBadRequest = "bad_request"
	// ErrNotFound is data not found
	ErrNotFound = "not_found"
	// ErrUnauthorized means that request in not authorized.
	ErrUnauthorized = "unauthorized"
)

// Error represents an error within the context of LP service.
type Error struct {
	// Code is a machine-readable code.
	Code string `json:"code"`
	// Message is a human-readable message.
	Message string `json:"message"`
	// Inner is a wrapped error that is never shown to API consumers.
	Inner error `json:"-"`
}

// Error returns the string representation of the error message.
func (e Error) Error() string {
	if e.Inner != nil {
		return fmt.Sprintf("%s %s: %v", e.Code, e.Message, e.Inner)
	}

	return fmt.Sprintf("%s %s", e.Code, e.Message)
}

// Unwrap returns an inner error if any.
// It allows to use errors.Is() with wallet.ErrorCode type.
func (e Error) Unwrap() error {
	return e.Inner
}

// Wrap makes a copy of current error and wrap another error into it
func (e Error) Wrap(inner error) Error {
	ret := e.copy()
	if ret.Inner != nil {
		ret.Inner = fmt.Errorf("%s: %w", inner.Error(), ret.Inner)
	} else {
		ret.Inner = inner
	}

	return ret
}

func (e Error) copy() Error {
	return Error{
		Code:    e.Code,
		Message: e.Message,
		Inner:   e.Inner,
	}
}

// IsErrorCode checks if err is Error and has a code
func IsErrorCode(err error, code string) bool {
	var ownErr Error
	if errors.As(err, &ownErr) {
		return ownErr.Code == code
	}

	return false
}

// NormalizeError returns our own error or unknown
func NormalizeError(err error) Error {
	var e Error
	if errors.As(err, &e) {
		return e
	}

	return Error{
		Code:  ErrInternal,
		Inner: err,
	}
}

var (
	// ErrPasswordsDoesntMatch is a VerifyPassword error.
	ErrPasswordsDoesntMatch = Error{
		Code:    ErrUnauthorized,
		Message: "Password doesn't match",
	}
	// ErrEmptyPassword an error when user try to input empty password.
	ErrEmptyPassword = Error{
		Code:    ErrBadRequest,
		Message: "Password can't be empty",
	}
	// ErrEmptyPasswordHash an error when user try to login before setting the password up.
	ErrEmptyPasswordHash = Error{
		Code:    ErrBadRequest,
		Message: "Password is not set yet. Please setup the password through welcome link in the email",
	}
	// ErrTokenNotFound an error when an auth token is not found.
	ErrTokenNotFound = Error{
		Code:    ErrUnauthorized,
		Message: "Token not found",
	}
	// ErrTokenSignatureInvalid is an error when token signature is invalid
	ErrTokenSignatureInvalid = Error{
		Code:    ErrUnauthorized,
		Message: "token signature is invalid",
	}
	// ErrTokenExpired is an error when token has been expired
	ErrTokenExpired = Error{
		Code:    ErrUnauthorized,
		Message: "token has been expired",
	}
	// ErrTokenInvalid is an error when token is invalid
	ErrTokenInvalid = Error{
		Code:    ErrUnauthorized,
		Message: "token is not valid yet",
	}
	// ErrReqBodyInvalid is an error when the request body is invalid
	ErrReqBodyInvalid = Error{
		Code:    ErrBadRequest,
		Message: "request body is invalid",
	}
)

// ToHTTPStatus converts error to http status
func (e Error) ToHTTPStatus() int {
	switch e.Code {
	case ErrInternal:
		return http.StatusInternalServerError
	case ErrBadRequest:
		return http.StatusBadRequest
	case ErrNotFound:
		return http.StatusNotFound
	case ErrUnauthorized:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// ErrorFromHTTPStatus converts http status to error
func ErrorFromHTTPStatus(status int) Error {
	var code string
	switch status {
	case http.StatusInternalServerError:
		code = ErrInternal
	case http.StatusBadRequest:
		code = ErrBadRequest
	case http.StatusNotFound:
		code = ErrNotFound
	case http.StatusUnauthorized:
		code = ErrUnauthorized
	default:
		code = ErrInternal
	}

	return Error{
		Code: code,
	}
}
