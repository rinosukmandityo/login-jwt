package internal

import (
	"errors"

	"golang.org/x/crypto/bcrypt"

	lg "github.com/rinosukmandityo/login-jwt"
)

// PasswordCost cost of bcrypt hash function
// https://auth0.com/blog/hashing-in-action-understanding-bcrypt/
const PasswordCost = bcrypt.DefaultCost

// GeneratePasswordHash generates bcrypt hash
func GeneratePasswordHash(password string, cost int) (string, error) {
	pass, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}

	return string(pass), nil
}

// VerifyPassword verifies password against bcrypt hash
func VerifyPassword(hashedPassword, password string) error {
	if hashedPassword == "" {
		return lg.ErrEmptyPasswordHash
	}
	if password == "" {
		return lg.ErrEmptyPassword
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return lg.ErrPasswordsDoesntMatch
	} else if err != nil {
		return err
	}

	return nil
}
