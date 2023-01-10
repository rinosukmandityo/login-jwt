package memory

import (
	"context"

	lg "github.com/rinosukmandityo/login-jwt"
)

// UserRepo is a kg.UserRepository implementation
type UserRepo struct {
	dataStore map[string]*lg.User
}

func NewUserRepository() *UserRepo {
	return &UserRepo{
		dataStore: make(map[string]*lg.User),
	}
}

func (u *UserRepo) Insert(ctx context.Context, user *lg.User) error {
	u.dataStore[user.Email] = user

	return nil
}

func (u *UserRepo) FindByEmail(ctx context.Context, email string) (*lg.User, error) {
	return u.dataStore[email], nil
}

func (u *UserRepo) FlushAll() {
	u.dataStore = make(map[string]*lg.User)
}
