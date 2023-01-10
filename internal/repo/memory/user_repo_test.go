package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	lg "github.com/rinosukmandityo/login-jwt"
	"github.com/rinosukmandityo/login-jwt/internal/repo/memory"
)

func TestFindByEmail(t *testing.T) {
	db := memory.NewUserRepository()
	defer db.FlushAll()

	expUser := &lg.User{
		ID:                ulid.MustParse("00000000000000000000000000"),
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
		IsDeleted:         false,
		FirstName:         "John",
		LastName:          "Wick",
		Email:             "user1@mail.com",
		PasswordHash:      "assume this is password has",
		PasswordUpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, db.Insert(context.Background(), expUser))

	user, err := db.FindByEmail(context.Background(), expUser.Email)
	require.NoError(t, err)
	require.Equal(t, expUser, user)
}
