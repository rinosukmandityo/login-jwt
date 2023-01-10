package internal

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

//nolint:gochecknoglobals
var ulidMx sync.Mutex

//nolint:gochecknoglobals
var ulidEntropy = ulid.Monotonic(rand.Reader, 0)

// GenerateULID generate ulid
func GenerateULID() ulid.ULID {
	ulidMx.Lock()
	defer ulidMx.Unlock()

	// ignore possible error here because of error low chance
	return ulid.MustNew(ulid.Timestamp(time.Now()), ulidEntropy)
}
