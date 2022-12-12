package auth

import (
	"math/rand"
	"time"
)

// returns a random alphanumeric string
func RandString() string {
	charset := "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	seedRand := rand.New(
		rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, 5)
	for i := range b {
		b[i] = charset[seedRand.Intn(len(charset))]
	}
	return string(b)
}
