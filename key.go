package openssl

import (
	"crypto/rand"
	"errors"
)

// Generates a key based on the input data and specified block size.
func KeyGenerator(src []byte, blockSize int) []byte {
	hashs := SHA1(SHA1(src))
	maxLen := len(hashs)
	if blockSize > maxLen {
		return src
	}

	return hashs[0:blockSize]
}

// RandomBytes generates cryptographically secure random bytes of specified length.
func RandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("openssl: invalid length")
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
