package openssl

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCBCEncryptAndDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes for AES-256
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	src := []byte("test data")
	iv := []byte("1234567890123456") // 16 bytes for AES

	// Test encryption
	encrypted, err := CBCEncrypt(block, src, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Test decryption
	decrypted, err := CBCDecrypt(block, encrypted, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestCBCDecryptInvalidCiphertextLength(t *testing.T) {
	invalidCiphertexts := [][]byte{
		bytes.Repeat([]byte{0x00}, 15), // one byte short of a full block
		bytes.Repeat([]byte{0x00}, 17), // one full block plus a stray byte
	}

	// AES uses a 16-byte block.
	aesBlock, err := aes.NewCipher([]byte("12345678901234567890123456789012")) // 32 bytes for AES-256
	assert.NoError(t, err)
	for _, ciphertext := range invalidCiphertexts {
		_, err := CBCDecrypt(aesBlock, ciphertext, []byte("1234567890123456"), PKCS7_PADDING)
		assert.ErrorContains(t, err, "not a multiple of the block size")
	}

	// The length check is generic: DES uses an 8-byte block.
	desBlock, err := des.NewCipher([]byte("12345123")) // 8 bytes for DES
	assert.NoError(t, err)
	for _, ciphertext := range invalidCiphertexts {
		_, err := CBCDecrypt(desBlock, ciphertext, []byte("67890678"), PKCS7_PADDING)
		assert.ErrorContains(t, err, "not a multiple of the block size")
	}
}

func TestCBCEncryptDecryptWithShortIV(t *testing.T) {
	// A short IV is zero-padded to the block size; both directions must pad
	// to the same IV for the roundtrip to work.
	block, err := aes.NewCipher([]byte("12345678901234567890123456789012")) // 32 bytes for AES-256
	assert.NoError(t, err)

	src := []byte("test data")
	shortIV := []byte("1234") // 4 bytes, auto-padded to 16

	encrypted, err := CBCEncrypt(block, src, shortIV, PKCS7_PADDING)
	assert.NoError(t, err)

	decrypted, err := CBCDecrypt(block, encrypted, shortIV, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestCBCIVPending(t *testing.T) {
	blockSize := 16
	testCases := []struct {
		iv       []byte
		expected []byte
	}{
		{[]byte("1234"), append([]byte("1234"), bytes.Repeat([]byte{0}, 12)...)},
		{[]byte("12345678901234567890"), []byte("1234567890123456")},
		{[]byte("1234567890123456"), []byte("1234567890123456")},
	}

	for _, tc := range testCases {
		result := cbcIVPending(tc.iv, blockSize)
		assert.Equal(t, tc.expected, result)
	}
}
