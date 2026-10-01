package openssl

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECBEncryptAndDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes for AES-256
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	src := []byte("test data")

	// Test encryption
	encrypted, err := ECBEncrypt(block, src, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Test decryption
	decrypted, err := ECBDecrypt(block, encrypted, PKCS7_PADDING)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestECBDecryptInvalidCiphertextLength(t *testing.T) {
	invalidCiphertexts := [][]byte{
		bytes.Repeat([]byte{0x00}, 15), // one byte short of a full block
		bytes.Repeat([]byte{0x00}, 17), // one full block plus a stray byte
	}

	// AES uses a 16-byte block.
	aesBlock, err := aes.NewCipher([]byte("12345678901234567890123456789012")) // 32 bytes for AES-256
	assert.NoError(t, err)
	for _, ciphertext := range invalidCiphertexts {
		_, err := ECBDecrypt(aesBlock, ciphertext, PKCS7_PADDING)
		assert.ErrorContains(t, err, "not a multiple of the block size")
	}

	// The length check is generic: DES uses an 8-byte block.
	desBlock, err := des.NewCipher([]byte("12345123")) // 8 bytes for DES
	assert.NoError(t, err)
	for _, ciphertext := range invalidCiphertexts {
		_, err := ECBDecrypt(desBlock, ciphertext, PKCS7_PADDING)
		assert.ErrorContains(t, err, "not a multiple of the block size")
	}
}

func TestECBEncrypterCryptBlocks(t *testing.T) {
	key := []byte("1234567890123456") // 16 bytes for AES-128
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	encrypter := NewECBEncrypter(block)
	src := make([]byte, encrypter.BlockSize()*2)
	dst := make([]byte, len(src))

	encrypter.CryptBlocks(dst, src)
	assert.Equal(t, len(src), len(dst))
}

func TestECBDecrypterCryptBlocks(t *testing.T) {
	key := []byte("1234567890123456") // 16 bytes for AES-128
	block, err := aes.NewCipher(key)
	assert.NoError(t, err)

	decrypter := NewECBDecrypter(block)
	src := make([]byte, decrypter.BlockSize()*2)
	dst := make([]byte, len(src))

	decrypter.CryptBlocks(dst, src)
	assert.Equal(t, len(src), len(dst))
}
