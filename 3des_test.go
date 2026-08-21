package openssl

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDes3Encrypt(t *testing.T) {
	src := []byte("123456")

	// 3DES-ECB, PKCS7_PADDING
	key := []byte("123456789012345678901234")
	dst, err := Des3ECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "zvq8DAMSQaM=")
}

func TestDes3ECBDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("zvq8DAMSQaM=")
	assert.NoError(t, err)

	// 3DES-ECB, PKCS7_PADDING
	key := []byte("123456789012345678901234")
	dst, err := Des3ECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func TestDes3CBCEncrypt(t *testing.T) {
	src := []byte("123456")
	iv := []byte("67890678")
	// 3DES-ECB, PKCS7_PADDING
	key := []byte("123456789012345678901234")
	dst, err := Des3CBCEncrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "elcFR372FXU=")
}

func TestDes3CBCDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("elcFR372FXU=")
	assert.NoError(t, err)

	iv := []byte("67890678")

	// 3DES-ECB, PKCS7_PADDING
	key := []byte("123456789012345678901234")
	dst, err := Des3CBCDecrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func TestDes3CFB(t *testing.T) {
	src := []byte("123456_3DES_CFB")
	key := []byte("123456789012345678901234")
	iv := []byte("67890678")

	encrypted, err := Des3CFBEncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := Des3CFBDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestDes3OFB(t *testing.T) {
	src := []byte("123456_3DES_OFB")
	key := []byte("123456789012345678901234")
	iv := []byte("67890678")

	encrypted, err := Des3OFBEncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := Des3OFBDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestDes3CTR(t *testing.T) {
	src := []byte("123456_3DES_CTR")
	key := []byte("123456789012345678901234")
	iv := []byte("67890678")

	encrypted, err := Des3CTREncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := Des3CTRDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}
