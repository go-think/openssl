package openssl

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDesEncrypt(t *testing.T) {
	src := []byte("123456")

	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "RJK5Sd4AS44=")
}

func TestDesECBDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("RJK5Sd4AS44=")
	assert.NoError(t, err)

	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func TestDesCBCEncrypt(t *testing.T) {
	src := []byte("123456")
	iv := []byte("67890678")
	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesCBCEncrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "fPHNaq8PdWA=")
}

func TestDesCBCDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("fPHNaq8PdWA=")
	assert.NoError(t, err)

	iv := []byte("67890678")

	// DES-ECB, PKCS7_PADDING
	key := []byte("12345123")
	dst, err := DesCBCDecrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func TestDesCFB(t *testing.T) {
	src := []byte("123456_DES_CFB")
	key := []byte("12345123")
	iv := []byte("67890678")

	encrypted, err := DesCFBEncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := DesCFBDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestDesOFB(t *testing.T) {
	src := []byte("123456_DES_OFB")
	key := []byte("12345123")
	iv := []byte("67890678")

	encrypted, err := DesOFBEncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := DesOFBDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestDesCTR(t *testing.T) {
	src := []byte("123456_DES_CTR")
	key := []byte("12345123")
	iv := []byte("67890678")

	encrypted, err := DesCTREncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := DesCTRDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}
