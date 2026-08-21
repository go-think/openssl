package openssl

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestAes(t *testing.T) {
	src := []byte("1234567890_QWERTY")
	key := []byte("12345123451234512345123451234512")
	dst, err := AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)

	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "MdzAshBM1s7uxcblqWIyTY0s2tcEpGg+OwaQzHMd45o=")

}

func TestAesEncrypt(t *testing.T) {
	src := []byte("123456")

	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "SpfAShHImQhWjd/21Pgz2Q==")

	// AES-192-ECB, PKCS7_PADDING
	key = []byte("123451234512345123451234")
	dst, err = AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "vOwA1oZknZ54rgXETVYwMg==")

	// AES-256-ECB, PKCS7_PADDING
	key = []byte("12345123451234512345123451234512")
	dst, err = AesECBEncrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "F+tlXjWffI4xt656KVwgLg==")
}

func TestAesECBDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("SpfAShHImQhWjd/21Pgz2Q==")
	assert.NoError(t, err)

	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))

	// AES-192-ECB, PKCS7_PADDING
	src, _ = base64.StdEncoding.DecodeString("vOwA1oZknZ54rgXETVYwMg==")
	key = []byte("123451234512345123451234")
	dst, err = AesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))

	// AES-256-ECB, PKCS7_PADDING
	src, _ = base64.StdEncoding.DecodeString("F+tlXjWffI4xt656KVwgLg==")
	key = []byte("12345123451234512345123451234512")
	dst, err = AesECBDecrypt(src, key, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func TestAesCBCEncrypt(t *testing.T) {
	src := []byte("123456")
	iv := []byte("6789067890678906")
	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesCBCEncrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(dst))
	assert.Equal(t, base64.StdEncoding.EncodeToString(dst), "0huM2ppRyYZmZnzdoCL/tA==")
}

func TestAesCBCDecrypt(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("0huM2ppRyYZmZnzdoCL/tA==")
	assert.NoError(t, err)

	iv := []byte("6789067890678906")

	// AES-128-ECB, PKCS7_PADDING
	key := []byte("1234512345123451")
	dst, err := AesCBCDecrypt(src, key, iv, PKCS7_PADDING)
	assert.NoError(t, err)
	t.Log(string(dst))
	assert.Equal(t, dst, []byte("123456"))
}

func Test_aesKeyPending(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{name: "key < 16", args: args{key: []byte("12354678901234")}, want: append([]byte("12354678901234"), []byte{0, 0}...)},
		{name: "key < 24", args: args{key: []byte("1235467890123546789012")}, want: append([]byte("1235467890123546789012"), []byte{0, 0}...)},
		{name: "key < 32", args: args{key: []byte("123546789012354678901235467890")}, want: append([]byte("123546789012354678901235467890"), []byte{0, 0}...)},
		{name: "key > 32", args: args{key: []byte("1235467890123546789012354678901234")}, want: []byte("12354678901235467890123546789012")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aesKeyPending(tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("aesKeyPending() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAesGCM(t *testing.T) {
	src := []byte("123456_GCM_DATA")
	key := []byte("1234512345123451")
	nonce := []byte("123456789012")
	aad := []byte("header_data")

	// Encrypt
	ciphertext, err := AesGCMEncrypt(src, key, nonce, aad)
	assert.NoError(t, err)

	// Decrypt
	plaintext, err := AesGCMDecrypt(ciphertext, key, nonce, aad)
	assert.NoError(t, err)
	assert.Equal(t, src, plaintext)

	// Invalid Key error
	_, err = AesGCMDecrypt(ciphertext, []byte("wrongkey12345678"), nonce, aad)
	assert.Error(t, err)
}

func TestAesCFB(t *testing.T) {
	src := []byte("123456_CFB_TEST_STRING")
	key := []byte("1234512345123451")
	iv := []byte("1234567890123456")

	encrypted, err := AesCFBEncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := AesCFBDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestAesOFB(t *testing.T) {
	src := []byte("123456_OFB_TEST_STRING")
	key := []byte("1234512345123451")
	iv := []byte("1234567890123456")

	encrypted, err := AesOFBEncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := AesOFBDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestAesCTR(t *testing.T) {
	src := []byte("123456_CTR_TEST_STRING")
	key := []byte("1234512345123451")
	iv := []byte("1234567890123456")

	encrypted, err := AesCTREncrypt(src, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, len(src), len(encrypted))

	decrypted, err := AesCTRDecrypt(encrypted, key, iv)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}