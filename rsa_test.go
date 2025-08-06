package openssl

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRSAGenerateKey(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)
	t.Logf("private key: %s\n", priBuf.Bytes())

	block, _ := pem.Decode(priBuf.Bytes())
	assert.NotNil(t, block, "Failed to decode private key")
	assert.Equal(t, "RSA PRIVATE KEY", block.Type, "Invalid key type")

	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err, "Failed to parse private key")
}

func TestRSAGeneratePublicKey(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)
	t.Logf("public key: %s\n", pubBuf.Bytes())

	block, _ := pem.Decode(pubBuf.Bytes())
	assert.NotNil(t, block, "Failed to decode public key")
	assert.Equal(t, "RSA PUBLIC KEY", block.Type, "Invalid key type")

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "Failed to parse public key")
	_, ok := pubKey.(*rsa.PublicKey)
	assert.True(t, ok, "Key is not an RSA public key")
}

func TestRSAEncrypt(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)
	t.Logf("private key: %s\n", priBuf.Bytes())

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)
	t.Logf("public key: %s\n", pubBuf.Bytes())

	src := []byte("123456")
	dst, err := RSAEncrypt(src, pubBuf.Bytes())
	assert.NoError(t, err)
	t.Logf("encrypt out: %s\n", base64.RawStdEncoding.EncodeToString(dst))

	dst, err = RSADecrypt(dst, priBuf.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, src, dst)

	t.Logf("src: %s \ndst:%s", src, dst)
}

func TestRSASign(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)
	t.Logf("private key: %s\n", priBuf.Bytes())

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)
	t.Logf("public key: %s\n", pubBuf.Bytes())

	src := []byte("123456")
	sign, err := RSASign(src, priBuf.Bytes(), crypto.SHA256)
	assert.NoError(t, err)
	t.Logf("sign out: %s\n", base64.RawStdEncoding.EncodeToString(sign))

	err = RSAVerify(src, sign, pubBuf.Bytes(), crypto.SHA256)
	assert.NoError(t, err)
}
