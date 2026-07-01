package openssl

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

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

func TestRSAEncryptLargeData(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)

	// 1KB plaintext, exceeds 2048-bit key block size (245 bytes)
	src := make([]byte, 1024)
	for i := range src {
		src[i] = byte(i % 256)
	}

	dst, err := RSAEncrypt(src, pubBuf.Bytes())
	assert.NoError(t, err)
	t.Logf("encrypted length: %d bytes (from %d bytes plaintext)", len(dst), len(src))

	// verify ciphertext is multiple blocks
	assert.Greater(t, len(dst), 256, "ciphertext should span multiple blocks")

	decrypted, err := RSADecrypt(dst, priBuf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted, "round-trip chunked encrypt/decrypt failed")
}

func TestRSADecryptPKCS1v15Ciphertext(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)

	block, _ := pem.Decode(priBuf.Bytes())
	assert.NotNil(t, block)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	src := []byte("legacy pkcs1 v1.5 ciphertext")
	dst, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, src)
	assert.NoError(t, err)

	decrypted, err := RSADecrypt(dst, priBuf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestRSAEncryptEmptyData(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)

	dst, err := RSAEncrypt([]byte{}, pubBuf.Bytes())
	assert.NoError(t, err)
	assert.Len(t, dst, 256)

	decrypted, err := RSADecrypt(dst, priBuf.Bytes())
	assert.NoError(t, err)
	assert.Len(t, decrypted, 0)
}

func TestRSAEncryptWithCertificate(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	assert.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	priPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	src := []byte("hello certificate encryption")
	dst, err := RSAEncrypt(src, certPEM)
	assert.NoError(t, err)

	decrypted, err := RSADecrypt(dst, priPEM)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
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
