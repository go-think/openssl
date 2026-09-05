package openssl

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
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

// rsaTestKeyPair generates a 2048-bit key pair and returns the private key
// (PKCS#1 PEM) and public key (PKIX PEM inside an "RSA PUBLIC KEY" block).
func rsaTestKeyPair(t *testing.T) (priPEM []byte, pubPEM []byte) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKey(2048, priBuf)
	assert.NoError(t, err)

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(priBuf.Bytes(), pubBuf)
	assert.NoError(t, err)

	return priBuf.Bytes(), pubBuf.Bytes()
}

// rsaTestCertificate returns a self-signed X.509 certificate PEM for the key.
func rsaTestCertificate(t *testing.T, privateKey *rsa.PrivateKey) []byte {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	assert.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestRSAGenerateKeyPKCS8(t *testing.T) {
	priBuf := bytes.NewBuffer(nil)
	err := RSAGenerateKeyPKCS8(2048, priBuf)
	assert.NoError(t, err)

	block, _ := pem.Decode(priBuf.Bytes())
	assert.NotNil(t, block, "Failed to decode private key")
	assert.Equal(t, "PRIVATE KEY", block.Type, "Invalid key type")

	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err, "Failed to parse PKCS#8 private key")
}

func TestRSAGeneratePublicKeyFromPKCS8(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	assert.NoError(t, err)
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	pubBuf := bytes.NewBuffer(nil)
	err = RSAGeneratePublicKey(pkcs8PEM, pubBuf)
	assert.NoError(t, err)

	block, _ := pem.Decode(pubBuf.Bytes())
	assert.NotNil(t, block)
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err)
}

// TestRSAKeyParsingMatrix exercises every accepted PEM flavor: private keys
// in PKCS#1 and PKCS#8, public keys as PKIX, PKCS#1 and X.509 certificate.
func TestRSAKeyParsingMatrix(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	pkcs1PrivPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	assert.NoError(t, err)
	pkcs8PrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	pkixDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NoError(t, err)
	pkixPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})

	pkcs1PubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)})

	certPEM := rsaTestCertificate(t, privateKey)

	publicPEMs := map[string][]byte{"pkix": pkixPubPEM, "pkcs1 public": pkcs1PubPEM, "certificate": certPEM}
	privatePEMs := map[string][]byte{"pkcs1": pkcs1PrivPEM, "pkcs8": pkcs8PrivPEM}

	src := []byte("parsing matrix")

	for pubName, pubPEM := range publicPEMs {
		dst, err := RSAEncrypt(src, pubPEM)
		assert.NoError(t, err, "RSAEncrypt with %s", pubName)

		for priName, priPEM := range privatePEMs {
			decrypted, err := RSADecrypt(dst, priPEM)
			assert.NoError(t, err, "RSADecrypt with %s private key", priName)
			assert.Equal(t, src, decrypted)
		}

		sign, err := RSASign(src, pkcs1PrivPEM, crypto.SHA256)
		assert.NoError(t, err)
		assert.NoError(t, RSAVerify(src, sign, pubPEM, crypto.SHA256), "RSAVerify with %s", pubName)
	}
}

func TestRSAPKCS8PrivateKeyRoundTrip(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	assert.NoError(t, err)
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	pkixDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})

	src := []byte("pkcs8 private key round trip")

	dst, err := RSAEncrypt(src, pubPEM)
	assert.NoError(t, err)
	decrypted, err := RSADecrypt(dst, pkcs8PEM)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)

	sign, err := RSASign(src, pkcs8PEM, crypto.SHA256)
	assert.NoError(t, err)
	assert.NoError(t, RSAVerify(src, sign, pubPEM, crypto.SHA256))
}

func TestRSAEncryptOAEP(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	src := []byte("123456")

	dst, err := RSAEncryptOAEP(src, pubPEM, crypto.SHA1)
	assert.NoError(t, err)
	decrypted, err := RSADecryptOAEP(dst, priPEM, crypto.SHA1)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)

	dst, err = RSAEncryptOAEP(src, pubPEM, crypto.SHA256)
	assert.NoError(t, err)
	decrypted, err = RSADecryptOAEP(dst, priPEM, crypto.SHA256)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted)
}

func TestRSAEncryptOAEPLargeData(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	// 1KB plaintext, exceeds the 2048-bit SHA-1 OAEP chunk size (214 bytes)
	src := make([]byte, 1024)
	for i := range src {
		src[i] = byte(i % 256)
	}

	dst, err := RSAEncryptOAEP(src, pubPEM, crypto.SHA1)
	assert.NoError(t, err)
	assert.Greater(t, len(dst), 256, "ciphertext should span multiple blocks")

	decrypted, err := RSADecryptOAEP(dst, priPEM, crypto.SHA1)
	assert.NoError(t, err)
	assert.Equal(t, src, decrypted, "round-trip chunked OAEP encrypt/decrypt failed")
}

func TestRSAEncryptOAEPEmptyData(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	dst, err := RSAEncryptOAEP([]byte{}, pubPEM, crypto.SHA1)
	assert.NoError(t, err)
	assert.Len(t, dst, 256)

	decrypted, err := RSADecryptOAEP(dst, priPEM, crypto.SHA1)
	assert.NoError(t, err)
	assert.Len(t, decrypted, 0)
}

func TestRSADecryptOAEPHashMismatch(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	dst, err := RSAEncryptOAEP([]byte("123456"), pubPEM, crypto.SHA1)
	assert.NoError(t, err)

	_, err = RSADecryptOAEP(dst, priPEM, crypto.SHA256)
	assert.Error(t, err)
}

func TestRSADecryptOAEPTamperedCiphertext(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	dst, err := RSAEncryptOAEP([]byte("123456"), pubPEM, crypto.SHA1)
	assert.NoError(t, err)

	dst[0] ^= 0xFF
	_, err = RSADecryptOAEP(dst, priPEM, crypto.SHA1)
	assert.Error(t, err, "OAEP integrity check should reject tampered ciphertext")
}

func TestRSASignPSS(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	src := []byte("pss signature")

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		sign, err := RSASignPSS(src, priPEM, hash)
		assert.NoError(t, err)
		assert.NoError(t, RSAVerifyPSS(src, sign, pubPEM, hash), "PSS round trip with %s", hash)
	}
}

func TestRSAVerifyWithCertificate(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	certPEM := rsaTestCertificate(t, privateKey)
	priPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	src := []byte("verify with certificate")

	sign, err := RSASign(src, priPEM, crypto.SHA256)
	assert.NoError(t, err)
	assert.NoError(t, RSAVerify(src, sign, certPEM, crypto.SHA256))

	pssSign, err := RSASignPSS(src, priPEM, crypto.SHA256)
	assert.NoError(t, err)
	assert.NoError(t, RSAVerifyPSS(src, pssSign, certPEM, crypto.SHA256))
}

func TestRSAVerifyTamperedSignature(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	src := []byte("123456")

	sign, err := RSASign(src, priPEM, crypto.SHA256)
	assert.NoError(t, err)
	tampered := append([]byte(nil), sign...)
	tampered[0] ^= 0xFF
	assert.Error(t, RSAVerify(src, tampered, pubPEM, crypto.SHA256))

	pssSign, err := RSASignPSS(src, priPEM, crypto.SHA256)
	assert.NoError(t, err)
	tamperedPSS := append([]byte(nil), pssSign...)
	tamperedPSS[len(tamperedPSS)-1] ^= 0xFF
	assert.Error(t, RSAVerifyPSS(src, tamperedPSS, pubPEM, crypto.SHA256))
}

func TestRSAInvalidKeys(t *testing.T) {
	// not PEM at all
	_, err := RSAEncrypt([]byte("123456"), []byte("not a pem"))
	assert.EqualError(t, err, "key is invalid format")
	_, err = RSADecrypt([]byte{}, []byte("not a pem"))
	assert.EqualError(t, err, "key is invalid format")

	// non-RSA public key (Ed25519)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	assert.NoError(t, err)
	edPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER})
	_, err = RSAEncrypt([]byte("123456"), edPubPEM)
	assert.EqualError(t, err, "the kind of key is not a rsa.PublicKey")

	// non-RSA private key (Ed25519 inside PKCS#8)
	edPrivDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	assert.NoError(t, err)
	edPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPrivDER})
	_, err = RSADecrypt([]byte{}, edPrivPEM)
	assert.EqualError(t, err, "the kind of key is not a rsa.PrivateKey")

	// PEM block with garbage DER: neither format applies, unified error
	garbagePub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01, 0x02, 0x03}})
	_, err = RSAEncrypt([]byte("123456"), garbagePub)
	assert.EqualError(t, err, "failed to parse public key")

	garbagePriv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01, 0x02, 0x03}})
	_, err = RSADecrypt([]byte{}, garbagePriv)
	assert.EqualError(t, err, "failed to parse private key")
}

func TestRSAInvalidHashReturnsError(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	src := []byte("123456")
	var zeroHash crypto.Hash
	unlinkedHash := crypto.Hash(99) // no implementation registered for this value

	expectErr := func(name string, err error) {
		assert.EqualError(t, err, "hash function is unavailable", name)
	}

	_, err := RSAEncryptOAEP(src, pubPEM, zeroHash)
	expectErr("RSAEncryptOAEP zero hash", err)
	_, err = RSAEncryptOAEP(src, pubPEM, unlinkedHash)
	expectErr("RSAEncryptOAEP unlinked hash", err)
	_, err = RSADecryptOAEP(src, priPEM, zeroHash)
	expectErr("RSADecryptOAEP zero hash", err)
	_, err = RSASign(src, priPEM, zeroHash)
	expectErr("RSASign zero hash", err)
	err = RSAVerify(src, []byte("sig"), pubPEM, zeroHash)
	expectErr("RSAVerify zero hash", err)
	_, err = RSASignPSS(src, priPEM, zeroHash)
	expectErr("RSASignPSS zero hash", err)
	err = RSAVerifyPSS(src, []byte("sig"), pubPEM, zeroHash)
	expectErr("RSAVerifyPSS zero hash", err)
}

func TestRSADecryptNonBlockMultiple(t *testing.T) {
	priPEM, pubPEM := rsaTestKeyPair(t)

	dst, err := RSAEncrypt([]byte("123456"), pubPEM)
	assert.NoError(t, err)
	_, err = RSADecrypt(dst[:len(dst)-10], priPEM)
	assert.EqualError(t, err, "ciphertext length is not a multiple of the key size")

	oaepDst, err := RSAEncryptOAEP([]byte("123456"), pubPEM, crypto.SHA1)
	assert.NoError(t, err)
	_, err = RSADecryptOAEP(oaepDst[:len(oaepDst)-1], priPEM, crypto.SHA1)
	assert.EqualError(t, err, "ciphertext length is not a multiple of the key size")

	// aligned inputs still decrypt correctly
	decrypted, err := RSADecrypt(dst, priPEM)
	assert.NoError(t, err)
	assert.Equal(t, []byte("123456"), decrypted)
	decrypted, err = RSADecryptOAEP(oaepDst, priPEM, crypto.SHA1)
	assert.NoError(t, err)
	assert.Equal(t, []byte("123456"), decrypted)
}
