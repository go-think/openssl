package openssl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

// Generates a new RSA private key in PKCS#1 format ("RSA PRIVATE KEY" PEM).
func RSAGenerateKey(bits int, out io.Writer) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	privateBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: X509PrivateKey}

	return pem.Encode(out, &privateBlock)
}

// RSAGenerateKeyPKCS8 generates a new RSA private key in PKCS#8 format
// ("PRIVATE KEY" PEM). The key is accepted by all RSA functions of this
// package that take a private key.
func RSAGenerateKeyPKCS8(bits int, out io.Writer) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	privateBlock := pem.Block{Type: "PRIVATE KEY", Bytes: der}

	return pem.Encode(out, &privateBlock)
}

// Generates an RSA public key from a private key (PKCS#1 or PKCS#8), writing
// it as a PEM block with the historical "RSA PUBLIC KEY" label. The DER
// payload is PKIX SubjectPublicKeyInfo (x509.MarshalPKIXPublicKey); the label
// is kept unchanged for backward compatibility.
func RSAGeneratePublicKey(priKey []byte, out io.Writer) error {
	privateKey, err := parsePrivateKey(priKey)
	if err != nil {
		return err
	}

	publicKey := privateKey.PublicKey
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}

	publicBlock := pem.Block{Type: "RSA PUBLIC KEY", Bytes: X509PublicKey}

	return pem.Encode(out, &publicBlock)
}

// Encrypts data using RSA (PKCS#1 v1.5 padding).
//
// RSAEncrypt and RSADecrypt handle arbitrary length plaintexts automatically
// by chunking according to key size.
func RSAEncrypt(src, pubKey []byte) ([]byte, error) {
	publicKey, err := parsePublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	keySize := publicKey.Size()
	maxBlockSize := keySize - 11
	if maxBlockSize <= 0 {
		return nil, errors.New("rsa public key is too small")
	}

	var dst []byte

	if len(src) == 0 {
		return rsa.EncryptPKCS1v15(rand.Reader, publicKey, src)
	}

	for len(src) > 0 {
		blockSize := len(src)
		if blockSize > maxBlockSize {
			blockSize = maxBlockSize
		}
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, src[:blockSize])
		if err != nil {
			return nil, err
		}
		dst = append(dst, encrypted...)
		src = src[blockSize:]
	}

	return dst, nil
}

// Decrypts data using RSA (PKCS#1 v1.5 padding).
func RSADecrypt(src, priKey []byte) ([]byte, error) {
	privateKey, err := parsePrivateKey(priKey)
	if err != nil {
		return nil, err
	}

	keySize := privateKey.PublicKey.Size()
	if keySize <= 0 {
		return nil, errors.New("rsa private key is invalid")
	}
	if len(src)%keySize != 0 {
		return nil, errors.New("ciphertext length is not a multiple of the key size")
	}

	var dst []byte

	for len(src) > 0 {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, src[:keySize])
		if err != nil {
			return nil, err
		}
		dst = append(dst, decrypted...)
		src = src[keySize:]
	}

	return dst, nil
}

// RSAEncryptOAEP encrypts data using RSA-OAEP (RFC 8017).
//
// The hash h is used both for OAEP encoding (with an empty label) and for
// MGF1, and must match the hash used on the decrypting side. Arbitrary
// length plaintexts are supported by chunking, each block carrying its own
// random padding.
func RSAEncryptOAEP(src, pubKey []byte, h crypto.Hash) ([]byte, error) {
	publicKey, err := parsePublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	if err := validateHash(h); err != nil {
		return nil, err
	}

	maxBlockSize := publicKey.Size() - 2*h.Size() - 2
	if maxBlockSize <= 0 {
		return nil, errors.New("rsa public key is too small for the chosen hash")
	}

	var dst []byte

	if len(src) == 0 {
		return rsa.EncryptOAEP(h.New(), rand.Reader, publicKey, src, nil)
	}

	for len(src) > 0 {
		blockSize := len(src)
		if blockSize > maxBlockSize {
			blockSize = maxBlockSize
		}
		encrypted, err := rsa.EncryptOAEP(h.New(), rand.Reader, publicKey, src[:blockSize], nil)
		if err != nil {
			return nil, err
		}
		dst = append(dst, encrypted...)
		src = src[blockSize:]
	}

	return dst, nil
}

// RSADecryptOAEP decrypts data encrypted with RSA-OAEP (RFC 8017) using the
// same hash as the encryption side.
func RSADecryptOAEP(src, priKey []byte, h crypto.Hash) ([]byte, error) {
	privateKey, err := parsePrivateKey(priKey)
	if err != nil {
		return nil, err
	}
	if err := validateHash(h); err != nil {
		return nil, err
	}

	keySize := privateKey.PublicKey.Size()
	if keySize <= 0 {
		return nil, errors.New("rsa private key is invalid")
	}
	if len(src)%keySize != 0 {
		return nil, errors.New("ciphertext length is not a multiple of the key size")
	}

	var dst []byte

	for len(src) > 0 {
		decrypted, err := rsa.DecryptOAEP(h.New(), rand.Reader, privateKey, src[:keySize], nil)
		if err != nil {
			return nil, err
		}
		dst = append(dst, decrypted...)
		src = src[keySize:]
	}

	return dst, nil
}

// Signs data using RSA (PKCS#1 v1.5 padding).
func RSASign(src []byte, priKey []byte, hash crypto.Hash) ([]byte, error) {
	privateKey, err := parsePrivateKey(priKey)
	if err != nil {
		return nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, err
	}

	h := hash.New()
	_, err = h.Write(src)
	if err != nil {
		return nil, err
	}

	bytes := h.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, bytes)
	if err != nil {
		return nil, err
	}

	return sign, nil
}

// Verifies a signature created with RSASign (PKCS#1 v1.5 padding).
// The public key may be a PKIX public key, a PKCS#1 public key or an X.509
// certificate PEM block.
func RSAVerify(src, sign, pubKey []byte, hash crypto.Hash) error {
	publicKey, err := parsePublicKey(pubKey)
	if err != nil {
		return err
	}
	if err := validateHash(hash); err != nil {
		return err
	}

	h := hash.New()
	_, err = h.Write(src)
	if err != nil {
		return err
	}

	bytes := h.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, hash, bytes, sign)
}

// RSASignPSS signs data using RSASSA-PSS (RFC 8017) with the given hash. The
// salt length is determined automatically (PSSSaltLengthAuto); the matching
// RSAVerifyPSS accepts any salt length.
func RSASignPSS(src []byte, priKey []byte, hash crypto.Hash) ([]byte, error) {
	privateKey, err := parsePrivateKey(priKey)
	if err != nil {
		return nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, err
	}

	h := hash.New()
	_, err = h.Write(src)
	if err != nil {
		return nil, err
	}

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	return rsa.SignPSS(rand.Reader, privateKey, hash, h.Sum(nil), opts)
}

// RSAVerifyPSS verifies a signature created with RSASignPSS (RSASSA-PSS,
// RFC 8017). Any salt length is accepted (PSSSaltLengthAuto). The public key
// may be a PKIX public key, a PKCS#1 public key or an X.509 certificate PEM
// block.
func RSAVerifyPSS(src, sign, pubKey []byte, hash crypto.Hash) error {
	publicKey, err := parsePublicKey(pubKey)
	if err != nil {
		return err
	}
	if err := validateHash(hash); err != nil {
		return err
	}

	h := hash.New()
	_, err = h.Write(src)
	if err != nil {
		return err
	}

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	return rsa.VerifyPSS(publicKey, hash, h.Sum(nil), sign, opts)
}

// validateHash reports a regular error when the hash implementation is not
// linked into the program, instead of letting crypto.Hash.Size or
// crypto.Hash.New panic. Referencing a crypto.Hash constant alone does not
// link the implementation: the corresponding crypto/<hash> package must be
// imported somewhere in the program.
func validateHash(h crypto.Hash) error {
	if !h.Available() {
		return errors.New("hash function is unavailable")
	}
	return nil
}

// parsePrivateKey parses a PEM-encoded RSA private key. Both PKCS#1
// ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") formats are accepted.
func parsePrivateKey(priKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err8 != nil {
			return nil, errors.New("failed to parse private key")
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("the kind of key is not a rsa.PrivateKey")
		}
		return rsaKey, nil
	}

	return privateKey, nil
}

// parsePublicKey parses a PEM-encoded RSA public key. The DER payload is
// detected automatically (PKIX SubjectPublicKeyInfo or PKCS#1) regardless of
// the PEM label — this package itself writes PKIX DER under the historical
// "RSA PUBLIC KEY" label — so the label must not be used to infer the DER
// structure. X.509 certificate PEM blocks are also accepted.
func parsePublicKey(pubKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("the kind of key is not a rsa.PublicKey")
		}
		return publicKey, nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("the kind of key is not a rsa.PublicKey")
		}
		return rsaKey, nil
	}

	// PKCS#1 "RSA PUBLIC KEY" DER, as produced by e.g.
	// openssl rsa -pubin -RSAPublicKey_out
	rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse public key")
	}

	return rsaKey, nil
}
