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

// Generates a new RSA private key.
func RSAGenerateKey(bits int, out io.Writer) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	privateBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: X509PrivateKey}

	return pem.Encode(out, &privateBlock)
}

// Generates an RSA public key from a private key.
func RSAGeneratePublicKey(priKey []byte, out io.Writer) error {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return errors.New("key is invalid format")
	}

	// x509 parse
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
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

// Encrypts data using RSA.
func RSAEncrypt(src, pubKey []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	// x509 parse
	var publicKeyInterface interface{}
	var err error

	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKeyInterface = cert.PublicKey
	} else {
		publicKeyInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the kind of key is not a rsa.PublicKey")
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

// Decrypts data using RSA.
func RSADecrypt(src, priKey []byte) ([]byte, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	// x509 parse
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	keySize := privateKey.PublicKey.Size()
	if keySize <= 0 {
		return nil, errors.New("rsa private key is invalid")
	}

	var dst []byte

	for len(src) > 0 {
		blockSize := len(src)
		if blockSize > keySize {
			blockSize = keySize
		}
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, src[:blockSize])
		if err != nil {
			return nil, err
		}
		dst = append(dst, decrypted...)
		src = src[blockSize:]
	}

	return dst, nil
}

// Signs data using RSA.
func RSASign(src []byte, priKey []byte, hash crypto.Hash) ([]byte, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, errors.New("key is invalid format")
	}

	// x509 parse
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
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

// Verifies a signature using RSA.
func RSAVerify(src, sign, pubKey []byte, hash crypto.Hash) error {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return errors.New("key is invalid format")
	}

	// x509 parse
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return errors.New("the kind of key is not a rsa.PublicKey")
	}

	h := hash.New()
	_, err = h.Write(src)
	if err != nil {
		return err
	}

	bytes := h.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, hash, bytes, sign)
}
