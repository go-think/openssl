package openssl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

// Ed25519GenerateKey generates an Ed25519 private key in PKCS#8 PEM format
// ("PRIVATE KEY").
func Ed25519GenerateKey(out io.Writer) error {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	return pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Ed25519GeneratePublicKey extracts an Ed25519 public key from a PKCS#8 PEM
// private key and writes it in PKIX PEM format ("PUBLIC KEY").
func Ed25519GeneratePublicKey(priKey []byte, out io.Writer) error {
	privateKey, err := parseEd25519PrivateKey(priKey)
	if err != nil {
		return err
	}

	der, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return err
	}

	return pem.Encode(out, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Ed25519Sign signs src using an Ed25519 PKCS#8 PEM private key.
func Ed25519Sign(src, priKey []byte) ([]byte, error) {
	privateKey, err := parseEd25519PrivateKey(priKey)
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(privateKey, src), nil
}

// Ed25519Verify verifies an Ed25519 signature using a PKIX PEM public key or
// an X.509 certificate PEM block.
func Ed25519Verify(src, sign, pubKey []byte) error {
	publicKey, err := parseEd25519PublicKey(pubKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, src, sign) {
		return errors.New("openssl: Ed25519 signature verification failed")
	}
	return nil
}

func parseEd25519PrivateKey(keyPEM []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("openssl: key is invalid format")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("openssl: failed to parse PKCS#8 private key")
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("openssl: key is not an Ed25519 private key")
	}
	return privateKey, nil
}

func parseEd25519PublicKey(keyPEM []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("openssl: key is invalid format")
	}

	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("openssl: certificate public key is not Ed25519")
		}
		return publicKey, nil
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("openssl: failed to parse PKIX public key")
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("openssl: key is not an Ed25519 public key")
	}
	return publicKey, nil
}
