package openssl

import (
	"crypto/cipher"
	"errors"
)

// GCMEncrypt encrypts data using GCM (Galois/Counter Mode).
func GCMEncrypt(block cipher.Block, src, nonce, additionalData []byte) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, errors.New("GCMEncrypt: incorrect nonce length")
	}

	return aesgcm.Seal(nil, nonce, src, additionalData), nil
}

// GCMDecrypt decrypts data using GCM (Galois/Counter Mode).
func GCMDecrypt(block cipher.Block, src, nonce, additionalData []byte) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, errors.New("GCMDecrypt: incorrect nonce length")
	}

	if len(src) < aesgcm.Overhead() {
		return nil, errors.New("GCMDecrypt: ciphertext too short")
	}

	return aesgcm.Open(nil, nonce, src, additionalData)
}

