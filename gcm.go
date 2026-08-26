package openssl

import (
	"crypto/cipher"
	"errors"
)

// GCMEncrypt encrypts data using GCM (Galois/Counter Mode).
//
// Parameters:
//   - nonce: 12-byte initialization vector (often referred to as 'iv' in other languages/libraries).
//   - additionalData: optional authenticated additional data (AAD), can be nil.
//
// Returns:
//   - ciphertext with a 16-byte authentication tag appended at the end (format: ciphertext || tag).
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
//
// Parameters:
//   - src: input ciphertext containing the 16-byte authentication tag at the end (format: ciphertext || tag).
//   - nonce: 12-byte initialization vector (referred to as 'iv' in other languages).
//   - additionalData: authenticated additional data (AAD) that must match the data used during encryption.
//
// Returns:
//   - decrypted plaintext after authentication tag verification.
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


