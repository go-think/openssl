package openssl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// AesECBEncrypt encrypts data using the ECB mode of the AES algorithm.
func AesECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := AesNewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(block, src, padding)
}

// AesECBDecrypt decrypts data using the ECB mode of the AES algorithm.
func AesECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := AesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return ECBDecrypt(block, src, padding)
}

// AesCBCEncrypt encrypts data using the CBC mode of the AES algorithm.
func AesCBCEncrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := AesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCEncrypt(block, src, iv, padding)
}

// AesCBCDecrypt decrypts data using the CBC mode of the AES algorithm.
func AesCBCDecrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := AesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCDecrypt(block, src, iv, padding)
}

// AesGCMEncrypt encrypts data using the GCM mode of the AES algorithm.
func AesGCMEncrypt(src, key, nonce, additionalData []byte) ([]byte, error) {
	block, err := AesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return GCMEncrypt(block, src, nonce, additionalData)
}

// AesGCMDecrypt decrypts data using the GCM mode of the AES algorithm.
func AesGCMDecrypt(src, key, nonce, additionalData []byte) ([]byte, error) {
	block, err := AesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return GCMDecrypt(block, src, nonce, additionalData)
}


// AesNewCipher creates and returns a new AES cipher block. Automatically pads the key length.
func AesNewCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(aesKeyPending(key))
}

// aesKeyPending ensures the key length is 16, 24, or 32 bytes (128, 192, or 256 bits).
func aesKeyPending(key []byte) []byte {
	k := len(key)
	count := 0
	switch true {
	case k <= 16:
		count = 16 - k
	case k <= 24:
		count = 24 - k
	case k <= 32:
		count = 32 - k
	default:
		return key[:32]
	}
	if count == 0 {
		return key
	}

	return append(key, bytes.Repeat([]byte{0}, count)...)
}
