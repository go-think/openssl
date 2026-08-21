package openssl

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
)

// DesECBEncrypt encrypts data using the ECB mode of the DES algorithm.
func DesECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(block, src, padding)
}

// DesECBDecrypt decrypts data using the ECB mode of the DES algorithm.
func DesECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return ECBDecrypt(block, src, padding)
}

// DesCBCEncrypt encrypts data using the CBC mode of the DES algorithm.
func DesCBCEncrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCEncrypt(block, src, iv, padding)
}

// DesCBCDecrypt decrypts data using the CBC mode of the DES algorithm.
func DesCBCDecrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCDecrypt(block, src, iv, padding)
}

// DesCFBEncrypt encrypts data using the CFB mode of the DES algorithm.
func DesCFBEncrypt(src, key, iv []byte) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CFBEncrypt(block, src, iv)
}

// DesCFBDecrypt decrypts data using the CFB mode of the DES algorithm.
func DesCFBDecrypt(src, key, iv []byte) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CFBDecrypt(block, src, iv)
}

// DesOFBEncrypt encrypts data using the OFB mode of the DES algorithm.
func DesOFBEncrypt(src, key, iv []byte) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return OFBEncrypt(block, src, iv)
}

// DesOFBDecrypt decrypts data using the OFB mode of the DES algorithm.
func DesOFBDecrypt(src, key, iv []byte) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return OFBDecrypt(block, src, iv)
}

// DesCTREncrypt encrypts data using the CTR mode of the DES algorithm.
func DesCTREncrypt(src, key, iv []byte) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CTREncrypt(block, src, iv)
}

// DesCTRDecrypt decrypts data using the CTR mode of the DES algorithm.
func DesCTRDecrypt(src, key, iv []byte) ([]byte, error) {
	block, err := DesNewCipher(key)
	if err != nil {
		return nil, err
	}

	return CTRDecrypt(block, src, iv)
}

// DesNewCipher creates and returns a new DES cipher block, adjusting the key length if necessary.
func DesNewCipher(key []byte) (cipher.Block, error) {
	if len(key) < 8 {
		key = append(key, bytes.Repeat([]byte{0}, 8-len(key))...)
	} else if len(key) > 8 {
		key = key[:8]
	}

	return des.NewCipher(key)
}
