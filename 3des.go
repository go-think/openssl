package openssl

import "crypto/des"

// Des3ECBEncrypt encrypts data using the ECB mode of the 3DES algorithm.
func Des3ECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(block, src, padding)
}

// Des3ECBDecrypt decrypts data using the ECB mode of the 3DES algorithm.
func Des3ECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return ECBDecrypt(block, src, padding)
}

// Des3CBCEncrypt encrypts data using the CBC mode of the 3DES algorithm.
func Des3CBCEncrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCEncrypt(block, src, iv, padding)
}

// Des3CBCDecrypt decrypts data using the CBC mode of the 3DES algorithm.
func Des3CBCDecrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCDecrypt(block, src, iv, padding)
}

// Des3CFBEncrypt encrypts data using the CFB mode of the 3DES algorithm.
func Des3CFBEncrypt(src, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return CFBEncrypt(block, src, iv)
}

// Des3CFBDecrypt decrypts data using the CFB mode of the 3DES algorithm.
func Des3CFBDecrypt(src, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return CFBDecrypt(block, src, iv)
}

// Des3OFBEncrypt encrypts data using the OFB mode of the 3DES algorithm.
func Des3OFBEncrypt(src, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return OFBEncrypt(block, src, iv)
}

// Des3OFBDecrypt decrypts data using the OFB mode of the 3DES algorithm.
func Des3OFBDecrypt(src, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return OFBDecrypt(block, src, iv)
}

// Des3CTREncrypt encrypts data using the CTR mode of the 3DES algorithm.
func Des3CTREncrypt(src, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return CTREncrypt(block, src, iv)
}

// Des3CTRDecrypt decrypts data using the CTR mode of the 3DES algorithm.
func Des3CTRDecrypt(src, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return CTRDecrypt(block, src, iv)
}
