package openssl

import (
	"bytes"
	"crypto/cipher"
	"errors"
)

// CBCEncrypt encrypts data using the CBC (Cipher Block Chaining) mode.
func CBCEncrypt(block cipher.Block, src, iv []byte, padding string) ([]byte, error) {
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)

	encryptData := make([]byte, len(src))

	if len(iv) != block.BlockSize() {
		// auto pad length to block size
		iv = cbcIVPending(iv, block.BlockSize())
		//return nil, errors.New("CBCEncrypt: IV length must equal block size")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptData, src)

	return encryptData, nil
}

// CBCDecrypt decrypts data using the CBC (Cipher Block Chaining) mode.
func CBCDecrypt(block cipher.Block, src, iv []byte, padding string) ([]byte, error) {
	if len(src)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext length is not a multiple of the block size")
	}

	dst := make([]byte, len(src))

	if len(iv) != block.BlockSize() {
		// auto pad length to block size
		iv = cbcIVPending(iv, block.BlockSize())
		//return nil, errors.New("CBCDecrypt: IV length must equal block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, src)

	return UnPadding(padding, dst)
}

// cbcIVPending automatically pads or truncates the IV to match the block size.
func cbcIVPending(iv []byte, blockSize int) []byte {
	k := len(iv)
	if k < blockSize {
		return append(iv, bytes.Repeat([]byte{0}, blockSize-k)...)
	} else if k > blockSize {
		return iv[0:blockSize]
	}

	return iv
}
