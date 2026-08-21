package openssl

import (
	"bytes"
	"crypto/cipher"
)

// CFBEncrypt encrypts data using the CFB (Cipher Feedback) mode.
func CFBEncrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		iv = cfbIVPending(iv, block.BlockSize())
	}

	dst := make([]byte, len(src))
	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(dst, src)

	return dst, nil
}

// CFBDecrypt decrypts data using the CFB (Cipher Feedback) mode.
func CFBDecrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		iv = cfbIVPending(iv, block.BlockSize())
	}

	dst := make([]byte, len(src))
	mode := cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(dst, src)

	return dst, nil
}

// cfbIVPending automatically pads or truncates the IV to match the block size.
func cfbIVPending(iv []byte, blockSize int) []byte {
	k := len(iv)
	if k < blockSize {
		return append(iv, bytes.Repeat([]byte{0}, blockSize-k)...)
	} else if k > blockSize {
		return iv[0:blockSize]
	}

	return iv
}
