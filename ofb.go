package openssl

import (
	"bytes"
	"crypto/cipher"
)

// OFBEncrypt encrypts data using the OFB (Output Feedback) mode.
func OFBEncrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		iv = ofbIVPending(iv, block.BlockSize())
	}

	dst := make([]byte, len(src))
	mode := cipher.NewOFB(block, iv)
	mode.XORKeyStream(dst, src)

	return dst, nil
}

// OFBDecrypt decrypts data using the OFB (Output Feedback) mode.
func OFBDecrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		iv = ofbIVPending(iv, block.BlockSize())
	}

	dst := make([]byte, len(src))
	mode := cipher.NewOFB(block, iv)
	mode.XORKeyStream(dst, src)

	return dst, nil
}

// ofbIVPending automatically pads or truncates the IV to match the block size.
func ofbIVPending(iv []byte, blockSize int) []byte {
	k := len(iv)
	if k < blockSize {
		return append(iv, bytes.Repeat([]byte{0}, blockSize-k)...)
	} else if k > blockSize {
		return iv[0:blockSize]
	}

	return iv
}
