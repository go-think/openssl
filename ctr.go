package openssl

import (
	"bytes"
	"crypto/cipher"
)

// CTREncrypt encrypts data using the CTR (Counter) mode.
func CTREncrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		iv = ctrIVPending(iv, block.BlockSize())
	}

	dst := make([]byte, len(src))
	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(dst, src)

	return dst, nil
}

// CTRDecrypt decrypts data using the CTR (Counter) mode.
func CTRDecrypt(block cipher.Block, src, iv []byte) ([]byte, error) {
	if len(iv) != block.BlockSize() {
		iv = ctrIVPending(iv, block.BlockSize())
	}

	dst := make([]byte, len(src))
	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(dst, src)

	return dst, nil
}

// ctrIVPending automatically pads or truncates the IV to match the block size.
func ctrIVPending(iv []byte, blockSize int) []byte {
	k := len(iv)
	if k < blockSize {
		return append(iv, bytes.Repeat([]byte{0}, blockSize-k)...)
	} else if k > blockSize {
		return iv[0:blockSize]
	}

	return iv
}
