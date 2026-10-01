package openssl

import (
	"crypto/cipher"
	"errors"
)

// Encrypts data using the ECB (Electronic Codebook) mode.
func ECBEncrypt(block cipher.Block, src []byte, padding string) ([]byte, error) {
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)

	encryptData := make([]byte, len(src))

	ecb := NewECBEncrypter(block)
	ecb.CryptBlocks(encryptData, src)

	return encryptData, nil
}

// Decrypts data using the ECB (Electronic Codebook) mode.
func ECBDecrypt(block cipher.Block, src []byte, padding string) ([]byte, error) {
	if len(src)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext length is not a multiple of the block size")
	}

	dst := make([]byte, len(src))

	mode := NewECBDecrypter(block)
	mode.CryptBlocks(dst, src)

	return UnPadding(padding, dst)
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

// Creates a new ECB struct.
func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

// Encrypts a series of blocks using the ECB mode.
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

// Decrypts a series of blocks using the ECB mode.
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
