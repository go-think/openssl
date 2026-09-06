package openssl

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

// hexBytes decodes a lowercase hex string into bytes, panicking on malformed
// input. For use with official test vectors only.
func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPBKDF2(t *testing.T) {
	tests := []struct {
		name     string
		password string
		salt     string
		iter     int
		keyLen   int
		h        func() hash.Hash
		want     string // expected derived key, lowercase hex
	}{
		// RFC 6070 test vectors (PBKDF2-HMAC-SHA1)
		{name: "RFC6070 SHA1 c=1", password: "password", salt: "salt", iter: 1, keyLen: 20, h: sha1.New, want: "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{name: "RFC6070 SHA1 c=2", password: "password", salt: "salt", iter: 2, keyLen: 20, h: sha1.New, want: "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{name: "RFC6070 SHA1 c=4096", password: "password", salt: "salt", iter: 4096, keyLen: 20, h: sha1.New, want: "4b007901b765489abead49d926f721d065a429c1"},
		{name: "RFC6070 SHA1 multi-block", password: "passwordPASSWORDpassword", salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt", iter: 4096, keyLen: 25, h: sha1.New, want: "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
		{name: "RFC6070 SHA1 embedded NUL", password: "pass\x00word", salt: "sa\x00lt", iter: 4096, keyLen: 16, h: sha1.New, want: "56fa6aa75548099dcc37d7f03425e0c3"},
		// PBKDF2-HMAC-SHA256 public test vectors
		{name: "SHA256 c=1", password: "password", salt: "salt", iter: 1, keyLen: 32, h: sha256.New, want: "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{name: "SHA256 c=2", password: "password", salt: "salt", iter: 2, keyLen: 32, h: sha256.New, want: "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{name: "SHA256 c=4096", password: "password", salt: "salt", iter: 4096, keyLen: 32, h: sha256.New, want: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{name: "SHA256 multi-block", password: "passwordPASSWORDpassword", salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt", iter: 4096, keyLen: 40, h: sha256.New, want: "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"},
		// PBKDF2-HMAC-SHA512 public vectors
		{name: "SHA512 c=1", password: "password", salt: "salt", iter: 1, keyLen: 64, h: sha512.New, want: "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"},
		{name: "SHA512 c=2", password: "password", salt: "salt", iter: 2, keyLen: 64, h: sha512.New, want: "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PBKDF2(tt.h, []byte(tt.password), []byte(tt.salt), tt.iter, tt.keyLen)
			assert.NoError(t, err)
			assert.Equal(t, tt.keyLen, len(got))
			assert.Equal(t, tt.keyLen, cap(got), "returned PBKDF2 slice capacity must be capped to keyLen")
			assert.Equal(t, tt.want, hex.EncodeToString(got), "PBKDF2 output should match the official test vector")
		})
	}
}

func TestPBKDF2Errors(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("PBKDF2 RFC-limit test requires a 64-bit int")
	}

	tests := []struct {
		name   string
		iter   int
		keyLen int
		h      func() hash.Hash
	}{
		{name: "iter=0", iter: 0, keyLen: 32, h: sha256.New},
		{name: "iter<0", iter: -1, keyLen: 32, h: sha256.New},
		{name: "keyLen=0", iter: 1, keyLen: 0, h: sha256.New},
		{name: "keyLen<0", iter: 1, keyLen: -8, h: sha256.New},
		{name: "keyLen exceeds RFC limit", iter: 1, keyLen: int(uint64(^uint32(0))*uint64(sha256.Size)) + 1, h: sha256.New},
		{name: "nil hash", iter: 1, keyLen: 32, h: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PBKDF2(tt.h, []byte("password"), []byte("salt"), tt.iter, tt.keyLen)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestHKDFRFC5869(t *testing.T) {
	// Build the 80-byte sequences 0x00..0x4f, 0x60..0xaf and 0xb0..0xff used
	// by RFC 5869 test cases 2 and 5.
	ikmSeq := make([]byte, 80)
	saltSeq := make([]byte, 80)
	infoSeq := make([]byte, 80)
	for i := 0; i < 80; i++ {
		ikmSeq[i] = byte(i)
		saltSeq[i] = byte(0x60 + i)
		infoSeq[i] = byte(0xb0 + i)
	}

	tests := []struct {
		name string
		h    func() hash.Hash
		ikm  []byte
		salt []byte
		info []byte
		prk  string // expected pseudorandom key, lowercase hex
		okm  string // expected output keying material, lowercase hex
	}{
		{
			name: "Case 1 SHA-256 basic",
			h:    sha256.New,
			ikm:  bytes.Repeat([]byte{0x0b}, 22),
			salt: hexBytes("000102030405060708090a0b0c"),
			info: hexBytes("f0f1f2f3f4f5f6f7f8f9"),
			prk:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			okm:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "Case 2 SHA-256 longer inputs/outputs",
			h:    sha256.New,
			ikm:  ikmSeq,
			salt: saltSeq,
			info: infoSeq,
			prk:  "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			okm:  "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name: "Case 3 SHA-256 zero-length salt/info",
			h:    sha256.New,
			ikm:  bytes.Repeat([]byte{0x0b}, 22),
			salt: []byte{},
			info: []byte{},
			prk:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			okm:  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
		{
			name: "Case 4 SHA-1 basic",
			h:    sha1.New,
			ikm:  bytes.Repeat([]byte{0x0b}, 11),
			salt: hexBytes("000102030405060708090a0b0c"),
			info: hexBytes("f0f1f2f3f4f5f6f7f8f9"),
			prk:  "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
			okm:  "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
		},
		{
			name: "Case 5 SHA-1 longer inputs/outputs",
			h:    sha1.New,
			ikm:  ikmSeq,
			salt: saltSeq,
			info: infoSeq,
			prk:  "8adae09a2a307059478d309b26c4115a224cfaf6",
			okm:  "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
		},
		{
			name: "Case 6 SHA-1 zero-length salt/info",
			h:    sha1.New,
			ikm:  bytes.Repeat([]byte{0x0b}, 22),
			salt: []byte{},
			info: []byte{},
			prk:  "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
			okm:  "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
		},
		{
			// salt not provided: defaults to HashLen zero octets
			name: "Case 7 SHA-1 salt not provided",
			h:    sha1.New,
			ikm:  bytes.Repeat([]byte{0x0c}, 22),
			salt: nil,
			info: []byte{},
			prk:  "2adccada18779e7c2077ad2eb19d3f3e731385dd",
			okm:  "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyLength := len(tt.okm) / 2

			prk, err := HKDFExtract(tt.h, tt.ikm, tt.salt)
			assert.NoError(t, err)
			assert.Equal(t, tt.prk, hex.EncodeToString(prk), "Extract output should match the RFC 5869 PRK")

			okm, err := HKDF(tt.h, tt.ikm, tt.salt, tt.info, keyLength)
			assert.NoError(t, err)
			assert.Equal(t, keyLength, cap(okm), "HKDF slice capacity must be capped to keyLength")
			assert.Equal(t, tt.okm, hex.EncodeToString(okm), "HKDF output should match the RFC 5869 OKM")

			// One-shot HKDF must equal the manual Extract + Expand composition.
			prk2, err := HKDFExtract(tt.h, tt.ikm, tt.salt)
			assert.NoError(t, err)
			expanded, err := HKDFExpand(tt.h, prk2, tt.info, keyLength)
			assert.NoError(t, err)
			assert.Equal(t, keyLength, cap(expanded), "HKDFExpand slice capacity must be capped to keyLength")
			assert.Equal(t, tt.okm, hex.EncodeToString(expanded), "Expand should match the RFC 5869 OKM")
		})
	}
}

func TestHKDFEmptySaltEqualsHashLenZeroSalt(t *testing.T) {
	// RFC 5869: when salt is not provided it defaults to a hash-size string
	// of zero bytes. HMAC zero-pads keys, so nil and empty salt must equal
	// an explicit hash-length all-zero salt.
	nilSalt, err := HKDFExtract(sha256.New, []byte("secret"), nil)
	assert.NoError(t, err)
	emptySalt, err := HKDFExtract(sha256.New, []byte("secret"), []byte{})
	assert.NoError(t, err)
	zeroSalt, err := HKDFExtract(sha256.New, []byte("secret"), make([]byte, sha256.Size))
	assert.NoError(t, err)

	assert.Equal(t, nilSalt, emptySalt)
	assert.Equal(t, nilSalt, zeroSalt)
}

func TestHKDFErrors(t *testing.T) {
	prk, err := HKDFExtract(sha256.New, []byte("secret"), []byte("salt"))
	assert.NoError(t, err)

	// keyLength exceeding 255 * hash size is rejected, the exact maximum is allowed
	_, err = HKDFExpand(sha256.New, prk, nil, 255*sha256.Size+1)
	assert.Error(t, err)
	okm, err := HKDFExpand(sha256.New, prk, nil, 255*sha256.Size)
	assert.NoError(t, err)
	assert.Equal(t, 255*sha256.Size, len(okm))

	// empty pseudorandom key
	_, err = HKDFExpand(sha256.New, nil, nil, 32)
	assert.Error(t, err)

	// keyLength <= 0
	_, err = HKDFExpand(sha256.New, prk, nil, 0)
	assert.Error(t, err)
	_, err = HKDFExpand(sha256.New, prk, nil, -1)
	assert.Error(t, err)

	// nil hash constructor
	_, err = HKDFExtract(nil, []byte("secret"), []byte("salt"))
	assert.Error(t, err)
	_, err = HKDFExpand(nil, prk, nil, 32)
	assert.Error(t, err)
	_, err = HKDF(nil, []byte("secret"), nil, nil, 32)
	assert.Error(t, err)
}

func TestHKDFReader(t *testing.T) {
	reader, err := HKDFReader(sha256.New, []byte("secret"), []byte("salt"), []byte("info"))
	assert.NoError(t, err)

	// Stream 64 bytes in chunks of 16 bytes
	chunk := make([]byte, 16)
	var streamOutput []byte
	for i := 0; i < 4; i++ {
		n, err := io.ReadFull(reader, chunk)
		assert.NoError(t, err)
		assert.Equal(t, 16, n)
		streamOutput = append(streamOutput, chunk...)
	}

	// Compare with one-shot HKDF
	oneshot, err := HKDF(sha256.New, []byte("secret"), []byte("salt"), []byte("info"), 64)
	assert.NoError(t, err)
	assert.Equal(t, oneshot, streamOutput)

	// Test HKDFExpandReader directly
	prk, err := HKDFExtract(sha256.New, []byte("secret"), []byte("salt"))
	assert.NoError(t, err)
	expandReader, err := HKDFExpandReader(sha256.New, prk, []byte("info"))
	assert.NoError(t, err)

	fullBuf := make([]byte, 64)
	_, err = io.ReadFull(expandReader, fullBuf)
	assert.NoError(t, err)
	assert.Equal(t, oneshot, fullBuf)

	// Test errors for nil / empty inputs
	_, err = HKDFReader(nil, []byte("secret"), nil, nil)
	assert.Error(t, err)
	_, err = HKDFExpandReader(nil, prk, nil)
	assert.Error(t, err)
	_, err = HKDFExpandReader(sha256.New, nil, nil)
	assert.Error(t, err)

	// Test stream exhaustion past 255 blocks (255 * 32 = 8160 bytes for SHA-256)
	maxBuf := make([]byte, 255*sha256.Size)
	exhaustReader, err := HKDFExpandReader(sha256.New, prk, nil)
	assert.NoError(t, err)
	n, err := io.ReadFull(exhaustReader, maxBuf)
	assert.NoError(t, err)
	assert.Equal(t, 255*sha256.Size, n)

	// A partial read that hits exhaustion should return the bytes read plus EOF.
	midRead := &hkdfStreamReader{mac: hmac.New(sha256.New, prk), buf: []byte{0x01, 0x02, 0x03, 0x04}, counter: 0}
	out := make([]byte, 8)
	n, err = midRead.Read(out)
	assert.Equal(t, 4, n)
	assert.ErrorIs(t, err, io.EOF)

	// A cleanly exhausted reader still reports an error when no bytes remain.
	var extra [1]byte
	_, err = exhaustReader.Read(extra[:])
	assert.Error(t, err)
}

func BenchmarkPBKDF2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = PBKDF2(sha256.New, []byte("password"), []byte("salt"), 10000, 32)
	}
}
