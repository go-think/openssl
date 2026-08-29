package openssl

import (
	"crypto/hmac"
	"errors"
	"hash"
	"io"
)

// PBKDF2 derives a key of keyLen bytes from the password and salt using
// PBKDF2 (RFC 2898 / RFC 8018) with the given hash constructor and iteration
// count. An empty salt is allowed (equivalent to OpenSSL's -nosalt).
//
// The output is byte-identical to PHP openssl_pbkdf2() / hash_pbkdf2(),
// Node.js crypto.pbkdf2Sync() and Python hashlib.pbkdf2_hmac() for the same
// inputs. Note the parameter order (iter, keyLen) is the reverse of PHP's
// openssl_pbkdf2($password, $salt, $key_length, $iterations).
func PBKDF2(h func() hash.Hash, password, salt []byte, iter, keyLen int) ([]byte, error) {
	if h == nil {
		return nil, errors.New("openssl: nil hash constructor")
	}
	if iter < 1 {
		return nil, errors.New("openssl: iteration count must be at least 1")
	}
	if keyLen <= 0 {
		return nil, errors.New("openssl: key length must be positive")
	}

	prf := hmac.New(h, password)
	hashLen := prf.Size()
	if maxKeyLen := uint64(^uint32(0)) * uint64(hashLen); uint64(keyLen) > maxKeyLen {
		return nil, errors.New("openssl: key length exceeds RFC 8018 PBKDF2 limit")
	}
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, 0, hashLen)

	// Best-effort zeroization of sensitive intermediate state on return.
	defer func() {
		prf.Reset()
		for i := range U {
			U[i] = 0
		}
	}()

	for block := 1; block <= numBlocks; block++ {
		// U_1 = PRF(password, salt || INT_32_BE(block))
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Reset()
		_, _ = prf.Write(salt)
		_, _ = prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		U = append(U[:0], T...)

		// U_n = PRF(password, U_(n-1)); T = U_1 XOR U_2 XOR ... XOR U_iter
		for n := 2; n <= iter; n++ {
			prf.Reset()
			_, _ = prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}

	return dk[:keyLen:keyLen], nil
}

// HKDFExtract performs the extract step of HKDF (RFC 5869), deriving a
// pseudorandom key (prk) from the input keying material (secret) and an optional
// salt. When salt is empty, a hash-size string of zero bytes is used as the
// salt, as recommended by the RFC.
func HKDFExtract(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("openssl: nil hash constructor")
	}
	if len(salt) == 0 {
		salt = make([]byte, h().Size())
	}
	mac := hmac.New(h, salt)
	_, _ = mac.Write(secret)

	return mac.Sum(nil), nil
}

// HKDFExpand performs the expand step of HKDF (RFC 5869), deriving keyLen
// bytes of output keying material from a pseudorandom key (prk) and optional info.
// keyLen must not exceed 255 times the hash output size.
func HKDFExpand(h func() hash.Hash, prk, info []byte, keyLen int) ([]byte, error) {
	if h == nil {
		return nil, errors.New("openssl: nil hash constructor")
	}
	if len(prk) == 0 {
		return nil, errors.New("openssl: empty pseudorandom key")
	}
	if keyLen <= 0 {
		return nil, errors.New("openssl: key length must be positive")
	}
	hashLen := h().Size()
	if keyLen > 255*hashLen {
		return nil, errors.New("openssl: key length exceeds 255 times the hash size")
	}

	var (
		out     = make([]byte, 0, keyLen)
		T       []byte
		counter byte = 1
	)
	mac := hmac.New(h, prk)
	for len(out) < keyLen {
		// T_i = HMAC(PRK, T_(i-1) || info || i)
		mac.Reset()
		_, _ = mac.Write(T)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		T = mac.Sum(T[:0])
		out = append(out, T...)
		counter++
	}

	return out[:keyLen:keyLen], nil
}

// HKDF derives keyLen bytes of output keying material in a single call,
// equivalent to HKDFExtract followed by HKDFExpand (RFC 5869). The output is
// byte-identical to PHP hash_hkdf() for the same inputs.
func HKDF(h func() hash.Hash, secret, salt, info []byte, keyLen int) ([]byte, error) {
	prk, err := HKDFExtract(h, secret, salt)
	if err != nil {
		return nil, err
	}

	return HKDFExpand(h, prk, info, keyLen)
}

// hkdfStreamReader implements io.Reader for HKDF-Expand stream generation (RFC 5869).
type hkdfStreamReader struct {
	mac     hash.Hash
	info    []byte
	counter byte
	prev    []byte
	buf     []byte
}

func (r *hkdfStreamReader) Read(p []byte) (int, error) {
	need := len(p)
	read := 0
	for read < need {
		if len(r.buf) == 0 {
			if r.counter == 0 { // wrapped around past 255 blocks
				if read == 0 {
					return 0, errors.New("openssl: hkdf cannot expand more than 255 blocks")
				}
				return read, io.EOF
			}
			r.mac.Reset()
			_, _ = r.mac.Write(r.prev)
			_, _ = r.mac.Write(r.info)
			_, _ = r.mac.Write([]byte{r.counter})
			r.prev = r.mac.Sum(r.prev[:0])
			r.buf = r.prev
			if r.counter == 255 {
				r.counter = 0 // mark as exhausted
			} else {
				r.counter++
			}
		}
		n := copy(p[read:], r.buf)
		r.buf = r.buf[n:]
		read += n
	}
	return read, nil
}

// HKDFExpandReader creates an io.Reader that streams key material from prk
// and info using HKDF-Expand (RFC 5869).
func HKDFExpandReader(h func() hash.Hash, prk, info []byte) (io.Reader, error) {
	if h == nil {
		return nil, errors.New("openssl: nil hash constructor")
	}
	if len(prk) == 0 {
		return nil, errors.New("openssl: empty pseudorandom key")
	}
	return &hkdfStreamReader{
		mac:     hmac.New(h, prk),
		info:    info,
		counter: 1,
	}, nil
}

// HKDFReader creates an io.Reader that streams key material from secret, salt,
// and info using HKDF (RFC 5869).
func HKDFReader(h func() hash.Hash, secret, salt, info []byte) (io.Reader, error) {
	prk, err := HKDFExtract(h, secret, salt)
	if err != nil {
		return nil, err
	}
	return HKDFExpandReader(h, prk, info)
}
