package openssl

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// Sha1 Calculate the sha1 hash of a string
func Sha1(str string) []byte {
	h := sha1.New()
	_, _ = h.Write([]byte(str))
	return h.Sum(nil)
}

// Sha1ToString Calculate the sha1 hash of a string, outputs lowercase hexits
func Sha1ToString(str string) string {
	return hex.EncodeToString(Sha1(str))
}

// HmacSha1 Calculate the sha1 hash of a string using the HMAC method
func HmacSha1(key string, data string) []byte {
	mac := hmac.New(sha1.New, []byte(key))
	_, _ = mac.Write([]byte(data))

	return mac.Sum(nil)
}

// HmacSha1ToString Calculate the sha1 hash of a string using the HMAC method, outputs lowercase hexits
func HmacSha1ToString(key string, data string) string {
	return hex.EncodeToString(HmacSha1(key, data))
}

// Sha224 Calculate the sha224 hash of a string
func Sha224(str string) []byte {
	h := sha256.New224()
	_, _ = h.Write([]byte(str))
	return h.Sum(nil)
}

// Sha224ToString Calculate the sha224 hash of a string, outputs lowercase hexits
func Sha224ToString(str string) string {
	return hex.EncodeToString(Sha224(str))
}

// HmacSha224 Calculate the sha224 hash of a string using the HMAC method
func HmacSha224(key string, data string) []byte {
	mac := hmac.New(sha256.New224, []byte(key))
	_, _ = mac.Write([]byte(data))

	return mac.Sum(nil)
}

// HmacSha224ToString Calculate the sha224 hash of a string using the HMAC method, outputs lowercase hexits
func HmacSha224ToString(key string, data string) string {
	return hex.EncodeToString(HmacSha224(key, data))
}

// Sha256 Calculate the sha256 hash of a string
func Sha256(str string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(str))
	return h.Sum(nil)
}

// Sha256ToString Calculate the sha256 hash of a string, outputs lowercase hexits
func Sha256ToString(str string) string {
	return hex.EncodeToString(Sha256(str))
}

// HmacSha256 Calculate the sha256 hash of a string using the HMAC method
func HmacSha256(key string, data string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(data))

	return mac.Sum(nil)
}

// HmacSha256ToString Calculate the sha256 hash of a string using the HMAC method, outputs lowercase hexits
func HmacSha256ToString(key string, data string) string {
	return hex.EncodeToString(HmacSha256(key, data))
}

// Sha384 Calculate the sha384 hash of a string
func Sha384(str string) []byte {
	h := sha512.New384()
	_, _ = h.Write([]byte(str))
	return h.Sum(nil)
}

// Sha384ToString Calculate the sha384 hash of a string, outputs lowercase hexits
func Sha384ToString(str string) string {
	return hex.EncodeToString(Sha384(str))
}

// HmacSha384 Calculate the sha384 hash of a string using the HMAC method
func HmacSha384(key string, data string) []byte {
	mac := hmac.New(sha512.New384, []byte(key))
	_, _ = mac.Write([]byte(data))

	return mac.Sum(nil)
}

// HmacSha384ToString Calculate the sha384 hash of a string using the HMAC method, outputs lowercase hexits
func HmacSha384ToString(key string, data string) string {
	return hex.EncodeToString(HmacSha384(key, data))
}

// Sha512 Calculate the sha512 hash of a string
func Sha512(str string) []byte {
	h := sha512.New()
	_, _ = h.Write([]byte(str))
	return h.Sum(nil)
}

// Sha512ToString Calculate the sha512 hash of a string, outputs lowercase hexits
func Sha512ToString(str string) string {
	return hex.EncodeToString(Sha512(str))
}

// HmacSha512 Calculate the sha512 hash of a string using the HMAC method
func HmacSha512(key string, data string) []byte {
	mac := hmac.New(sha512.New, []byte(key))
	_, _ = mac.Write([]byte(data))

	return mac.Sum(nil)
}

// HmacSha512ToString Calculate the sha512 hash of a string using the HMAC method, outputs lowercase hexits
func HmacSha512ToString(key string, data string) string {
	return hex.EncodeToString(HmacSha512(key, data))
}
