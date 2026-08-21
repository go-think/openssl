# Openssl encryption

[![Go Report Card](https://goreportcard.com/badge/github.com/go-think/openssl)](https://goreportcard.com/report/github.com/go-think/openssl)
[![build](https://github.com/go-think/openssl/actions/workflows/build.yml/badge.svg)](https://github.com/go-think/openssl/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/go-think/openssl/badge.svg?branch=master)](https://coveralls.io/github/go-think/openssl?branch=master)
[![Godoc](https://godoc.org/github.com/go-think/openssl?status.svg)](https://pkg.go.dev/github.com/go-think/openssl)
[![Release](https://img.shields.io/github/release/go-think/openssl.svg)](https://github.com/go-think/openssl/releases/latest)

A functions wrapping of OpenSSL library for symmetric and asymmetric encryption and decryption, digital signatures, hashing, and HMAC. It provides clean, boilerplate-free cryptographic APIs with 100% compatibility across OpenSSL, PHP, Java, and Node.js.

---

## Features

- **Symmetric Ciphers**: AES (128/192/256 bits), DES (64 bits), 3DES (192 bits).
- **All Major Cipher Modes**:
  - **Block Modes**: ECB, CBC
  - **Stream Modes**: CFB, OFB, CTR
  - **AEAD Authentication**: GCM (Galois/Counter Mode)
- **Flexible Padding Schemes**: PKCS#7 (PKCS#5), ZeroPadding (Zeros), with automatic padding and unpadding.
- **Asymmetric Cryptography (RSA)**:
  - Key pair generation (PKCS#1 PEM) and public key extraction.
  - Encryption & decryption with **automatic chunking** for arbitrary large data.
  - Supports standard Public Key PEM and X.509 **Certificate** formats.
  - Digital signature and verification (`RSASign` / `RSAVerify`) with configurable hash algorithms.
- **Hashes & HMAC**: MD5, SHA-1, SHA-256, SHA-512, HMAC-SHA1, HMAC-SHA256, HMAC-SHA512.
- **Smart Key & IV Handling**: Automatic padding / truncating for keys and IVs to eliminate boilerplate code.
- **100% Interoperability**: Seamlessly compatible with OpenSSL, PHP (`openssl_encrypt`), Java, Python, and Node.js.

---

## Table of Contents

- [Installation](#installation)
- [Symmetric Encryption](#symmetric-encryption)
  - [AES](#aes)
  - [DES](#des)
  - [3DES](#3des)
  - [Padding Schemes](#padding-schemes)
- [Asymmetric Encryption (RSA)](#rsa)
  - [Key Generation](#1-key-generation)
  - [Encryption & Decryption](#2-encryption--decryption-auto-chunking)
  - [Sign & Verify](#3-sign--verify)
- [Hash & HMAC](#hash--hmac)
  - [MD5](#md5)
  - [SHA & HMAC-SHA](#sha--hmac-sha)
- [Cross-Language Interoperability](#cross-language-interoperability)
- [License](#license)
- [Contact](#contact)

---

## Installation

The only requirement is the [Go Programming Language](https://golang.org/dl/)

```bash
go get -u github.com/go-think/openssl
```

---

## Symmetric Encryption

### AES

The length of the key can be 16, 24, or 32 characters (128, 192, or 256 bits). Keys shorter or longer than the required size are automatically padded or truncated.

#### AES-ECB
```go
src := []byte("123456")
key := []byte("1234567890123456")

// Encrypt
dst, err := openssl.AesECBEncrypt(src, key, openssl.PKCS7_PADDING)
fmt.Println(base64.StdEncoding.EncodeToString(dst)) // yXVUkR45PFz0UfpbDB8/ew==

// Decrypt
plain, err := openssl.AesECBDecrypt(dst, key, openssl.PKCS7_PADDING)
fmt.Println(string(plain)) // 123456
```

#### AES-CBC
```go
src := []byte("123456")
key := []byte("1234567890123456")
iv  := []byte("1234567890123456")

// Encrypt
dst, err := openssl.AesCBCEncrypt(src, key, iv, openssl.PKCS7_PADDING)
fmt.Println(base64.StdEncoding.EncodeToString(dst)) // 1jdzWuniG6UMtoa3T6uNLA==

// Decrypt
plain, err := openssl.AesCBCDecrypt(dst, key, iv, openssl.PKCS7_PADDING)
fmt.Println(string(plain)) // 123456
```

#### AES-GCM (Galois/Counter Mode)
GCM is an AEAD mode that provides confidentiality and authentication integrity without requiring padding.
```go
src := []byte("123456")
key := []byte("1234567890123456")
nonce := []byte("123456789012")          // Standard 12-byte nonce
additionalData := []byte("header_info") // Optional AAD

// Encrypt
dst, err := openssl.AesGCMEncrypt(src, key, nonce, additionalData)
fmt.Println(base64.StdEncoding.EncodeToString(dst))

// Decrypt
plain, err := openssl.AesGCMDecrypt(dst, key, nonce, additionalData)
fmt.Println(string(plain)) // 123456
```

#### AES-CFB / AES-OFB / AES-CTR (Stream Modes)
Stream cipher modes do not require padding.
```go
src := []byte("123456")
key := []byte("1234567890123456")
iv  := []byte("1234567890123456")

// AES-CFB
cfbDst, _ := openssl.AesCFBEncrypt(src, key, iv)
cfbSrc, _ := openssl.AesCFBDecrypt(cfbDst, key, iv)

// AES-OFB
ofbDst, _ := openssl.AesOFBEncrypt(src, key, iv)
ofbSrc, _ := openssl.AesOFBDecrypt(ofbDst, key, iv)

// AES-CTR
ctrDst, _ := openssl.AesCTREncrypt(src, key, iv)
ctrSrc, _ := openssl.AesCTRDecrypt(ctrDst, key, iv)
```

---

### DES

The length of the key must be 8 characters (64 bits).

```go
src := []byte("123456")
key := []byte("12345123")
iv  := []byte("67890678")

// DES-ECB
dst, _ := openssl.DesECBEncrypt(src, key, openssl.PKCS7_PADDING)
src, _  = openssl.DesECBDecrypt(dst, key, openssl.PKCS7_PADDING)

// DES-CBC
dst, _  = openssl.DesCBCEncrypt(src, key, iv, openssl.PKCS7_PADDING)
src, _  = openssl.DesCBCDecrypt(dst, key, iv, openssl.PKCS7_PADDING)

// DES-CFB / DES-OFB / DES-CTR
dst, _  = openssl.DesCFBEncrypt(src, key, iv)
src, _  = openssl.DesCFBDecrypt(dst, key, iv)

dst, _  = openssl.DesOFBEncrypt(src, key, iv)
src, _  = openssl.DesOFBDecrypt(dst, key, iv)

dst, _  = openssl.DesCTREncrypt(src, key, iv)
src, _  = openssl.DesCTRDecrypt(dst, key, iv)
```

---

### 3DES

The length of the key must be 24 characters (192 bits).

```go
src := []byte("123456")
key := []byte("123456789012345678901234")
iv  := []byte("67890678")

// 3DES-ECB
dst, _ := openssl.Des3ECBEncrypt(src, key, openssl.PKCS7_PADDING)
src, _  = openssl.Des3ECBDecrypt(dst, key, openssl.PKCS7_PADDING)

// 3DES-CBC
dst, _  = openssl.Des3CBCEncrypt(src, key, iv, openssl.PKCS7_PADDING)
src, _  = openssl.Des3CBCDecrypt(dst, key, iv, openssl.PKCS7_PADDING)

// 3DES-CFB / 3DES-OFB / 3DES-CTR
dst, _  = openssl.Des3CFBEncrypt(src, key, iv)
src, _  = openssl.Des3CFBDecrypt(dst, key, iv)

dst, _  = openssl.Des3OFBEncrypt(src, key, iv)
src, _  = openssl.Des3OFBDecrypt(dst, key, iv)

dst, _  = openssl.Des3CTREncrypt(src, key, iv)
src, _  = openssl.Des3CTRDecrypt(dst, key, iv)
```

---

### Padding Schemes

The library provides built-in constants for standard block padding schemes:

| Constant | Description |
| :--- | :--- |
| `openssl.PKCS7_PADDING` | Standard PKCS#7 padding (compatible with OpenSSL default) |
| `openssl.PKCS5_PADDING` | PKCS#5 padding (equivalent to PKCS#7 in implementation) |
| `openssl.ZEROS_PADDING` | Zero byte padding |

---

## RSA

Supports standard PKCS#1 PEM private keys, public keys, and X.509 `CERTIFICATE` blocks.

### 1. Key Generation
```go
var privateKeyBuf, publicKeyBuf bytes.Buffer

// Generate 2048-bit Private Key
err := openssl.RSAGenerateKey(2048, &privateKeyBuf)

// Extract Public Key from Private Key
err = openssl.RSAGeneratePublicKey(privateKeyBuf.Bytes(), &publicKeyBuf)
```

### 2. Encryption & Decryption (Auto-Chunking)
`RSAEncrypt` and `RSADecrypt` handle arbitrary length plaintexts automatically by chunking according to key size.
```go
src := []byte("Arbitrary length data to encrypt using RSA...")

// Encrypt with Public Key (or X.509 Certificate)
encrypted, err := openssl.RSAEncrypt(src, publicKeyPem)

// Decrypt with Private Key
decrypted, err := openssl.RSADecrypt(encrypted, privateKeyPem)
fmt.Println(string(decrypted))
```

### 3. Sign & Verify
```go
src := []byte("Data to be signed")

// Sign using SHA-256
signature, err := openssl.RSASign(src, privateKeyPem, crypto.SHA256)

// Verify signature
err = openssl.RSAVerify(src, signature, publicKeyPem, crypto.SHA256)
if err == nil {
    fmt.Println("Signature verified successfully!")
}
```

---

## Hash & HMAC

### MD5
```go
// Returns []byte
hash := openssl.Md5("hello world")

// Returns hex string
hexStr := openssl.Md5ToString("hello world") // 5eb63bbbe01eeed093cb22bb8f5acdc3
```

### SHA & HMAC-SHA

Supports SHA-1, SHA-256, and SHA-512 with corresponding HMAC functions:

```go
data := "hello world"
key  := "secret-key"

// SHA Hash
sha1Bytes   := openssl.Sha1(data)
sha256Bytes := openssl.Sha256(data)
sha512Bytes := openssl.Sha512(data)

// HMAC Hash (returns []byte)
hmac1   := openssl.HmacSha1(key, data)
hmac256 := openssl.HmacSha256(key, data)
hmac512 := openssl.HmacSha512(key, data)

// HMAC Hash (returns hex string)
hmac1Str   := openssl.HmacSha1ToString(key, data)
hmac256Str := openssl.HmacSha256ToString(key, data)
hmac512Str := openssl.HmacSha512ToString(key, data)
```

---

## Cross-Language Interoperability

This library is engineered to produce identical binary ciphertext to standard OpenSSL and other languages.

### Java Example (`javax.crypto`)
```java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AesDemo {
    public static void main(String[] args) throws Exception {
        String data = "123456";
        String key  = "1234567890123456";
        String iv   = "1234567890123456";

        // AES-128-CBC with PKCS5Padding (equivalent to PKCS7Padding)
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        String base64Encrypted = Base64.getEncoder().encodeToString(encrypted);
        System.out.println(base64Encrypted); // 1jdzWuniG6UMtoa3T6uNLA== (Identical to Go)

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(base64Encrypted));
        System.out.println(new String(decrypted, StandardCharsets.UTF_8)); // 123456
    }
}
```

### PHP Example (`openssl_encrypt`)
```php
<?php
$data = "123456";
$key  = "1234567890123456";
$iv   = "1234567890123456";

// AES-128-CBC
$encrypted = openssl_encrypt($data, 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);
echo base64_encode($encrypted); // 1jdzWuniG6UMtoa3T6uNLA== (Identical to Go output)
```

---

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PRs are welcomed!
- Issues: [https://github.com/go-think/openssl/issues](https://github.com/go-think/openssl/issues)
