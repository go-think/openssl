# Openssl encryption

[![Go Report Card](https://goreportcard.com/badge/github.com/go-think/openssl)](https://goreportcard.com/report/github.com/go-think/openssl)
[![build](https://github.com/go-think/openssl/actions/workflows/build.yml/badge.svg)](https://github.com/go-think/openssl/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/go-think/openssl/badge.svg?branch=master)](https://coveralls.io/github/go-think/openssl?branch=master)
[![Godoc](https://godoc.org/github.com/go-think/openssl?status.svg)](https://pkg.go.dev/github.com/go-think/openssl)
[![Release](https://img.shields.io/github/release/go-think/openssl.svg)](https://github.com/go-think/openssl/releases/latest)

A functions wrapping of OpenSSL library for symmetric and asymmetric encryption and decryption, digital signatures, hashing, and HMAC. It provides clean, boilerplate-free cryptographic APIs with 100% compatibility across OpenSSL, PHP, Java, Python, and Node.js.

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
- **Hashes & HMAC**: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, HMAC-SHA1, HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512.
- **Key Derivation (KDF)**: PBKDF2 (RFC 2898/8018) and HKDF (RFC 5869) for deriving keys from passwords or shared secrets, with output byte-identical to PHP `openssl_pbkdf2` / `hash_hkdf`, Node.js, Python, and OpenSSL.
- **CSPRNG Utilities**: Cryptographically secure random bytes generation (`RandomBytes`) for keys, IVs, nonces, and salts.
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
  - [Key & IV Utilities](#key--iv-utilities)
- [Asymmetric Encryption (RSA)](#rsa)
  - [Key Generation](#1-key-generation)
  - [Encryption & Decryption](#2-encryption--decryption-auto-chunking)
  - [Sign & Verify](#3-sign--verify)
- [Hash & HMAC](#hash--hmac)
  - [MD5](#md5)
  - [SHA & HMAC-SHA](#sha--hmac-sha)
- [Key Derivation (KDF)](#key-derivation-kdf)
  - [PBKDF2](#pbkdf2)
  - [HKDF](#hkdf)
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
iv  := []byte("1234567890123456") // Or generate securely via openssl.RandomBytes(16)

// Encrypt
dst, err := openssl.AesCBCEncrypt(src, key, iv, openssl.PKCS7_PADDING)
fmt.Println(base64.StdEncoding.EncodeToString(dst)) // 1jdzWuniG6UMtoa3T6uNLA==

// Decrypt
plain, err := openssl.AesCBCDecrypt(dst, key, iv, openssl.PKCS7_PADDING)
fmt.Println(string(plain)) // 123456
```

#### AES-GCM (Galois/Counter Mode)

GCM is an authenticated encryption (AEAD) mode that provides both confidentiality and data authenticity without requiring padding:
- **Nonce (IV)**: Standard recommended size is **12 bytes** (often called `iv` in other languages).
- **Additional Data (AAD)**: Optional data that is authenticated but not encrypted (can be `nil`).
- **Authentication Tag**: In Go standard library, the 16-byte authentication tag is automatically appended to the ciphertext ($\text{Output} = \text{Ciphertext} \parallel \text{Tag}$).
- **Security Notice (Critical)**: **Never reuse the same `nonce` with the same key in GCM mode.** Reusing a nonce breaks authentication integrity. In production, always generate a fresh cryptographically secure random nonce via `openssl.RandomBytes(12)`.

```go
src := []byte("123456")
key := []byte("1234567890123456")

// In production, ALWAYS generate a fresh unique nonce (IV):
// nonce, err := openssl.RandomBytes(12)
nonce := []byte("123456789012")          // Static 12-byte nonce (demonstration only)
additionalData := []byte("header_info") // Optional AAD

// Encrypt (output contains ciphertext + 16-byte auth tag)
dst, err := openssl.AesGCMEncrypt(src, key, nonce, additionalData)
fmt.Println(base64.StdEncoding.EncodeToString(dst))

// Decrypt (automatically verifies the 16-byte tag at the end)
plain, err := openssl.AesGCMDecrypt(dst, key, nonce, additionalData)
fmt.Println(string(plain)) // 123456
```

##### Production Pattern (Self-Contained Payload: Nonce + Ciphertext + Tag)

Because the 12-byte `nonce` does not need to be secret, the standard industry practice is to prepend it to the ciphertext for convenient storage and transmission:

```go
// 1. Generate random nonce & encrypt
nonce, _ := openssl.RandomBytes(12)
ciphertextWithTag, err := openssl.AesGCMEncrypt(src, key, nonce, additionalData)

// 2. Pack: Nonce (12B) || Ciphertext || Tag (16B)
payload := append(nonce, ciphertextWithTag...)

// 3. Unpack & decrypt on receiver side:
extractedNonce := payload[:12]
rawCiphertext  := payload[12:]
plain, err := openssl.AesGCMDecrypt(rawCiphertext, key, extractedNonce, additionalData)
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

### Key & IV Utilities

#### Secure Random Bytes (IV / Nonce / Salt)
Generates cryptographically secure random bytes using `crypto/rand` (equivalent to PHP's `openssl_random_pseudo_bytes()` or Node.js `crypto.randomBytes()`):

```go
// Generate 12-byte Nonce for AES-GCM
nonce, err := openssl.RandomBytes(12)

// Generate 16-byte IV for AES-CBC / CTR / CFB / OFB
iv, err := openssl.RandomBytes(16)

// Generate 32-byte Key for AES-256
key, err := openssl.RandomBytes(32)

// Generate random Hex token / secret string
tokenBytes, _ := openssl.RandomBytes(32)
hexToken := hex.EncodeToString(tokenBytes) // 64-character hex string
```


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

Supports SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 with corresponding HMAC functions:

```go
data := "hello world"
key  := "secret-key"

// SHA Hash (returns []byte)
sha1Bytes   := openssl.Sha1(data)
sha224Bytes := openssl.Sha224(data)
sha256Bytes := openssl.Sha256(data)
sha384Bytes := openssl.Sha384(data)
sha512Bytes := openssl.Sha512(data)

// SHA Hash (returns hex string)
sha256Hex   := openssl.Sha256ToString(data)

// HMAC Hash (returns []byte)
hmac1   := openssl.HmacSha1(key, data)
hmac224 := openssl.HmacSha224(key, data)
hmac256 := openssl.HmacSha256(key, data)
hmac384 := openssl.HmacSha384(key, data)
hmac512 := openssl.HmacSha512(key, data)

// HMAC Hash (returns hex string)
hmac1Str   := openssl.HmacSha1ToString(key, data)
hmac224Str := openssl.HmacSha224ToString(key, data)
hmac256Str := openssl.HmacSha256ToString(key, data)
hmac384Str := openssl.HmacSha384ToString(key, data)
hmac512Str := openssl.HmacSha512ToString(key, data)
```

---

## Key Derivation (KDF)

### PBKDF2

Derives a key of arbitrary length from a password and salt per [RFC 2898 / RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018). The output is raw binary (`[]byte`) and is byte-identical to PHP `openssl_pbkdf2()` / `hash_pbkdf2()`, Node.js `crypto.pbkdf2Sync()`, Python `hashlib.pbkdf2_hmac()`, and the `openssl kdf` CLI for the same inputs.

```go
import (
    "crypto/sha256"

    openssl "github.com/go-think/openssl"
)

password := []byte("password")
salt, _ := openssl.RandomBytes(16) // ALWAYS use a random salt per password

// Example-only: 10,000 iterations keeps this sample fast; production
// PBKDF2-HMAC-SHA256 should use hundreds of thousands of iterations.
key, err := openssl.PBKDF2(sha256.New, password, salt, 10000, 32)
if err != nil {
    panic(err)
}
```

> **Note the parameter order**: Go uses `(h, password, salt, iter, keyLen)`, while PHP uses `openssl_pbkdf2($password, $salt, $key_length, $iterations, $digest)`.

Identical PHP:

```php
$salt = /* the same 16-byte salt as Go */;
$key  = openssl_pbkdf2('password', $salt, 32, 10000, 'sha256'); // same binary output
```

Identical Node.js:

```javascript
const key = crypto.pbkdf2Sync('password', salt, 10000, 32, 'sha256'); // same binary output
```

**Security guidance**: use a high iteration count (follow current OWASP recommendations — hundreds of thousands of iterations for PBKDF2-HMAC-SHA256), a unique random salt per password via `openssl.RandomBytes(16)`, and prefer SHA-256/SHA-512 over SHA-1.

### HKDF

Derives keys from high-entropy input keying material per [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) — the standard way to expand a shared secret (e.g., from ECDH) into per-purpose keys. The output is byte-identical to PHP `hash_hkdf()` for the same inputs.

```go
import (
    "crypto/sha256"
    "io"

    openssl "github.com/go-think/openssl"
)

secret := []byte("input keying material") // e.g. an ECDH shared secret
salt, _ := openssl.RandomBytes(32)        // optional but recommended
info   := []byte("app-session-encryption")

// One-shot (equivalent to PHP hash_hkdf('sha256', $ikm, 32, $info, $salt))
key, err := openssl.HKDF(sha256.New, secret, salt, info, 32)
if err != nil {
    panic(err)
}

// Or in two explicit steps for finer control:
prk, err := openssl.HKDFExtract(sha256.New, secret, salt) // salt may be nil
if err != nil {
    panic(err)
}
key, err = openssl.HKDFExpand(sha256.New, prk, info, 32) // max 255 * hash size
if err != nil {
    panic(err)
}

// Or stream key material on demand via io.Reader:
reader, err := openssl.HKDFReader(sha256.New, secret, salt, info)
if err != nil {
    panic(err)
}
chunk := make([]byte, 16)
_, err = io.ReadFull(reader, chunk)
if err != nil {
    panic(err)
}
```

> **PBKDF2 vs HKDF**: use PBKDF2 for low-entropy passwords (slow by design); use HKDF only for high-entropy secrets (fast by design).

---

## Cross-Language Interoperability

This library is engineered to produce identical binary ciphertext to standard OpenSSL and other languages.

### AES-GCM Concept & Parameter Mapping

| Concept / Field | Go (`openssl`) | Node.js (`crypto`) | Python (`cryptography`) | Java (`javax.crypto`) | PHP (`openssl_encrypt`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initialization Vector** | `nonce` (12 bytes) | `iv` | `nonce` / `iv` | `GCMParameterSpec(128, iv)` | `$iv` |
| **Authenticated Data** | `additionalData` | `cipher.setAAD(aad)` | `associated_data` | `cipher.updateAAD(aad)` | `$aad` |
| **Authentication Tag** | Appended to ciphertext (`ciphertext \|\| tag`) | `cipher.getAuthTag()` (separated) | `AESGCM` appends / separated in primitives | Appended to ciphertext | Passed as reference (`&$tag`) |

---

### Node.js Example (`crypto`)

#### AES-GCM Interoperability
```javascript
const crypto = require('crypto');

const key = Buffer.from('1234567890123456'); // 16-byte key
const nonce = Buffer.from('123456789012');    // 12-byte nonce (IV)
const aad = Buffer.from('header_info');
const plaintext = '123456';

// 1. Encrypt with Node.js
const cipher = crypto.createCipheriv('aes-128-gcm', key, nonce);
cipher.setAAD(aad);
let encrypted = cipher.update(plaintext, 'utf8');
encrypted = Buffer.concat([encrypted, cipher.final()]);
const tag = cipher.getAuthTag(); // 16-byte Tag

// Pack into Go format (ciphertext || tag)
const goCompatiblePayload = Buffer.concat([encrypted, tag]);

// 2. Decrypt data from Go (Go outputs ciphertext || tag)
const ciphertextPart = goCompatiblePayload.subarray(0, goCompatiblePayload.length - 16);
const tagPart = goCompatiblePayload.subarray(goCompatiblePayload.length - 16);

const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonce);
decipher.setAAD(aad);
decipher.setAuthTag(tagPart);
let decrypted = decipher.update(ciphertextPart, null, 'utf8');
decrypted += decipher.final('utf8');
console.log(decrypted); // 123456
```

---

### Java Example (`javax.crypto`)

#### AES-128-CBC
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

#### AES-128-GCM
```java
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

// AES-128-GCM in Java automatically appends/expects the 16-byte tag at the end (identical to Go)
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKeySpec keySpec = new SecretKeySpec("1234567890123456".getBytes(StandardCharsets.UTF_8), "AES");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, "123456789012".getBytes(StandardCharsets.UTF_8));

// Encrypt
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
cipher.updateAAD("header_info".getBytes(StandardCharsets.UTF_8));
byte[] ciphertextWithTag = cipher.doFinal("123456".getBytes(StandardCharsets.UTF_8));

// Decrypt
cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
cipher.updateAAD("header_info".getBytes(StandardCharsets.UTF_8));
byte[] decrypted = cipher.doFinal(ciphertextWithTag);
```

---

### PHP Example (`openssl_encrypt`)

#### AES-128-CBC
```php
<?php
$data = "123456";
$key  = "1234567890123456";
$iv   = "1234567890123456";

// AES-128-CBC
$encrypted = openssl_encrypt($data, 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);
echo base64_encode($encrypted); // 1jdzWuniG6UMtoa3T6uNLA== (Identical to Go output)
```

#### AES-128-GCM
```php
<?php
$data  = "123456";
$key   = "1234567890123456";
$nonce = "123456789012"; // 12-byte IV
$aad   = "header_info";

// 1. Encrypt with PHP
$ciphertext = openssl_encrypt($data, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
$goCompatiblePayload = $ciphertext . $tag; // Append tag to match Go format

// 2. Decrypt data from Go (extract 16-byte tag from end)
$raw = $goCompatiblePayload;
$cipherPart = substr($raw, 0, -16);
$tagPart    = substr($raw, -16);

$decrypted = openssl_decrypt($cipherPart, 'aes-128-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tagPart, $aad);
echo $decrypted; // 123456
```

---

### Python Example (`cryptography`)

#### AES-128-GCM
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = b"1234567890123456" # 16-byte key
nonce = b"123456789012"     # 12-byte nonce (IV)
aad = b"header_info"
data = b"123456"

aesgcm = AESGCM(key)

# 1. Encrypt with Python (Output format is ciphertext || 16-byte tag, 100% identical to Go)
ciphertext_with_tag = aesgcm.encrypt(nonce, data, aad)

# 2. Decrypt data from Go (Go output can be directly decrypted by Python)
decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
print(decrypted.decode()) # 123456
```

---

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PRs are welcomed!
- Issues: [https://github.com/go-think/openssl/issues](https://github.com/go-think/openssl/issues)
