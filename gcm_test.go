package openssl

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestGCM(t *testing.T) {
	key := []byte("1234567890123456") // 16 bytes key
	nonce := []byte("123456789012")     // 12 bytes nonce
	src := []byte("hello world, GCM mode test")
	aad := []byte("additional authenticated data")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}

	// Encrypt
	ciphertext, err := GCMEncrypt(block, src, nonce, aad)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	// Decrypt
	plaintext, err := GCMDecrypt(block, ciphertext, nonce, aad)
	if err != nil {
		t.Fatalf("GCMDecrypt failed: %v", err)
	}

	if !bytes.Equal(src, plaintext) {
		t.Fatalf("expected plaintext %s, got %s", src, plaintext)
	}

	// Test tamper in ciphertext
	tamperedCiphertext := append([]byte(nil), ciphertext...)
	tamperedCiphertext[0] ^= 0xff
	_, err = GCMDecrypt(block, tamperedCiphertext, nonce, aad)
	if err == nil {
		t.Fatalf("expected error on tampered ciphertext, got nil")
	}

	// Test tamper in AAD
	tamperedAAD := []byte("tampered aad")
	_, err = GCMDecrypt(block, ciphertext, nonce, tamperedAAD)
	if err == nil {
		t.Fatalf("expected error on tampered AAD, got nil")
	}

	// Test invalid nonce length (encrypt)
	invalidNonce := []byte("short_nonce")
	_, err = GCMEncrypt(block, src, invalidNonce, aad)
	if err == nil || err.Error() != "GCMEncrypt: incorrect nonce length" {
		t.Fatalf("expected incorrect nonce length error, got: %v", err)
	}

	// Test invalid nonce length (decrypt)
	_, err = GCMDecrypt(block, ciphertext, invalidNonce, aad)
	if err == nil || err.Error() != "GCMDecrypt: incorrect nonce length" {
		t.Fatalf("expected incorrect nonce length error, got: %v", err)
	}

	// Test short ciphertext (decrypt)
	shortCiphertext := []byte("too_short")
	_, err = GCMDecrypt(block, shortCiphertext, nonce, aad)
	if err == nil || err.Error() != "GCMDecrypt: ciphertext too short" {
		t.Fatalf("expected ciphertext too short error, got: %v", err)
	}
}

