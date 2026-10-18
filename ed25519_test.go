package openssl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestEd25519GenerateKeyAndSignVerify(t *testing.T) {
	var privateKeyPEM, publicKeyPEM bytes.Buffer
	if err := Ed25519GenerateKey(&privateKeyPEM); err != nil {
		t.Fatalf("Ed25519GenerateKey() error = %v", err)
	}
	if err := Ed25519GeneratePublicKey(privateKeyPEM.Bytes(), &publicKeyPEM); err != nil {
		t.Fatalf("Ed25519GeneratePublicKey() error = %v", err)
	}

	privateBlock, _ := pem.Decode(privateKeyPEM.Bytes())
	if privateBlock == nil || privateBlock.Type != "PRIVATE KEY" {
		t.Fatal("generated private key is not PKCS#8 PEM")
	}
	publicBlock, _ := pem.Decode(publicKeyPEM.Bytes())
	if publicBlock == nil || publicBlock.Type != "PUBLIC KEY" {
		t.Fatal("generated public key is not PKIX PEM")
	}

	message := []byte("cross-language Ed25519 test")
	signature, err := Ed25519Sign(message, privateKeyPEM.Bytes())
	if err != nil {
		t.Fatalf("Ed25519Sign() error = %v", err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(signature), ed25519.SignatureSize)
	}
	if err := Ed25519Verify(message, signature, publicKeyPEM.Bytes()); err != nil {
		t.Fatalf("Ed25519Verify() error = %v", err)
	}

	if err := Ed25519Verify([]byte("tampered"), signature, publicKeyPEM.Bytes()); err == nil {
		t.Fatal("Ed25519Verify() succeeded for a modified message")
	}
	signature[0] ^= 1
	if err := Ed25519Verify(message, signature, publicKeyPEM.Bytes()); err == nil {
		t.Fatal("Ed25519Verify() succeeded for a modified signature")
	}
}

func TestEd25519RFC8032TestVector(t *testing.T) {
	seed := decodeHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantSignature := decodeHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"+
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

	privateKey := ed25519.NewKeyFromSeed(seed)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})

	signature, err := Ed25519Sign(nil, privatePEM)
	if err != nil {
		t.Fatalf("Ed25519Sign() error = %v", err)
	}
	if !bytes.Equal(signature, wantSignature) {
		t.Fatalf("signature = %x, want %x", signature, wantSignature)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := Ed25519Verify(nil, wantSignature, publicPEM); err != nil {
		t.Fatalf("Ed25519Verify() RFC vector error = %v", err)
	}
}

func TestEd25519VerifyCertificate(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Ed25519 test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	message := []byte("certificate verification")
	signature, err := Ed25519Sign(message, marshalEd25519PrivateKey(t, privateKey))
	if err != nil {
		t.Fatalf("Ed25519Sign() error = %v", err)
	}
	if err := Ed25519Verify(message, signature, certPEM); err != nil {
		t.Fatalf("Ed25519Verify() certificate error = %v", err)
	}
}

func TestEd25519RejectsInvalidAndWrongTypeKeys(t *testing.T) {
	if _, err := Ed25519Sign([]byte("message"), []byte("not a PEM key")); err == nil {
		t.Fatal("Ed25519Sign() accepted malformed PEM")
	}
	if err := Ed25519Verify(nil, nil, []byte("not a PEM key")); err == nil {
		t.Fatal("Ed25519Verify() accepted malformed PEM")
	}
	if err := Ed25519GeneratePublicKey([]byte("not a PEM key"), &bytes.Buffer{}); err == nil {
		t.Fatal("Ed25519GeneratePublicKey() accepted malformed PEM")
	}

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	rsaPrivateDER, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	rsaPrivatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPrivateDER})
	if _, err := Ed25519Sign([]byte("message"), rsaPrivatePEM); err == nil {
		t.Fatal("Ed25519Sign() accepted an RSA private key")
	}

	rsaPublicDER, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	rsaPublicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPublicDER})
	if err := Ed25519Verify(nil, nil, rsaPublicPEM); err == nil {
		t.Fatal("Ed25519Verify() accepted an RSA public key")
	}
}

func marshalEd25519PrivateKey(t *testing.T, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return decoded
}
