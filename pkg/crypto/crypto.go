package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
)

const (
	nonceSize = 12 // GCM standard nonce size
)

// GenerateKey generates a new ECDSA P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PrivateKeyToPEM serialises an ECDSA private key to PEM.
func PrivateKeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

// PublicKeyFromPEM deserialises an ECDSA public key from PEM.
func PublicKeyFromPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}
	return ecPub, nil
}

// Sign signs data with the given ECDSA private key.
// Returns a hex-encoded "r:s" signature.
func Sign(data []byte, key *ecdsa.PrivateKey) (string, error) {
	hash := SHA256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sig := fmt.Sprintf("%s:%s",
		hex.EncodeToString(r.Bytes()),
		hex.EncodeToString(s.Bytes()),
	)
	return sig, nil
}

// Verify verifies an ECDSA signature produced by Sign.
func Verify(data []byte, sig string, pub *ecdsa.PublicKey) (bool, error) {
	var rHex, sHex string
	_, err := fmt.Sscanf(sig, "%s:%s", &rHex, &sHex)
	if err != nil {
		return false, fmt.Errorf("parse signature: %w", err)
	}
	rBytes, err := hex.DecodeString(rHex)
	if err != nil {
		return false, fmt.Errorf("decode r: %w", err)
	}
	sBytes, err := hex.DecodeString(sHex)
	if err != nil {
		return false, fmt.Errorf("decode s: %w", err)
	}

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	hash := SHA256(data)
	return ecdsa.Verify(pub, hash, r, s), nil
}

// SHA256 returns the SHA-256 hash of data.
func SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// SHA256Hex returns the hex-encoded SHA-256 hash of data.
func SHA256Hex(data []byte) string {
	return hex.EncodeToString(SHA256(data))
}

// ChainHash computes sha256(prevHash || data), used for audit log chaining.
func ChainHash(prevHash string, data []byte) string {
	combined := append([]byte(prevHash), data...)
	return SHA256Hex(combined)
}

// GenerateAESKey generates a random 256-bit AES key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate aes key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// The returned ciphertext includes the nonce prepended.
func Encrypt(plaintext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext produced by Encrypt.
func Decrypt(encoded string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// RandomHex returns n random bytes as a hex string.
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ConstantTimeCompare performs a timing-safe string comparison.
func ConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
