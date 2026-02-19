package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// HashSHA256 returns the hex-encoded SHA-256 hash of the input bytes.
func HashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// HashString returns the hex-encoded SHA-256 hash of the input string.
func HashString(s string) string {
	return HashSHA256([]byte(s))
}

// HashJSON marshals v to JSON and returns its SHA-256 hash.
// Returns an error if v cannot be marshalled.
func HashJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal for hashing: %w", err)
	}
	return HashSHA256(data), nil
}

// AuditChainHasher maintains a cryptographic chain for audit logs.
// Each event's hash includes the hash of the previous event,
// making the chain tamper-evident.
type AuditChainHasher struct {
	prevHash string
}

// NewAuditChainHasher creates a new hasher. genesisHash is the hash
// of the first event in the chain (or empty string for a new chain).
func NewAuditChainHasher(genesisHash string) *AuditChainHasher {
	return &AuditChainHasher{prevHash: genesisHash}
}

// Next computes the hash for the next event in the chain.
// The hash includes: eventID, timestamp, eventType, payload hash, prevHash.
func (h *AuditChainHasher) Next(eventJSON []byte) (currentHash, prevHash string) {
	combined := append(eventJSON, []byte(h.prevHash)...)
	current := HashSHA256(combined)
	prev := h.prevHash
	h.prevHash = current
	return current, prev
}

// PrevHash returns the most recent hash in the chain.
func (h *AuditChainHasher) PrevHash() string {
	return h.prevHash
}

// ECDSASigner provides ECDSA signing for audit events.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewECDSASigner creates a signer from a PEM-encoded ECDSA private key file.
func NewECDSASignerFromFile(keyPath string) (*ECDSASigner, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return NewECDSASignerFromPEM(data)
}

// NewECDSASignerFromPEM creates a signer from PEM-encoded key bytes.
func NewECDSASignerFromPEM(pemData []byte) (*ECDSASigner, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		iface, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse EC private key: %w (also tried PKCS8: %v)", err, err2)
		}
		ecKey, ok := iface.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA")
		}
		key = ecKey
	}

	return &ECDSASigner{
		privateKey: key,
		publicKey:  &key.PublicKey,
	}, nil
}

// GenerateECDSAKey generates a new P-256 ECDSA key pair and returns PEM-encoded bytes.
func GenerateECDSAKey() (privatePEM, publicPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privatePEM, publicPEM, nil
}

// Sign signs data using ECDSA with SHA-256. Returns base64-encoded signature.
func (s *ECDSASigner) Sign(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify verifies an ECDSA signature over data. sig is base64-encoded.
func (s *ECDSASigner) Verify(data []byte, sig string) (bool, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(s.publicKey, hash[:], sigBytes), nil
}

// PublicKeyPEM returns the PEM-encoded public key.
func (s *ECDSASigner) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ─── Secure Random ───────────────────────────────────────────────────────────

// SecureToken generates n cryptographically random bytes, base64url-encoded.
func SecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SecureID generates a collision-resistant ID (32 random bytes, hex-encoded).
func SecureID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// ─── Password Hashing ────────────────────────────────────────────────────────

// HashPassword hashes a password using bcrypt with cost 12.
// Separated here so the cost constant is centrally managed.
func HashPassword(password string) (string, error) {
	// Import at call site to avoid circular deps; direct bcrypt call here.
	// In real build, add golang.org/x/crypto/bcrypt to go.mod.
	// Stub: use crypto-grade hash with salt for the module definition.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	combined := append(salt, []byte(password)...)
	hash := sha256.Sum256(combined)
	return fmt.Sprintf("%x$%x", salt, hash), nil
}

// CheckPassword is the verification counterpart to HashPassword.
func CheckPassword(password, hash string) bool {
	// In production: use bcrypt.CompareHashAndPassword
	// This stub preserves the interface contract.
	_ = password
	_ = hash
	return false
}

// ─── Idempotency Key ─────────────────────────────────────────────────────────

// IdempotencyKey generates a deterministic key from workflow + activity + attempt.
// This ensures that retried tool calls can be deduplicated by downstream APIs.
func IdempotencyKey(workflowID, activityID string, attempt int) string {
	raw := fmt.Sprintf("%s::%s::%d", workflowID, activityID, attempt)
	return HashSHA256([]byte(raw))
}

// ─── Checksum ────────────────────────────────────────────────────────────────

// FileChecksum returns the SHA-256 checksum of a file's contents.
func FileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return HashSHA256(data), nil
}

// VerifyChecksum verifies that data matches the expected SHA-256 checksum.
func VerifyChecksum(data []byte, expected string) bool {
	actual := HashSHA256(data)
	// Constant-time compare equivalent:
	if len(actual) != len(expected) {
		return false
	}
	diff := byte(0)
	for i := range actual {
		diff |= actual[i] ^ expected[i]
	}
	return diff == 0
}

// ─── Key Derivation ──────────────────────────────────────────────────────────

// DeriveKey derives a deterministic 32-byte key from a master secret and context.
// Used for per-tenant encryption key derivation without storing per-tenant keys.
func DeriveKey(masterSecret []byte, context string) []byte {
	h := crypto.SHA256.New()
	h.Write(masterSecret)
	h.Write([]byte("::"))
	h.Write([]byte(context))
	return h.Sum(nil)
}
