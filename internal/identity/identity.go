// Package identity manages the endpoint signing identity and signed envelopes.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/openclaw/turnwire/internal/securestore"
)

const keyFileName = "identity.ed25519"

// Signer owns one endpoint's private signing key.
type Signer struct {
	name       string
	privateKey ed25519.PrivateKey
}

// LoadOrCreate loads the identity key in auditDir, creating it when requested.
func LoadOrCreate(auditDir, name string, create bool) (*Signer, error) {
	store, err := securestore.Open(auditDir, create, "identity directory")
	if err != nil {
		return nil, err
	}
	defer store.Close()
	key, err := store.Read(keyFileName)
	if err != nil {
		if !create || !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("load identity key: %w", err)
		}
		return createKey(store, name)
	}
	return newSigner(name, key)
}

func createKey(store *securestore.Store, name string) (*Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate identity key: %w", err)
	}
	if err := store.Create(keyFileName, privateKey); err != nil {
		return nil, fmt.Errorf("store identity key: %w", err)
	}
	return newSigner(name, privateKey)
}

func newSigner(name string, key []byte) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("identity key has an invalid size")
	}
	privateKey := append(ed25519.PrivateKey(nil), key...)
	return &Signer{name: name, privateKey: privateKey}, nil
}

// Name returns the configured endpoint name.
func (s *Signer) Name() string { return s.name }

// PublicKey returns the raw-base64 public identity key.
func (s *Signer) PublicKey() string {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return base64.RawStdEncoding.EncodeToString(publicKey)
}

// Sign signs canonical JSON and returns raw-base64 Ed25519 bytes.
func (s *Signer) Sign(value any) (string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode signed value: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.privateKey, canonical)), nil
}

// Verify verifies raw-base64 Ed25519 bytes over canonical JSON.
func Verify(publicKeyText string, value any, signatureText string) error {
	publicKey, err := base64.RawStdEncoding.DecodeString(publicKeyText)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("peer public key is invalid")
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("signature is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode signed value: %w", err)
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// Checkpoint is an independently storable signed audit head.
type Checkpoint struct {
	Version   int    `json:"version"`
	Identity  string `json:"identity"`
	PublicKey string `json:"public_key"`
	Sequence  uint64 `json:"sequence"`
	AuditHead string `json:"audit_head"`
	CreatedAt string `json:"created_at"`
	Signature string `json:"signature"`
}

type unsignedCheckpoint struct {
	Version   int    `json:"version"`
	Identity  string `json:"identity"`
	PublicKey string `json:"public_key"`
	Sequence  uint64 `json:"sequence"`
	AuditHead string `json:"audit_head"`
	CreatedAt string `json:"created_at"`
}

// Checkpoint signs a current audit head for independent anchoring.
func (s *Signer) Checkpoint(sequence uint64, head string, now time.Time) (Checkpoint, error) {
	unsigned := unsignedCheckpoint{
		Version:   1,
		Identity:  s.name,
		PublicKey: s.PublicKey(),
		Sequence:  sequence,
		AuditHead: head,
		CreatedAt: now.UTC().Format(time.RFC3339Nano),
	}
	signature, err := s.Sign(unsigned)
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{
		Version: unsigned.Version, Identity: unsigned.Identity, PublicKey: unsigned.PublicKey, Sequence: unsigned.Sequence,
		AuditHead: unsigned.AuditHead, CreatedAt: unsigned.CreatedAt, Signature: signature,
	}, nil
}

// VerifyCheckpoint verifies the self-contained signature. Trust in PublicKey
// still requires an independently pinned key or earlier trusted checkpoint.
func VerifyCheckpoint(checkpoint Checkpoint) error {
	unsigned := unsignedCheckpoint{
		Version: checkpoint.Version, Identity: checkpoint.Identity, PublicKey: checkpoint.PublicKey,
		Sequence: checkpoint.Sequence, AuditHead: checkpoint.AuditHead, CreatedAt: checkpoint.CreatedAt,
	}
	return Verify(checkpoint.PublicKey, unsigned, checkpoint.Signature)
}
