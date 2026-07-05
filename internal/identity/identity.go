// Package identity manages the endpoint signing identity and signed envelopes.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
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
	Version          int    `json:"version"`
	Identity         string `json:"identity"`
	PublicKey        string `json:"public_key"`
	Sequence         uint64 `json:"sequence"`
	AuditHead        string `json:"audit_head"`
	DeploymentSHA256 string `json:"deployment_sha256"`
	CreatedAt        string `json:"created_at"`
	Signature        string `json:"signature"`
}

type unsignedCheckpoint struct {
	Version          int    `json:"version"`
	Identity         string `json:"identity"`
	PublicKey        string `json:"public_key"`
	Sequence         uint64 `json:"sequence"`
	AuditHead        string `json:"audit_head"`
	DeploymentSHA256 string `json:"deployment_sha256"`
	CreatedAt        string `json:"created_at"`
}

// Rotation proves continuity from the currently pinned key to a new key. Both
// keys sign the transition before the old private key is atomically replaced.
type Rotation struct {
	Identity          string `json:"identity"`
	PreviousPublicKey string `json:"previous_public_key"`
	NewPublicKey      string `json:"new_public_key"`
	CreatedAt         string `json:"created_at"`
	PreviousSignature string `json:"previous_signature"`
	NewSignature      string `json:"new_signature"`
}

type unsignedRotation struct {
	Identity          string `json:"identity"`
	PreviousPublicKey string `json:"previous_public_key"`
	NewPublicKey      string `json:"new_public_key"`
	CreatedAt         string `json:"created_at"`
}

type countersignedRotation struct {
	unsignedRotation
	PreviousSignature string `json:"previous_signature"`
}

// Revocation proves that the local identity intentionally destroyed its
// private key. Peers must remove the pinned key separately.
type Revocation struct {
	Identity  string `json:"identity"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
	Signature string `json:"signature"`
}

type unsignedRevocation struct {
	Identity  string `json:"identity"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

// RotationPlan holds a signed transition until its caller has durably recorded
// the certificate. Commit then atomically replaces the old private key.
type RotationPlan struct {
	auditDir      string
	newPrivateKey ed25519.PrivateKey
	rotation      Rotation
}

// Certificate returns the dual-signed public transition.
func (p *RotationPlan) Certificate() Rotation { return p.rotation }

// PrepareRotation creates a transition without mutating the current identity.
func PrepareRotation(auditDir, name string, now time.Time) (*RotationPlan, error) {
	store, err := securestore.Open(auditDir, false, "identity directory")
	if err != nil {
		return nil, err
	}
	defer store.Close()
	oldBytes, err := store.Read(keyFileName)
	if err != nil {
		return nil, fmt.Errorf("load identity key: %w", err)
	}
	oldSigner, err := newSigner(name, oldBytes)
	if err != nil {
		return nil, err
	}
	_, newBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate identity key: %w", err)
	}
	newSigner, err := newSigner(name, newBytes)
	if err != nil {
		return nil, err
	}
	unsigned := unsignedRotation{
		Identity: name, PreviousPublicKey: oldSigner.PublicKey(), NewPublicKey: newSigner.PublicKey(),
		CreatedAt: now.UTC().Format(time.RFC3339Nano),
	}
	previousSignature, err := oldSigner.Sign(unsigned)
	if err != nil {
		return nil, err
	}
	newSignature, err := newSigner.Sign(countersignedRotation{unsignedRotation: unsigned, PreviousSignature: previousSignature})
	if err != nil {
		return nil, err
	}
	rotation := Rotation{
		Identity: unsigned.Identity, PreviousPublicKey: unsigned.PreviousPublicKey, NewPublicKey: unsigned.NewPublicKey,
		CreatedAt: unsigned.CreatedAt, PreviousSignature: previousSignature, NewSignature: newSignature,
	}
	return &RotationPlan{auditDir: auditDir, newPrivateKey: newBytes, rotation: rotation}, nil
}

// Commit replaces the key only if the current identity still matches the
// certificate's previous key.
func (p *RotationPlan) Commit() error {
	if p == nil || len(p.newPrivateKey) != ed25519.PrivateKeySize {
		return errors.New("identity rotation plan is unavailable")
	}
	store, err := securestore.Open(p.auditDir, false, "identity directory")
	if err != nil {
		return err
	}
	defer store.Close()
	current, err := store.Read(keyFileName)
	if err != nil {
		return fmt.Errorf("load identity key: %w", err)
	}
	currentSigner, err := newSigner(p.rotation.Identity, current)
	if err != nil {
		return err
	}
	if currentSigner.PublicKey() != p.rotation.PreviousPublicKey {
		return errors.New("identity changed after rotation was prepared")
	}
	if err := store.Replace(keyFileName, p.newPrivateKey); err != nil {
		return fmt.Errorf("replace identity key: %w", err)
	}
	clear(p.newPrivateKey)
	p.newPrivateKey = nil
	return nil
}

// VerifyRotation verifies both signatures and the expected currently pinned
// identity. A transition for any other key or peer fails closed.
func VerifyRotation(rotation Rotation, identityName, pinnedPublicKey string) error {
	if rotation.Identity != identityName || rotation.PreviousPublicKey != pinnedPublicKey || rotation.NewPublicKey == rotation.PreviousPublicKey {
		return errors.New("identity rotation does not match the pinned peer")
	}
	unsigned := unsignedRotation{
		Identity: rotation.Identity, PreviousPublicKey: rotation.PreviousPublicKey,
		NewPublicKey: rotation.NewPublicKey, CreatedAt: rotation.CreatedAt,
	}
	if _, err := time.Parse(time.RFC3339Nano, rotation.CreatedAt); err != nil {
		return errors.New("identity rotation timestamp is invalid")
	}
	if err := Verify(rotation.PreviousPublicKey, unsigned, rotation.PreviousSignature); err != nil {
		return fmt.Errorf("verify previous identity signature: %w", err)
	}
	if err := Verify(rotation.NewPublicKey, countersignedRotation{unsignedRotation: unsigned, PreviousSignature: rotation.PreviousSignature}, rotation.NewSignature); err != nil {
		return fmt.Errorf("verify new identity signature: %w", err)
	}
	return nil
}

// RevocationPlan holds a signed final certificate until the caller has
// durably recorded it.
type RevocationPlan struct {
	auditDir   string
	revocation Revocation
}

// Certificate returns the signed public revocation evidence.
func (p *RevocationPlan) Certificate() Revocation { return p.revocation }

// PrepareRevocation signs a certificate without deleting the private key.
func PrepareRevocation(auditDir, name string, now time.Time) (*RevocationPlan, error) {
	signer, err := LoadOrCreate(auditDir, name, false)
	if err != nil {
		return nil, err
	}
	unsigned := unsignedRevocation{Identity: name, PublicKey: signer.PublicKey(), CreatedAt: now.UTC().Format(time.RFC3339Nano)}
	signature, err := signer.Sign(unsigned)
	if err != nil {
		return nil, err
	}
	return &RevocationPlan{auditDir: auditDir, revocation: Revocation{
		Identity: unsigned.Identity, PublicKey: unsigned.PublicKey, CreatedAt: unsigned.CreatedAt, Signature: signature,
	}}, nil
}

// Commit deletes the key only if it still matches the prepared certificate.
func (p *RevocationPlan) Commit() error {
	if p == nil || p.revocation.PublicKey == "" {
		return errors.New("identity revocation plan is unavailable")
	}
	store, err := securestore.Open(p.auditDir, false, "identity directory")
	if err != nil {
		return err
	}
	defer store.Close()
	current, err := store.Read(keyFileName)
	if err != nil {
		return fmt.Errorf("load identity key: %w", err)
	}
	currentSigner, err := newSigner(p.revocation.Identity, current)
	if err != nil {
		return err
	}
	if currentSigner.PublicKey() != p.revocation.PublicKey {
		return errors.New("identity changed after revocation was prepared")
	}
	if err := store.Delete(keyFileName); err != nil {
		return fmt.Errorf("delete identity key: %w", err)
	}
	p.revocation.PublicKey = ""
	return nil
}

// Checkpoint signs a current audit head for independent anchoring.
func (s *Signer) Checkpoint(sequence uint64, head, deploymentSHA256 string, now time.Time) (Checkpoint, error) {
	decodedDeployment, decodeErr := hex.DecodeString(deploymentSHA256)
	if decodeErr != nil || len(decodedDeployment) != sha256.Size || deploymentSHA256 != strings.ToLower(deploymentSHA256) {
		return Checkpoint{}, errors.New("deployment SHA-256 is required")
	}
	unsigned := unsignedCheckpoint{
		Version:          1,
		Identity:         s.name,
		PublicKey:        s.PublicKey(),
		Sequence:         sequence,
		AuditHead:        head,
		DeploymentSHA256: deploymentSHA256,
		CreatedAt:        now.UTC().Format(time.RFC3339Nano),
	}
	signature, err := s.Sign(unsigned)
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{
		Version: unsigned.Version, Identity: unsigned.Identity, PublicKey: unsigned.PublicKey, Sequence: unsigned.Sequence,
		AuditHead: unsigned.AuditHead, DeploymentSHA256: unsigned.DeploymentSHA256,
		CreatedAt: unsigned.CreatedAt, Signature: signature,
	}, nil
}

// VerifyCheckpoint verifies the self-contained signature. Trust in PublicKey
// still requires an independently pinned key or earlier trusted checkpoint.
func VerifyCheckpoint(checkpoint Checkpoint) error {
	unsigned := unsignedCheckpoint{
		Version: checkpoint.Version, Identity: checkpoint.Identity, PublicKey: checkpoint.PublicKey,
		Sequence: checkpoint.Sequence, AuditHead: checkpoint.AuditHead,
		DeploymentSHA256: checkpoint.DeploymentSHA256, CreatedAt: checkpoint.CreatedAt,
	}
	return Verify(checkpoint.PublicKey, unsigned, checkpoint.Signature)
}
