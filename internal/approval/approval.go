// Package approval stores local, operator-created approval records.
package approval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openclaw/turnwire/internal/securestore"
)

// Pending is the exact message awaiting local review.
type Pending struct {
	MessageID   string `json:"message_id"`
	Direction   string `json:"direction"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Body        string `json:"body"`
	BodySHA256  string `json:"body_sha256"`
	ReasonCode  string `json:"reason_code"`
	CreatedAt   string `json:"created_at"`
}

// Binding identifies the exact protocol action an operator approved.
type Binding struct {
	MessageID   string `json:"message_id"`
	Direction   string `json:"direction"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	BodySHA256  string `json:"body_sha256"`
}

// Binding returns the security-relevant fields from a pending request.
func (p Pending) Binding() Binding {
	return Binding{
		MessageID:   p.MessageID,
		Direction:   p.Direction,
		Source:      p.Source,
		Destination: p.Destination,
		BodySHA256:  p.BodySHA256,
	}
}

type approved struct {
	Binding
	ApprovedAt string `json:"approved_at"`
}

// Store holds immutable pending and approval records outside the MCP protocol.
type Store struct {
	store *securestore.Store
}

// Open opens the owner-only approval directory inside the state directory.
func Open(auditDir string, create bool) (*Store, error) {
	store, err := securestore.Open(filepath.Join(auditDir, "approvals"), create, "approval directory")
	if err != nil {
		return nil, err
	}
	return &Store{store: store}, nil
}

func (s *Store) Close() error { return s.store.Close() }

// AliasesDirectory reports whether candidate is the approvals directory.
func (s *Store) AliasesDirectory(candidate *os.File) (bool, error) {
	return s.store.AliasesDirectory(candidate)
}

// SavePending durably stores an exact review request. Replays must match.
func (s *Store) SavePending(pending Pending) error {
	data, err := json.Marshal(pending)
	if err != nil {
		return fmt.Errorf("encode pending approval: %w", err)
	}
	name := pending.MessageID + ".pending.json"
	err = s.store.Create(name, data)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("store pending approval: %w", err)
	}
	existing, readErr := s.store.Read(name)
	if readErr != nil {
		return fmt.Errorf("read pending approval replay: %w", readErr)
	}
	var prior Pending
	decoder := json.NewDecoder(bytes.NewReader(existing))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&prior); decodeErr != nil {
		return fmt.Errorf("decode pending approval replay: %w", decodeErr)
	}
	if prior.Binding() != pending.Binding() || prior.Body != pending.Body {
		return errors.New("pending approval conflicts with an existing message")
	}
	return nil
}

// Pending loads one exact review request for local operator display.
func (s *Store) Pending(messageID string) (Pending, error) {
	data, err := s.store.Read(messageID + ".pending.json")
	if err != nil {
		return Pending{}, err
	}
	var pending Pending
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pending); err != nil {
		return Pending{}, fmt.Errorf("decode pending approval: %w", err)
	}
	return pending, nil
}

// Approve writes an immutable approval bound to one direction and peer pair.
func (s *Store) Approve(binding Binding, now time.Time) error {
	record := approved{
		Binding:    binding,
		ApprovedAt: now.UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode approval: %w", err)
	}
	err = s.store.Create(binding.MessageID+".approved.json", data)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := s.store.Read(binding.MessageID + ".approved.json")
		if readErr != nil {
			return fmt.Errorf("read existing approval: %w", readErr)
		}
		var prior approved
		if decodeErr := json.Unmarshal(existing, &prior); decodeErr != nil {
			return fmt.Errorf("decode existing approval: %w", decodeErr)
		}
		if prior.Binding == binding {
			return nil
		}
		return errors.New("approval conflicts with an existing message")
	}
	if err != nil {
		return fmt.Errorf("store approval: %w", err)
	}
	return nil
}

// IsApproved verifies an operator approval for this exact protocol action.
func (s *Store) IsApproved(binding Binding) (bool, error) {
	data, err := s.store.Read(binding.MessageID + ".approved.json")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var record approved
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return false, fmt.Errorf("decode approval: %w", err)
	}
	return record.Binding == binding, nil
}
