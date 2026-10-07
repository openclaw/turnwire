// Package approval stores local, operator-created approval records.
package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/openclaw/turnwire/internal/securestore"
	"github.com/openclaw/turnwire/internal/strictjson"
)

// Pending is the exact message awaiting local review.
type Pending struct {
	MessageID    string `json:"message_id"`
	Direction    string `json:"direction"`
	Source       string `json:"source"`
	Destination  string `json:"destination"`
	Body         string `json:"body"`
	BodyExternal bool   `json:"body_external,omitempty"`
	BodySHA256   string `json:"body_sha256"`
	ReasonCode   string `json:"reason_code"`
	CreatedAt    string `json:"created_at"`
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
// A body that is legal under max_message_bytes can still expand past the
// secure-store cap once JSON escapes it. That body is spilled raw, beside
// the pending record, so the review can still be approved.
func (s *Store) SavePending(pending Pending) error {
	if pending.BodyExternal {
		return errors.New("pending approval body must be inline")
	}
	data, err := json.Marshal(pending)
	if err != nil {
		return fmt.Errorf("encode pending approval: %w", err)
	}
	record := data
	if !securestore.Fits(data) {
		if !securestore.Fits([]byte(pending.Body)) {
			return errors.New("pending approval body does not fit after JSON escaping")
		}
		if err := s.writeSpilledBody(pending); err != nil {
			return err
		}
		spilled := pending
		spilled.Body = ""
		spilled.BodyExternal = true
		record, err = json.Marshal(spilled)
		if err != nil {
			return fmt.Errorf("encode pending approval: %w", err)
		}
		if !securestore.Fits(record) {
			return errors.New("pending approval body does not fit after JSON escaping")
		}
	}
	return s.storePending(pending.MessageID, record, pending)
}

func (s *Store) writeSpilledBody(pending Pending) error {
	// A record that is already stored keeps its body until the replay check.
	if _, err := s.store.Read(pending.MessageID + ".pending.json"); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read pending approval replay: %w", err)
	}
	bodyName := pending.MessageID + ".body"
	err := s.store.Create(bodyName, []byte(pending.Body))
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("store pending approval body: %w", err)
	}
	existing, readErr := s.store.Read(bodyName)
	if readErr != nil {
		return fmt.Errorf("read pending approval body replay: %w", readErr)
	}
	if string(existing) != pending.Body {
		return errors.New("pending approval conflicts with an existing message")
	}
	return nil
}

func (s *Store) storePending(messageID string, data []byte, pending Pending) error {
	err := s.store.Create(messageID+".pending.json", data)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("store pending approval: %w", err)
	}
	prior, readErr := s.loadPending(messageID)
	if readErr != nil {
		return fmt.Errorf("read pending approval replay: %w", readErr)
	}
	if prior.Binding() != pending.Binding() || prior.Body != pending.Body {
		return errors.New("pending approval conflicts with an existing message")
	}
	return nil
}

func (s *Store) loadPending(messageID string) (Pending, error) {
	data, err := s.store.Read(messageID + ".pending.json")
	if err != nil {
		return Pending{}, err
	}
	var pending Pending
	if err := decodeRecord(data, &pending); err != nil {
		return Pending{}, fmt.Errorf("decode pending approval: %w", err)
	}
	if !pending.BodyExternal {
		return pending, nil
	}
	if pending.Body != "" {
		return Pending{}, errors.New("pending approval body is ambiguous")
	}
	body, err := s.store.Read(messageID + ".body")
	if err != nil {
		return Pending{}, fmt.Errorf("read pending approval body: %w", err)
	}
	if !utf8.Valid(body) {
		return Pending{}, errors.New("pending approval body is not valid UTF-8")
	}
	if fmt.Sprintf("%x", sha256.Sum256(body)) != pending.BodySHA256 {
		return Pending{}, errors.New("pending approval body hash does not match")
	}
	pending.Body = string(body)
	pending.BodyExternal = false
	return pending, nil
}

// Pending loads one exact review request for local operator display.
func (s *Store) Pending(messageID string) (Pending, error) {
	return s.loadPending(messageID)
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
		if decodeErr := decodeRecord(existing, &prior); decodeErr != nil {
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
	if err := decodeRecord(data, &record); err != nil {
		return false, fmt.Errorf("decode approval: %w", err)
	}
	return record.Binding == binding, nil
}

func decodeRecord(data []byte, record any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("approval record must be a JSON object")
	}
	if err := strictjson.ValidateText(data); err != nil {
		return err
	}
	if err := strictjson.ValidateUniqueKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(record)
}
