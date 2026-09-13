package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openclaw/turnwire/internal/identity"
)

func (s *Service) Inbox(_ context.Context, input InboxInput) (InboxOutput, error) {
	if s.isClosing() {
		return InboxOutput{}, ErrClosed
	}
	if err := takeBudget(s.requestBudget, s.now()); err != nil {
		return InboxOutput{}, err
	}
	release, err := s.beginOperation()
	if err != nil {
		return InboxOutput{}, err
	}
	defer release()
	if input.Limit == 0 {
		input.Limit = 20
	}
	if input.Limit < 1 || input.Limit > 100 {
		return InboxOutput{}, ErrInvalidInput
	}
	s.mu.Lock()
	messages := make([]Message, 0, input.Limit)
	encodedBytes := inboxOutputBaseBytes
	for _, message := range s.inbox {
		if message.AuditSequence > input.AfterSequence {
			encoded, encodeErr := json.Marshal(message)
			if encodeErr != nil {
				s.mu.Unlock()
				return InboxOutput{}, fmt.Errorf("encode inbox message: %w", encodeErr)
			}
			separator := 0
			if len(messages) > 0 {
				separator = 1
			}
			if encodedBytes+separator+len(encoded) > MaxInboxOutputBytes {
				break
			}
			messages = append(messages, message)
			encodedBytes += separator + len(encoded)
			if len(messages) == input.Limit {
				break
			}
		}
	}
	s.mu.Unlock()
	requestID, err := newID()
	if err != nil {
		return InboxOutput{}, err
	}
	entry, err := s.appendEvent(requestID, requestID, requestID, eventInboxRead, "succeeded", "", "", map[string]string{"identity": s.signer.Name(), "message_count": fmt.Sprintf("%d", len(messages))})
	if err != nil {
		return InboxOutput{}, err
	}
	output := InboxOutput{Messages: messages, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
	encoded, err := json.Marshal(output)
	if err != nil {
		return InboxOutput{}, fmt.Errorf("encode inbox output: %w", err)
	}
	if len(encoded) > MaxInboxOutputBytes {
		return InboxOutput{}, errors.New("inbox output exceeds protocol byte limit")
	}
	return output, nil
}

func (s *Service) Checkpoint() (identity.Checkpoint, error) {
	if s.isClosing() {
		return identity.Checkpoint{}, ErrClosed
	}
	if err := takeBudget(s.requestBudget, s.now()); err != nil {
		return identity.Checkpoint{}, err
	}
	release, err := s.beginOperation()
	if err != nil {
		return identity.Checkpoint{}, err
	}
	defer release()
	sequence, head, err := s.audit.Head()
	if err != nil {
		return identity.Checkpoint{}, err
	}
	return s.signer.Checkpoint(sequence, head, s.deploymentSHA256, s.now())
}

const inboxOutputBaseBytes = len(`{"messages":[],"audit_sequence":18446744073709551615,"audit_head":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`)
