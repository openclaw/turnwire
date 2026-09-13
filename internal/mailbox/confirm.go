package mailbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/turnwire/internal/identifier"
)

func (s *Service) Confirm(ctx context.Context, input ConfirmInput) (ConfirmOutput, error) {
	if err := ctx.Err(); err != nil {
		return ConfirmOutput{}, err
	}
	if s.isClosing() {
		return ConfirmOutput{}, ErrClosed
	}
	if err := takeBudget(s.requestBudget, s.now()); err != nil {
		return ConfirmOutput{}, err
	}
	ack := input.Acknowledgement
	if ack.Version != 1 || !identifier.Valid(ack.MessageID) || !identifier.Valid(ack.Source) || ack.Destination != s.signer.Name() ||
		!validSHA256(ack.EnvelopeSHA256) || ack.ReceiverAuditSequence == 0 || !validSHA256(ack.ReceiverAuditHead) {
		return ConfirmOutput{}, ErrUnauthorized
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, ack.ReceivedAt)
	if err != nil || receivedAt.Location() != time.UTC || receivedAt.Format(time.RFC3339Nano) != ack.ReceivedAt ||
		receivedAt.After(s.now().Add(5*time.Minute)) || s.now().Sub(receivedAt) > s.maxMessageAge {
		return ConfirmOutput{}, ErrUnauthorized
	}
	publicKey, ok := s.peers[ack.Source]
	if !ok || verifyAcknowledgement(publicKey, ack) != nil {
		return ConfirmOutput{}, ErrUnauthorized
	}
	s.mu.Lock()
	envelope, sent := s.sent[ack.MessageID]
	existing, confirmed := s.confirmed[ack.MessageID]
	s.mu.Unlock()
	if !sent || ack.Source != envelope.Destination || ack.EnvelopeSHA256 != hashJSON(envelope) {
		return ConfirmOutput{}, ErrConflict
	}
	if confirmed {
		return existing, nil
	}
	release, _, err := s.claim("confirm:"+ack.MessageID, ack.EnvelopeSHA256)
	if err != nil {
		return ConfirmOutput{}, err
	}
	defer release()
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return ConfirmOutput{}, fmt.Errorf("encode acknowledgement: %w", err)
	}
	details := map[string]string{
		"direction": "outbound", "source": envelope.Source, "destination": envelope.Destination,
		"message_id": ack.MessageID, "envelope_sha256": ack.EnvelopeSHA256, "acknowledgement": string(ackJSON),
	}
	entry, err := s.appendEvent(ack.MessageID, envelope.RequestID, envelope.ConversationID, eventDeliveryConfirmed, "confirmed", "", "", details)
	if err != nil {
		return ConfirmOutput{}, err
	}
	output := ConfirmOutput{Status: "confirmed", MessageID: ack.MessageID, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
	s.mu.Lock()
	s.confirmed[ack.MessageID] = output
	s.mu.Unlock()
	return output, nil
}
