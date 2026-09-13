package mailbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/guard"
	"github.com/openclaw/turnwire/internal/identifier"
)

func (s *Service) Receive(ctx context.Context, input ReceiveInput) (ReceiveOutput, error) {
	if err := ctx.Err(); err != nil {
		return ReceiveOutput{}, err
	}
	if s.isClosing() {
		return ReceiveOutput{}, ErrClosed
	}
	if err := takeBudget(s.requestBudget, s.now()); err != nil {
		return ReceiveOutput{}, err
	}
	envelope := input.Envelope
	envelopeHash, err := s.validateEnvelope(envelope)
	if err != nil {
		return ReceiveOutput{}, err
	}
	release, existing, err := s.claim("receive:"+envelope.MessageID, envelopeHash)
	if err != nil {
		return ReceiveOutput{}, err
	}
	if existing != nil {
		return ReceiveOutput{}, ErrConflict
	}
	defer release()
	s.mu.Lock()
	if received, ok := s.received[envelope.MessageID]; ok {
		s.mu.Unlock()
		if received.envelopeHash != envelopeHash {
			return ReceiveOutput{}, ErrConflict
		}
		if received.output.Acknowledgement != nil {
			return received.output, nil
		}
		return s.issueAcknowledgement(envelope, received)
	}
	if seenHash, ok := s.seenInbound[envelope.MessageID]; ok && seenHash != envelopeHash {
		s.mu.Unlock()
		return ReceiveOutput{}, ErrConflict
	}
	s.mu.Unlock()

	_, err = s.appendEvent(envelope.MessageID, envelope.RequestID, envelope.ConversationID, eventInboundVerified, "verified", "", envelope.Body, map[string]string{
		"direction": "inbound", "source": envelope.Source, "destination": envelope.Destination,
		"message_id": envelope.MessageID, "envelope_sha256": envelopeHash, "body_sha256": envelope.BodySHA256,
	})
	if err != nil {
		return ReceiveOutput{}, err
	}
	s.mu.Lock()
	s.seenInbound[envelope.MessageID] = envelopeHash
	s.mu.Unlock()
	decision, reason, _, guardEntry, err := s.evaluate(ctx, envelope.MessageID, envelope.RequestID, envelope.ConversationID, "inbound", envelope.Source, envelope.Destination, envelope.Body)
	if err != nil {
		return ReceiveOutput{}, err
	}
	base := ReceiveOutput{Status: decision, MessageID: envelope.MessageID, Decision: decision, ReasonCode: reason, AuditSequence: guardEntry.Seq, AuditHead: guardEntry.EntryHash}
	if decision == guard.DecisionDeny {
		blocked, appendErr := s.appendEvent(envelope.MessageID, envelope.RequestID, envelope.ConversationID, eventMessageBlocked, "denied", reason, "", messageDetails("inbound", envelope.Source, envelope.Destination, envelope.MessageID))
		if appendErr != nil {
			return ReceiveOutput{}, appendErr
		}
		base.Status, base.AuditSequence, base.AuditHead = "denied", blocked.Seq, blocked.EntryHash
		return base, nil
	}
	if decision == guard.DecisionReview {
		approvalBinding := approval.Binding{MessageID: envelope.MessageID, Direction: "inbound", Source: envelope.Source, Destination: envelope.Destination, BodySHA256: envelope.BodySHA256}
		approved, approvalErr := s.approvals.IsApproved(approvalBinding)
		if approvalErr != nil {
			return ReceiveOutput{}, approvalErr
		}
		if !approved {
			if err := s.savePending(envelope.MessageID, "inbound", envelope.Source, envelope.Destination, envelope.Body, reason, envelope.CreatedAt); err != nil {
				return ReceiveOutput{}, err
			}
			pending, appendErr := s.appendEvent(envelope.MessageID, envelope.RequestID, envelope.ConversationID, eventApprovalRequired, "pending", reason, "", messageDetails("inbound", envelope.Source, envelope.Destination, envelope.MessageID))
			if appendErr != nil {
				return ReceiveOutput{}, appendErr
			}
			base.Status, base.AuditSequence, base.AuditHead = "review_required", pending.Seq, pending.EntryHash
			return base, nil
		}
		guardEntry, err = s.appendEvent(envelope.MessageID, envelope.RequestID, envelope.ConversationID, eventApprovalConsumed, "approved", reason, "", messageDetails("inbound", envelope.Source, envelope.Destination, envelope.MessageID))
		if err != nil {
			return ReceiveOutput{}, err
		}
		decision = "review_approved"
	}
	details := messageDetails("inbound", envelope.Source, envelope.Destination, envelope.MessageID)
	details["envelope_sha256"] = envelopeHash
	details["decision"] = decision
	details["reason_code"] = reason
	accepted, err := s.appendEvent(envelope.MessageID, envelope.RequestID, envelope.ConversationID, eventInboundAccepted, "accepted", "", envelope.Body, details)
	if err != nil {
		return ReceiveOutput{}, err
	}
	base.Status, base.Decision = "accepted", decision
	base.AuditSequence, base.AuditHead = accepted.Seq, accepted.EntryHash
	message := Message{MessageID: envelope.MessageID, ConversationID: envelope.ConversationID, Source: envelope.Source, Destination: envelope.Destination, Body: envelope.Body, BodySHA256: envelope.BodySHA256, ReceivedAt: accepted.Timestamp, AuditSequence: accepted.Seq}
	received := receivedRecord{envelopeHash: envelopeHash, receivedAt: accepted.Timestamp, output: base}
	s.mu.Lock()
	s.received[envelope.MessageID] = received
	s.inbox = append(s.inbox, message)
	s.mu.Unlock()
	return s.issueAcknowledgement(envelope, received)
}

func (s *Service) issueAcknowledgement(envelope Envelope, received receivedRecord) (ReceiveOutput, error) {
	ack := Acknowledgement{
		Version: 1, MessageID: envelope.MessageID, Source: s.signer.Name(), Destination: envelope.Source,
		EnvelopeSHA256: received.envelopeHash, ReceivedAt: received.receivedAt,
		ReceiverAuditSequence: received.output.AuditSequence, ReceiverAuditHead: received.output.AuditHead,
	}
	if err := signAcknowledgement(s.signer, &ack); err != nil {
		return ReceiveOutput{}, err
	}
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return ReceiveOutput{}, fmt.Errorf("encode acknowledgement: %w", err)
	}
	details := messageDetails("inbound", envelope.Source, envelope.Destination, envelope.MessageID)
	details["envelope_sha256"] = received.envelopeHash
	details["acknowledgement"] = string(ackJSON)
	issued, err := s.appendEvent(envelope.MessageID, envelope.RequestID, envelope.ConversationID, eventAcknowledgementIssued, "issued", "", "", details)
	if err != nil {
		return ReceiveOutput{}, err
	}
	output := received.output
	output.Acknowledgement = &ack
	output.AuditSequence, output.AuditHead = issued.Seq, issued.EntryHash
	s.mu.Lock()
	s.received[envelope.MessageID] = receivedRecord{envelopeHash: received.envelopeHash, receivedAt: received.receivedAt, output: output}
	s.mu.Unlock()
	return output, nil
}

func (s *Service) validateEnvelope(envelope Envelope) (string, error) {
	if envelope.Version != 1 || !identifier.Valid(envelope.MessageID) || !identifier.Valid(envelope.RequestID) || !identifier.Valid(envelope.ConversationID) || !identifier.Valid(envelope.Source) ||
		envelope.Destination != s.signer.Name() || !validText(envelope.Body, s.maxMessageBytes) || envelope.BodySHA256 != hashText(envelope.Body) ||
		envelope.SourceAuditSequence == 0 || !validSHA256(envelope.SourceAuditHead) || strings.TrimSpace(envelope.PolicyVersion) == "" || len(envelope.PolicyVersion) > 128 ||
		strings.TrimSpace(envelope.GuardModel) == "" || len(envelope.GuardModel) > 128 || (envelope.GuardDecision != guard.DecisionAllow && envelope.GuardDecision != "review_approved") {
		return "", ErrUnauthorized
	}
	publicKey, ok := s.peers[envelope.Source]
	if !ok || verifyEnvelope(publicKey, envelope) != nil {
		return "", ErrUnauthorized
	}
	createdAt, err := time.Parse(time.RFC3339Nano, envelope.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339Nano) != envelope.CreatedAt ||
		createdAt.After(s.now().Add(5*time.Minute)) || s.now().Sub(createdAt) > s.maxMessageAge {
		return "", ErrUnauthorized
	}
	return hashJSON(envelope), nil
}
