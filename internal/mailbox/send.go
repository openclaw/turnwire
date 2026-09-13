package mailbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/guard"
)

func (s *Service) Send(ctx context.Context, input SendInput) (SendOutput, error) {
	if err := ctx.Err(); err != nil {
		return SendOutput{}, err
	}
	if s.isClosing() {
		return SendOutput{}, ErrClosed
	}
	if err := takeBudget(s.requestBudget, s.now()); err != nil {
		return SendOutput{}, err
	}
	input, err := normalizeSend(input, s.maxMessageBytes)
	if err != nil {
		return SendOutput{}, err
	}
	if _, ok := s.peers[input.Destination]; !ok {
		return SendOutput{}, fmt.Errorf("%w: destination is not a configured peer", ErrInvalidInput)
	}
	binding := hashText(input.Destination + "\x00" + input.ConversationID + "\x00" + input.Text)
	requestKey := sendClaimKey(input.RequestID)
	release, existing, err := s.claim(requestKey, binding)
	if err != nil {
		return SendOutput{}, err
	}
	if existing != nil {
		return *existing, nil
	}
	defer release()

	record := s.request(requestKey)
	messageID := record.messageID
	var submitted audit.Entry
	if messageID == "" {
		messageID, err = newID()
		if err != nil {
			return SendOutput{}, err
		}
		submitted, err = s.appendEvent(messageID, input.RequestID, input.ConversationID, eventMessageSubmitted, "accepted", "", input.Text, map[string]string{
			"direction": "outbound", "source": s.signer.Name(), "destination": input.Destination,
			"message_id": messageID, "body_sha256": hashText(input.Text),
		})
		if err != nil {
			return SendOutput{}, fmt.Errorf("record outbound proposal: %w", err)
		}
		s.setRequest(requestKey, requestRecord{hash: binding, messageID: messageID, createdAt: submitted.Timestamp, bodyHash: submitted.TextSHA256})
	} else {
		submitted = audit.Entry{Timestamp: record.createdAt, TextSHA256: record.bodyHash}
	}

	decision, reason, evaluation, guardEntry, err := s.evaluate(ctx, messageID, input.RequestID, input.ConversationID, "outbound", s.signer.Name(), input.Destination, input.Text)
	if err != nil {
		return SendOutput{}, err
	}
	base := SendOutput{Status: decision, MessageID: messageID, RequestID: input.RequestID, BodySHA256: hashText(input.Text), Decision: decision, ReasonCode: reason, AuditSequence: guardEntry.Seq, AuditHead: guardEntry.EntryHash}
	if decision == guard.DecisionDeny {
		blocked, appendErr := s.appendEvent(messageID, input.RequestID, input.ConversationID, eventMessageBlocked, "denied", reason, "", messageDetails("outbound", s.signer.Name(), input.Destination, messageID))
		if appendErr != nil {
			return SendOutput{}, appendErr
		}
		base.Status, base.AuditSequence, base.AuditHead = "denied", blocked.Seq, blocked.EntryHash
		s.setRequest(requestKey, requestRecord{hash: binding, messageID: messageID, createdAt: submitted.Timestamp, bodyHash: base.BodySHA256, output: base, final: true})
		return base, nil
	}
	if decision == guard.DecisionReview {
		approvalBinding := approval.Binding{MessageID: messageID, Direction: "outbound", Source: s.signer.Name(), Destination: input.Destination, BodySHA256: base.BodySHA256}
		approved, approvalErr := s.approvals.IsApproved(approvalBinding)
		if approvalErr != nil {
			return SendOutput{}, fmt.Errorf("check local approval: %w", approvalErr)
		}
		if !approved {
			if err := s.savePending(messageID, "outbound", s.signer.Name(), input.Destination, input.Text, reason, submitted.Timestamp); err != nil {
				return SendOutput{}, err
			}
			pending, appendErr := s.appendEvent(messageID, input.RequestID, input.ConversationID, eventApprovalRequired, "pending", reason, "", messageDetails("outbound", s.signer.Name(), input.Destination, messageID))
			if appendErr != nil {
				return SendOutput{}, appendErr
			}
			base.Status, base.AuditSequence, base.AuditHead = "review_required", pending.Seq, pending.EntryHash
			s.setRequest(requestKey, requestRecord{hash: binding, messageID: messageID, createdAt: submitted.Timestamp, bodyHash: base.BodySHA256, output: base})
			return base, nil
		}
		guardEntry, err = s.appendEvent(messageID, input.RequestID, input.ConversationID, eventApprovalConsumed, "approved", reason, "", messageDetails("outbound", s.signer.Name(), input.Destination, messageID))
		if err != nil {
			return SendOutput{}, err
		}
		decision = "review_approved"
	}

	envelope := Envelope{
		Version: 1, MessageID: messageID, RequestID: input.RequestID, ConversationID: input.ConversationID,
		Source: s.signer.Name(), Destination: input.Destination, CreatedAt: submitted.Timestamp,
		Body: input.Text, BodySHA256: base.BodySHA256, PolicyVersion: s.policyVersion,
		GuardModel: evaluation.Model, GuardDecision: decision,
		SourceAuditSequence: guardEntry.Seq, SourceAuditHead: guardEntry.EntryHash,
	}
	if err := signEnvelope(s.signer, &envelope); err != nil {
		return SendOutput{}, err
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return SendOutput{}, err
	}
	released, err := s.appendEvent(messageID, input.RequestID, input.ConversationID, eventOutboundReleased, "released", "", string(envelopeJSON), messageDetails("outbound", s.signer.Name(), input.Destination, messageID))
	if err != nil {
		return SendOutput{}, err
	}
	base.Status, base.Decision, base.Envelope = "released", decision, &envelope
	base.AuditSequence, base.AuditHead = released.Seq, released.EntryHash
	s.mu.Lock()
	s.sent[messageID] = envelope
	s.requests[requestKey] = requestRecord{hash: binding, messageID: messageID, createdAt: submitted.Timestamp, bodyHash: base.BodySHA256, output: base, final: true}
	s.mu.Unlock()
	return base, nil
}
