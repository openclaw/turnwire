package mailbox

import (
	"encoding/json"
	"errors"

	"github.com/openclaw/turnwire/internal/audit"
)

type requestRecord struct {
	hash      string
	messageID string
	createdAt string
	bodyHash  string
	output    SendOutput
	final     bool
}

type receivedRecord struct {
	envelopeHash       string
	receivedAt         string
	acceptanceSequence uint64
	acceptanceHead     string
	output             ReceiveOutput
}

func (s *Service) request(requestID string) requestRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[requestID]
}
func (s *Service) setRequest(requestID string, record requestRecord) {
	s.mu.Lock()
	s.requests[requestID] = record
	s.mu.Unlock()
}

func (s *Service) rebuildIndex() error {
	localKeys, err := s.localSigningKeys()
	if err != nil {
		return err
	}
	// Older final events omit the reason; recover it from the same guard
	// precedence used by the live evaluation path.
	type decisionState struct{ decision, reason string }
	decisions := make(map[string]decisionState)
	return s.audit.Scan(func(entry audit.Entry) error {
		messageID := entry.Details["message_id"]
		scope := entry.Details["direction"] + ":" + messageID
		reason := entry.Details["reason_code"]
		if reason == "" {
			reason = decisions[scope].reason
		}
		switch entry.Type {
		case eventDeterministicGuard:
			decisions[scope] = decisionState{entry.Details["decision"], entry.Details["reason_code"]}
		case eventModelGuard:
			prior := decisions[scope]
			decision, reason := effectiveDecision(prior.decision, prior.reason, entry.Details["decision"], entry.Details["reason_code"])
			decisions[scope] = decisionState{decision, reason}

		case eventMessageSubmitted:
			binding := hashText(entry.Details["destination"] + "\x00" + entry.ConversationID + "\x00" + entry.Text)
			s.requests[sendClaimKey(entry.RequestID)] = requestRecord{hash: binding, messageID: messageID, createdAt: entry.Timestamp, bodyHash: entry.TextSHA256}
		case eventMessageBlocked:
			if entry.Details["direction"] == "outbound" {
				key := sendClaimKey(entry.RequestID)
				record := s.requests[key]
				record.final = true
				record.output = SendOutput{Status: "denied", MessageID: messageID, RequestID: entry.RequestID, BodySHA256: record.bodyHash, Decision: "deny", ReasonCode: entry.ErrorCode, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
				s.requests[key] = record
			}
		case eventOutboundReleased:
			var envelope Envelope
			if err := json.Unmarshal([]byte(entry.Text), &envelope); err != nil {
				return err
			}
			s.sent[envelope.MessageID] = envelope
			key := sendClaimKey(entry.RequestID)
			record := s.requests[key]
			record.final = true
			record.output = SendOutput{Status: "released", MessageID: envelope.MessageID, RequestID: envelope.RequestID, BodySHA256: envelope.BodySHA256, Decision: envelope.GuardDecision, ReasonCode: reason, Envelope: &envelope, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
			s.requests[key] = record
		case eventInboundAccepted:
			output := ReceiveOutput{Status: "accepted", MessageID: messageID, Decision: entry.Details["decision"], ReasonCode: reason, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
			s.received[messageID] = receivedRecord{envelopeHash: entry.Details["envelope_sha256"], receivedAt: entry.Timestamp, acceptanceSequence: entry.Seq, acceptanceHead: entry.EntryHash, output: output}
			s.inbox = append(s.inbox, Message{MessageID: messageID, ConversationID: entry.ConversationID, Source: entry.Details["source"], Destination: entry.Details["destination"], Body: entry.Text, BodySHA256: entry.TextSHA256, ReceivedAt: entry.Timestamp, AuditSequence: entry.Seq})
		case eventAcknowledgementIssued:
			received, ok := s.received[messageID]
			if !ok {
				return errors.New("acknowledgement precedes inbound acceptance")
			}
			var ack Acknowledgement
			if err := json.Unmarshal([]byte(entry.Details["acknowledgement"]), &ack); err != nil {
				return err
			}
			if ack.Version != 1 || ack.MessageID != messageID || ack.Source != s.signer.Name() || ack.Destination != entry.Details["source"] ||
				ack.EnvelopeSHA256 != received.envelopeHash || ack.ReceivedAt != received.receivedAt ||
				ack.ReceiverAuditSequence != received.acceptanceSequence || ack.ReceiverAuditHead != received.acceptanceHead ||
				!verifyHistoricalAcknowledgement(localKeys, ack) {
				return errors.New("stored acknowledgement does not match inbound acceptance")
			}
			received.output.Acknowledgement = nil
			if verifyAcknowledgement(s.signer.PublicKey(), ack) == nil {
				received.output.Acknowledgement = &ack
			}
			received.output.AuditSequence, received.output.AuditHead = entry.Seq, entry.EntryHash
			s.received[messageID] = received
		case eventInboundVerified:
			s.seenInbound[messageID] = entry.Details["envelope_sha256"]
		case eventDeliveryConfirmed:
			s.confirmed[messageID] = ConfirmOutput{Status: "confirmed", MessageID: messageID, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
		}
		return nil
	})
}

func sendClaimKey(requestID string) string { return "send:" + requestID }
func hashJSON(value any) string            { encoded, _ := json.Marshal(value); return hashText(string(encoded)) }
func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
