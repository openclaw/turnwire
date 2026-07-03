package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/guard"
	"github.com/openclaw/turnwire/internal/identity"
)

const (
	eventMessageSubmitted      = "message_submitted"
	eventDeterministicGuard    = "deterministic_guard"
	eventModelGuard            = "model_guard"
	eventGuardFailed           = "guard_failed"
	eventApprovalRequired      = "approval_required"
	eventApprovalConsumed      = "approval_consumed"
	eventMessageBlocked        = "message_blocked"
	eventOutboundReleased      = "outbound_released"
	eventInboundVerified       = "inbound_verified"
	eventInboundAccepted       = "inbound_accepted"
	eventAcknowledgementIssued = "acknowledgement_issued"
	eventDeliveryConfirmed     = "delivery_confirmed"
	eventInboxRead             = "inbox_read"
)

type Options struct {
	Audit           *audit.Log
	Signer          *identity.Signer
	Peers           map[string]string
	Guard           guard.Evaluator
	Approvals       *approval.Store
	Policy          string
	PolicyVersion   string
	MaxMessageBytes int
	Timeout         time.Duration
	MaxMessageAge   time.Duration
	MaxConcurrent   int
	Now             func() time.Time
}

type requestRecord struct {
	hash      string
	messageID string
	createdAt string
	bodyHash  string
	output    SendOutput
	final     bool
}

type receivedRecord struct {
	envelopeHash string
	receivedAt   string
	output       ReceiveOutput
}

type Service struct {
	audit           *audit.Log
	signer          *identity.Signer
	peers           map[string]string
	guard           guard.Evaluator
	approvals       *approval.Store
	policy          string
	policyVersion   string
	maxMessageBytes int
	timeout         time.Duration
	maxMessageAge   time.Duration
	semaphore       chan struct{}
	now             func() time.Time
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	mu           sync.Mutex
	closing      bool
	active       map[string]string
	requests     map[string]requestRecord
	sent         map[string]Envelope
	received     map[string]receivedRecord
	seenInbound  map[string]string
	confirmed    map[string]ConfirmOutput
	inbox        []Message
	workers      sync.WaitGroup
	shutdownOnce sync.Once
	drained      chan struct{}
}

func New(opts Options) (*Service, error) {
	if opts.Audit == nil || opts.Signer == nil || opts.Guard == nil || opts.Approvals == nil {
		return nil, errors.New("audit, identity, guard, and approval store are required")
	}
	if opts.MaxMessageBytes <= 0 || opts.Timeout <= 0 || opts.MaxMessageAge <= 0 || opts.MaxConcurrent <= 0 {
		return nil, errors.New("channel limits must be positive")
	}
	if strings.TrimSpace(opts.Policy) == "" || strings.TrimSpace(opts.PolicyVersion) == "" {
		return nil, errors.New("guard policy and version are required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	service := &Service{
		audit: opts.Audit, signer: opts.Signer, peers: clonePeers(opts.Peers), guard: opts.Guard,
		approvals: opts.Approvals, policy: opts.Policy, policyVersion: opts.PolicyVersion,
		maxMessageBytes: opts.MaxMessageBytes, timeout: opts.Timeout, maxMessageAge: opts.MaxMessageAge,
		semaphore: make(chan struct{}, opts.MaxConcurrent), now: now,
		active: make(map[string]string), requests: make(map[string]requestRecord),
		sent: make(map[string]Envelope), received: make(map[string]receivedRecord), seenInbound: make(map[string]string),
		confirmed: make(map[string]ConfirmOutput),
		drained:   make(chan struct{}), lifecycleCtx: lifecycleCtx, lifecycleCancel: lifecycleCancel,
	}
	if err := service.rebuildIndex(); err != nil {
		lifecycleCancel()
		return nil, err
	}
	return service, nil
}

func (s *Service) Send(ctx context.Context, input SendInput) (SendOutput, error) {
	if err := ctx.Err(); err != nil {
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

func (s *Service) Receive(ctx context.Context, input ReceiveInput) (ReceiveOutput, error) {
	if err := ctx.Err(); err != nil {
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

func (s *Service) Confirm(ctx context.Context, input ConfirmInput) (ConfirmOutput, error) {
	if err := ctx.Err(); err != nil {
		return ConfirmOutput{}, err
	}
	ack := input.Acknowledgement
	if ack.Version != 1 || !validID(ack.MessageID) || !validID(ack.Source) || ack.Destination != s.signer.Name() ||
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

func (s *Service) Inbox(_ context.Context, input InboxInput) (InboxOutput, error) {
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
	for _, message := range s.inbox {
		if message.AuditSequence > input.AfterSequence {
			messages = append(messages, message)
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
	return InboxOutput{Messages: messages, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}, nil
}

func (s *Service) Checkpoint() (identity.Checkpoint, error) {
	release, err := s.beginOperation()
	if err != nil {
		return identity.Checkpoint{}, err
	}
	defer release()
	sequence, head, err := s.audit.Head()
	if err != nil {
		return identity.Checkpoint{}, err
	}
	return s.signer.Checkpoint(sequence, head, s.now())
}

func (s *Service) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		s.lifecycleCancel()
		go func() { s.workers.Wait(); close(s.drained) }()
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.drained:
		return nil
	}
}

func (s *Service) evaluate(ctx context.Context, messageID, requestID, conversationID, direction, source, destination, text string) (string, string, guard.Evaluation, audit.Entry, error) {
	findings := guard.Scan(text)
	deterministicDecision, deterministicReason := guard.DecisionAllow, "allowed"
	for _, finding := range findings {
		if finding.Decision == guard.DecisionDeny || deterministicDecision == guard.DecisionAllow {
			deterministicDecision, deterministicReason = finding.Decision, finding.Code
		}
	}
	details := messageDetails(direction, source, destination, messageID)
	details["decision"] = deterministicDecision
	details["reason_code"] = deterministicReason
	entry, err := s.appendEvent(messageID, requestID, conversationID, eventDeterministicGuard, "completed", "", "", details)
	if err != nil {
		return "", "", guard.Evaluation{}, audit.Entry{}, err
	}
	if deterministicDecision == guard.DecisionDeny {
		return deterministicDecision, deterministicReason, guard.Evaluation{Model: "not_called"}, entry, nil
	}
	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	stopShutdownCancel := context.AfterFunc(s.lifecycleCtx, cancel)
	evaluation, evalErr := s.guard.Evaluate(callCtx, guard.Input{Direction: direction, Source: source, Destination: destination, Text: text, Policy: s.policy})
	callErr := callCtx.Err()
	stopShutdownCancel()
	cancel()
	if callErr != nil {
		evalErr = callErr
	}
	if evalErr != nil {
		failed, appendErr := s.appendEvent(messageID, requestID, conversationID, eventGuardFailed, "failed", guardErrorCode(evalErr), "", messageDetails(direction, source, destination, messageID))
		if appendErr != nil {
			return "", "", guard.Evaluation{}, audit.Entry{}, errors.Join(evalErr, appendErr)
		}
		return "", "", guard.Evaluation{}, failed, fmt.Errorf("model guard failed closed: %w", evalErr)
	}
	details = messageDetails(direction, source, destination, messageID)
	details["decision"] = evaluation.Decision
	details["reason_code"] = evaluation.ReasonCode
	details["model"] = evaluation.Model
	details["policy_version"] = s.policyVersion
	if evaluation.ProviderRequestID != "" {
		details["provider_request_id"] = evaluation.ProviderRequestID
	}
	if evaluation.ResponseID != "" {
		details["provider_response_id"] = evaluation.ResponseID
	}
	entry, err = s.appendEvent(messageID, requestID, conversationID, eventModelGuard, "completed", "", "", details)
	if err != nil {
		return "", "", guard.Evaluation{}, audit.Entry{}, err
	}
	decision, reason := evaluation.Decision, evaluation.ReasonCode
	if deterministicDecision == guard.DecisionReview && decision == guard.DecisionAllow {
		decision, reason = guard.DecisionReview, deterministicReason
	}
	return decision, reason, evaluation, entry, nil
}

func (s *Service) validateEnvelope(envelope Envelope) (string, error) {
	if envelope.Version != 1 || !validID(envelope.MessageID) || !validID(envelope.RequestID) || !validID(envelope.ConversationID) || !validID(envelope.Source) ||
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

func (s *Service) claim(key, binding string) (func(), *SendOutput, error) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, nil, ErrClosed
	}
	if record, ok := s.requests[key]; ok {
		if record.hash != binding {
			s.mu.Unlock()
			return nil, nil, ErrConflict
		}
		if record.final {
			output := record.output
			s.mu.Unlock()
			return func() {}, &output, nil
		}
	}
	if existing, ok := s.active[key]; ok {
		s.mu.Unlock()
		if existing != binding {
			return nil, nil, ErrConflict
		}
		return nil, nil, ErrBusy
	}
	select {
	case s.semaphore <- struct{}{}:
		s.workers.Add(1)
		s.active[key] = binding
		s.mu.Unlock()
		return func() { s.mu.Lock(); delete(s.active, key); <-s.semaphore; s.mu.Unlock(); s.workers.Done() }, nil, nil
	default:
		s.mu.Unlock()
		return nil, nil, ErrBusy
	}
}

func (s *Service) beginOperation() (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil, ErrClosed
	}
	s.workers.Add(1)
	return s.workers.Done, nil
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

func (s *Service) savePending(messageID, direction, source, destination, text, reason, createdAt string) error {
	return s.approvals.SavePending(approval.Pending{MessageID: messageID, Direction: direction, Source: source, Destination: destination, Body: text, BodySHA256: hashText(text), ReasonCode: reason, CreatedAt: createdAt})
}

func (s *Service) appendEvent(exchangeID, requestID, conversationID, eventType, status, errorCode, text string, details map[string]string) (audit.Entry, error) {
	eventID, err := newID()
	if err != nil {
		return audit.Entry{}, err
	}
	return s.audit.Append(audit.Event{EventID: eventID, ExchangeID: exchangeID, RequestID: requestID, ConversationID: conversationID, Type: eventType, Status: status, ErrorCode: errorCode, Text: text, Details: details})
}

func (s *Service) rebuildIndex() error {
	return s.audit.Scan(func(entry audit.Entry) error {
		messageID := entry.Details["message_id"]
		switch entry.Type {
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
			record.output = SendOutput{Status: "released", MessageID: envelope.MessageID, RequestID: envelope.RequestID, BodySHA256: envelope.BodySHA256, Decision: envelope.GuardDecision, Envelope: &envelope, AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
			s.requests[key] = record
		case eventInboundAccepted:
			output := ReceiveOutput{Status: "accepted", MessageID: messageID, Decision: entry.Details["decision"], AuditSequence: entry.Seq, AuditHead: entry.EntryHash}
			s.received[messageID] = receivedRecord{envelopeHash: entry.Details["envelope_sha256"], receivedAt: entry.Timestamp, output: output}
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
			if ack.MessageID != messageID || ack.Source != s.signer.Name() || ack.Destination != entry.Details["source"] ||
				ack.EnvelopeSHA256 != received.envelopeHash || ack.ReceivedAt != received.receivedAt ||
				ack.ReceiverAuditSequence != received.output.AuditSequence || ack.ReceiverAuditHead != received.output.AuditHead ||
				verifyAcknowledgement(s.signer.PublicKey(), ack) != nil {
				return errors.New("stored acknowledgement does not match inbound acceptance")
			}
			received.output.Acknowledgement = &ack
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

func clonePeers(peers map[string]string) map[string]string {
	cloned := make(map[string]string, len(peers))
	for k, v := range peers {
		cloned[k] = v
	}
	return cloned
}
func sendClaimKey(requestID string) string { return "send:" + requestID }
func messageDetails(direction, source, destination, messageID string) map[string]string {
	return map[string]string{"direction": direction, "source": source, "destination": destination, "message_id": messageID}
}
func hashJSON(value any) string { encoded, _ := json.Marshal(value); return hashText(string(encoded)) }
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
func guardErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, guard.ErrMissingAPIKey) {
		return "missing_api_key"
	}
	return "provider_error"
}
