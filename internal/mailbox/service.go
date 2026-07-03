package mailbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/responder"
)

const (
	eventRequestReceived = "request_received"
	eventReplyCommitted  = "reply_committed"
	eventRunFailed       = "run_failed"

	// Bound blocked handlers even when a caller floods one idempotency key.
	maxCoalescedWaitersPerRequest = 1
)

type Options struct {
	Audit          *audit.Log
	Responder      responder.Responder
	MaxInputBytes  int
	MaxOutputBytes int
	Timeout        time.Duration
	MaxConcurrent  int
}

type Service struct {
	audit          *audit.Log
	responder      responder.Responder
	maxInputBytes  int
	maxOutputBytes int
	timeout        time.Duration
	semaphore      chan struct{}
	readAuditEntry func(audit.EntryReference) (audit.Entry, error)

	mu       sync.Mutex
	requests map[string]*requestState
	durable  map[string]durableRequest
	closing  bool

	workers      sync.WaitGroup
	shutdownOnce sync.Once
	drained      chan struct{}
}

type requestState struct {
	requestSHA256   string
	done            chan struct{}
	output          TalkOutput
	err             error
	ctx             context.Context
	cancel          context.CancelFunc
	callers         int
	waiters         int
	bindingVerified bool
	finished        bool
}

func New(opts Options) (*Service, error) {
	if opts.Audit == nil {
		return nil, errors.New("audit log is required")
	}
	if opts.Responder == nil {
		return nil, errors.New("responder is required")
	}
	if opts.MaxInputBytes <= 0 || opts.MaxOutputBytes <= 0 {
		return nil, errors.New("message limits must be positive")
	}
	if opts.Timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if opts.MaxConcurrent <= 0 {
		return nil, errors.New("max concurrency must be positive")
	}
	durable, err := buildDurableRequestIndex(opts.Audit)
	if err != nil {
		return nil, err
	}

	service := &Service{
		audit:          opts.Audit,
		responder:      opts.Responder,
		maxInputBytes:  opts.MaxInputBytes,
		maxOutputBytes: opts.MaxOutputBytes,
		timeout:        opts.Timeout,
		semaphore:      make(chan struct{}, opts.MaxConcurrent),
		readAuditEntry: opts.Audit.ReadReference,
		requests:       make(map[string]*requestState),
		durable:        durable,
		drained:        make(chan struct{}),
	}
	return service, nil
}

func (s *Service) Talk(ctx context.Context, input TalkInput) (TalkOutput, error) {
	if err := ctx.Err(); err != nil {
		return TalkOutput{}, err
	}
	callerProvidedRequestID := input.RequestID != ""
	normalized, err := normalizeInput(input, s.maxInputBytes)
	if err != nil {
		return TalkOutput{}, err
	}
	requestHash := hashRequest(normalized.ConversationID, normalized.Text)

	state, owner, err := s.claimRequest(normalized.RequestID, requestHash, callerProvidedRequestID)
	if err != nil {
		return TalkOutput{}, err
	}
	if owner {
		go s.executeRequest(state, normalized, callerProvidedRequestID)
	}

	return s.waitForRequest(ctx, state, !owner)
}

func (s *Service) executeRequest(state *requestState, input TalkInput, callerProvidedRequestID bool) {
	defer s.workers.Done()
	ctx := state.ctx
	if callerProvidedRequestID {
		lookup, err := s.lookupRequest(ctx, input.RequestID)
		if err != nil {
			s.finishRequest(input.RequestID, state, TalkOutput{}, err)
			return
		}
		if lookup.bound && lookup.requestSHA256 != state.requestSHA256 {
			s.finishRequest(input.RequestID, state, TalkOutput{}, ErrConflict)
			return
		}
		if err := ctx.Err(); err != nil {
			s.finishRequest(input.RequestID, state, TalkOutput{}, err)
			return
		}
		if lookup.bound {
			s.verifyRequestBinding(state)
		}
		if lookup.completed {
			if err := validateReply(lookup.output.Reply, s.maxOutputBytes); err != nil {
				s.finishRequest(input.RequestID, state, TalkOutput{}, replyFailure(err))
				return
			}
			s.finishRequest(input.RequestID, state, lookup.output, nil)
			return
		}
	}
	if err := ctx.Err(); err != nil {
		s.finishRequest(input.RequestID, state, TalkOutput{}, err)
		return
	}

	output, runErr := s.run(ctx, state, input)
	s.finishRequest(input.RequestID, state, output, runErr)
}

func (s *Service) waitForRequest(ctx context.Context, state *requestState, waiter bool) (TalkOutput, error) {
	defer s.releaseCaller(state, waiter)
	select {
	case <-ctx.Done():
		return TalkOutput{}, ctx.Err()
	case <-state.done:
		if err := ctx.Err(); err != nil {
			return TalkOutput{}, err
		}
		return state.output, state.err
	}
}

func (s *Service) run(ctx context.Context, state *requestState, input TalkInput) (TalkOutput, error) {
	if err := ctx.Err(); err != nil {
		return TalkOutput{}, err
	}
	exchangeID, err := newID()
	if err != nil {
		return TalkOutput{}, err
	}
	receivedEventID, err := newID()
	if err != nil {
		return TalkOutput{}, err
	}
	received, receivedReference, err := s.audit.AppendWithReference(audit.Event{
		EventID:        receivedEventID,
		ExchangeID:     exchangeID,
		RequestID:      input.RequestID,
		ConversationID: input.ConversationID,
		Type:           eventRequestReceived,
		Status:         "accepted",
		Text:           input.Text,
	})
	if err != nil {
		return TalkOutput{}, fmt.Errorf("record inbound message: %w", err)
	}
	s.recordDurableEntry(received, receivedReference)
	s.verifyRequestBinding(state)

	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	reply, respondErr := s.responder.Respond(callCtx, input.Text)
	callErr := callCtx.Err()
	cancel()
	if callErr != nil {
		respondErr = callErr
	}
	if respondErr == nil {
		respondErr = validateReply(reply, s.maxOutputBytes)
	}
	if respondErr != nil {
		failureEventID, idErr := newID()
		if idErr != nil {
			return TalkOutput{}, errors.Join(respondErr, idErr)
		}
		failed, failedReference, auditErr := s.audit.AppendWithReference(audit.Event{
			EventID:        failureEventID,
			ExchangeID:     exchangeID,
			RequestID:      input.RequestID,
			ConversationID: input.ConversationID,
			Type:           eventRunFailed,
			Status:         "failed",
			ErrorCode:      errorCode(respondErr),
		})
		if auditErr != nil {
			return TalkOutput{}, errors.Join(respondErr, fmt.Errorf("record responder failure: %w", auditErr))
		}
		s.recordDurableEntry(failed, failedReference)
		return TalkOutput{}, replyFailure(respondErr)
	}

	replyEventID, err := newID()
	if err != nil {
		return TalkOutput{}, err
	}
	committed, committedReference, err := s.audit.AppendWithReference(audit.Event{
		EventID:        replyEventID,
		ExchangeID:     exchangeID,
		RequestID:      input.RequestID,
		ConversationID: input.ConversationID,
		Type:           eventReplyCommitted,
		Status:         "succeeded",
		Text:           reply,
	})
	if err != nil {
		return TalkOutput{}, fmt.Errorf("record outbound message: %w", err)
	}
	s.recordDurableEntry(committed, committedReference)

	return TalkOutput{
		ExchangeID:     exchangeID,
		RequestID:      input.RequestID,
		ConversationID: input.ConversationID,
		Reply:          reply,
		CreatedAt:      received.Timestamp,
		RepliedAt:      committed.Timestamp,
		InputSHA256:    received.TextSHA256,
		OutputSHA256:   committed.TextSHA256,
		AuditSequence:  committed.Seq,
		AuditHead:      committed.EntryHash,
	}, nil
}

func (s *Service) claimRequest(requestID, requestHash string, requiresBindingLookup bool) (*requestState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil, false, ErrClosed
	}
	if existing, ok := s.requests[requestID]; ok {
		if existing.requestSHA256 != requestHash {
			if !existing.bindingVerified {
				return nil, false, ErrBusy
			}
			return nil, false, ErrConflict
		}
		if existing.callers == 0 || existing.waiters >= maxCoalescedWaitersPerRequest {
			return nil, false, ErrBusy
		}
		existing.callers++
		existing.waiters++
		return existing, false, nil
	}
	select {
	case s.semaphore <- struct{}{}:
	default:
		return nil, false, ErrBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &requestState{
		requestSHA256:   requestHash,
		done:            make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
		callers:         1,
		bindingVerified: !requiresBindingLookup,
	}
	s.workers.Add(1)
	s.requests[requestID] = state
	return state, true, nil
}

func (s *Service) verifyRequestBinding(state *requestState) {
	s.mu.Lock()
	state.bindingVerified = true
	s.mu.Unlock()
}

func (s *Service) releaseCaller(state *requestState, waiter bool) {
	s.mu.Lock()
	state.callers--
	if waiter {
		state.waiters--
	}
	if state.callers == 0 && !state.finished {
		state.cancel()
	}
	s.mu.Unlock()
}

func (s *Service) finishRequest(requestID string, state *requestState, output TalkOutput, err error) {
	s.mu.Lock()
	state.finished = true
	state.output = output
	state.err = err
	delete(s.requests, requestID)
	<-s.semaphore
	close(state.done)
	state.cancel()
	s.mu.Unlock()
}

// Shutdown rejects new calls, cancels every shared operation, and waits until
// all detached workers have finished their final audit write. Call it before
// closing the Audit handle supplied to New.
func (s *Service) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		for _, state := range s.requests {
			state.cancel()
		}
		s.mu.Unlock()

		go func() {
			s.workers.Wait()
			close(s.drained)
		}()
	})

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.drained:
		return nil
	}
}

type durableRequest struct {
	bound          bool
	requestSHA256  string
	completed      bool
	output         TalkOutput
	replyReference audit.EntryReference
	pending        durablePending
}

type durablePending struct {
	exchangeID  string
	createdAt   string
	inputSHA256 string
}

func buildDurableRequestIndex(log *audit.Log) (map[string]durableRequest, error) {
	index := make(map[string]durableRequest)
	if err := log.ScanWithReferences(func(entry audit.Entry, reference audit.EntryReference) error {
		applyDurableEntry(index, entry, reference)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("inspect relay history: %w", err)
	}
	return index, nil
}

func applyDurableEntry(index map[string]durableRequest, entry audit.Entry, reference audit.EntryReference) {
	result := index[entry.RequestID]
	switch entry.Type {
	case eventRequestReceived:
		requestHash := hashRequest(entry.ConversationID, entry.Text)
		if !result.bound {
			result.bound = true
			result.requestSHA256 = requestHash
		}
		if requestHash == result.requestSHA256 && !result.completed {
			result.pending = durablePending{
				exchangeID:  entry.ExchangeID,
				createdAt:   entry.Timestamp,
				inputSHA256: entry.TextSHA256,
			}
		}
	case eventReplyCommitted:
		if result.completed || result.pending.exchangeID == "" || result.pending.exchangeID != entry.ExchangeID {
			return
		}
		result.completed = true
		result.output = TalkOutput{
			ExchangeID:     entry.ExchangeID,
			RequestID:      entry.RequestID,
			ConversationID: entry.ConversationID,
			CreatedAt:      result.pending.createdAt,
			RepliedAt:      entry.Timestamp,
			InputSHA256:    result.pending.inputSHA256,
			OutputSHA256:   entry.TextSHA256,
			AuditSequence:  entry.Seq,
			AuditHead:      entry.EntryHash,
		}
		result.replyReference = reference
		result.pending = durablePending{}
	case eventRunFailed:
		if result.pending.exchangeID == entry.ExchangeID {
			result.pending = durablePending{}
		}
	}
	if result.bound {
		index[entry.RequestID] = result
	}
}

func (s *Service) recordDurableEntry(entry audit.Entry, reference audit.EntryReference) {
	s.mu.Lock()
	applyDurableEntry(s.durable, entry, reference)
	s.mu.Unlock()
}

func (s *Service) lookupRequest(ctx context.Context, requestID string) (durableRequest, error) {
	if err := ctx.Err(); err != nil {
		return durableRequest{}, err
	}
	s.mu.Lock()
	result := s.durable[requestID]
	s.mu.Unlock()
	if result.completed {
		entry, err := s.readAuditEntry(result.replyReference)
		if err != nil {
			return durableRequest{}, fmt.Errorf("read durable reply: %w", err)
		}
		if !durableReplyMatches(result, entry) {
			return durableRequest{}, errors.New("durable reply reference does not match the request index")
		}
		result.output.Reply = entry.Text
	}
	if err := ctx.Err(); err != nil {
		return durableRequest{}, err
	}
	return result, nil
}

func durableReplyMatches(result durableRequest, entry audit.Entry) bool {
	return entry.Type == eventReplyCommitted &&
		entry.Status == "succeeded" &&
		entry.ExchangeID == result.output.ExchangeID &&
		entry.RequestID == result.output.RequestID &&
		entry.ConversationID == result.output.ConversationID &&
		entry.Timestamp == result.output.RepliedAt &&
		entry.TextSHA256 == result.output.OutputSHA256 &&
		entry.Seq == result.output.AuditSequence &&
		entry.EntryHash == result.output.AuditHead
}

func validateReply(reply string, maxOutputBytes int) error {
	if !utf8.ValidString(reply) || strings.ContainsRune(reply, '\x00') || strings.TrimSpace(reply) == "" {
		return responder.ErrInvalidReply
	}
	if len(reply) > maxOutputBytes {
		return responder.ErrReplyTooLarge
	}
	return nil
}

// replyFailure keeps live and durable-replay validation failures in the same
// caller-facing error class while preserving the responder sentinel.
func replyFailure(err error) error {
	return fmt.Errorf("generate reply: %w", err)
}

func hashText(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

func hashRequest(conversationID, text string) string {
	// Length-prefix fields so concatenation cannot create ambiguous inputs.
	return hashText(fmt.Sprintf("%d:%s%d:%s", len(conversationID), conversationID, len(text), text))
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, responder.ErrReplyTooLarge):
		return "reply_too_large"
	case errors.Is(err, responder.ErrInvalidReply):
		return "invalid_reply"
	case errors.Is(err, responder.ErrMissingAPIKey):
		return "missing_api_key"
	default:
		return "provider_error"
	}
}
