package mailbox

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/budget"
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
	maxRequestsPerMinute       = 600
	maxGuardCallsPerHour       = 1000
)

type Options struct {
	Audit                *audit.Log
	Signer               *identity.Signer
	Peers                map[string]string
	Guard                guard.Evaluator
	Approvals            *approval.Store
	Policy               string
	PolicyVersion        string
	DeploymentSHA256     string
	MaxMessageBytes      int
	Timeout              time.Duration
	MaxMessageAge        time.Duration
	MaxConcurrent        int
	MaxRequestsPerMinute int
	MaxGuardCallsPerHour int
	Now                  func() time.Time
}

type Service struct {
	audit            *audit.Log
	signer           *identity.Signer
	peers            map[string]string
	guard            guard.Evaluator
	approvals        *approval.Store
	policy           string
	policyVersion    string
	deploymentSHA256 string
	maxMessageBytes  int
	timeout          time.Duration
	maxMessageAge    time.Duration
	semaphore        chan struct{}
	requestBudget    limiter
	guardBudget      limiter
	budgetClosers    []*budget.Counter
	now              func() time.Time
	lifecycleCtx     context.Context
	lifecycleCancel  context.CancelFunc

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

type limiter interface {
	Take(time.Time) (bool, error)
}

func takeBudget(counter limiter, now time.Time) error {
	allowed, err := counter.Take(now)
	if err != nil {
		return fmt.Errorf("%w: durable budget unavailable", ErrRateLimited)
	}
	if !allowed {
		return ErrRateLimited
	}
	return nil
}

func New(opts Options) (*Service, error) {
	if opts.Audit == nil || opts.Signer == nil || opts.Guard == nil || opts.Approvals == nil {
		return nil, errors.New("audit, identity, guard, and approval store are required")
	}
	if opts.MaxMessageBytes <= 0 || opts.MaxMessageBytes > MaxMessageBytes || opts.Timeout <= 0 || opts.MaxMessageAge <= 0 || opts.MaxConcurrent <= 0 ||
		opts.MaxRequestsPerMinute <= 0 || opts.MaxRequestsPerMinute > maxRequestsPerMinute ||
		opts.MaxGuardCallsPerHour <= 0 || opts.MaxGuardCallsPerHour > maxGuardCallsPerHour {
		return nil, errors.New("channel limits must be positive")
	}
	if strings.TrimSpace(opts.Policy) == "" || strings.TrimSpace(opts.PolicyVersion) == "" {
		return nil, errors.New("guard policy and version are required")
	}
	if len(opts.DeploymentSHA256) != 64 {
		return nil, errors.New("deployment SHA-256 is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	budgetDir := filepath.Dir(opts.Audit.Path())
	requestBudget, err := budget.Open(budgetDir, "service-requests", opts.MaxRequestsPerMinute, time.Minute)
	if err != nil {
		lifecycleCancel()
		return nil, fmt.Errorf("open request budget: %w", err)
	}
	guardBudget, err := budget.Open(budgetDir, "guard-calls", opts.MaxGuardCallsPerHour, time.Hour)
	if err != nil {
		_ = requestBudget.Close()
		lifecycleCancel()
		return nil, fmt.Errorf("open guard budget: %w", err)
	}
	service := &Service{
		audit: opts.Audit, signer: opts.Signer, peers: maps.Clone(opts.Peers), guard: opts.Guard,
		approvals: opts.Approvals, policy: opts.Policy, policyVersion: opts.PolicyVersion,
		deploymentSHA256: opts.DeploymentSHA256,
		maxMessageBytes:  opts.MaxMessageBytes, timeout: opts.Timeout, maxMessageAge: opts.MaxMessageAge,
		semaphore:     make(chan struct{}, opts.MaxConcurrent),
		requestBudget: requestBudget,
		guardBudget:   guardBudget,
		budgetClosers: []*budget.Counter{requestBudget, guardBudget},
		now:           now,
		active:        make(map[string]string), requests: make(map[string]requestRecord),
		sent: make(map[string]Envelope), received: make(map[string]receivedRecord), seenInbound: make(map[string]string),
		confirmed: make(map[string]ConfirmOutput),
		drained:   make(chan struct{}), lifecycleCtx: lifecycleCtx, lifecycleCancel: lifecycleCancel,
	}
	if err := service.rebuildIndex(); err != nil {
		_ = requestBudget.Close()
		_ = guardBudget.Close()
		lifecycleCancel()
		return nil, err
	}
	return service, nil
}

func (s *Service) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
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
		var closeErr error
		for _, counter := range s.budgetClosers {
			closeErr = errors.Join(closeErr, counter.Close())
		}
		return closeErr
	}
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

func (s *Service) appendEvent(exchangeID, requestID, conversationID, eventType, status, errorCode, text string, details map[string]string) (audit.Entry, error) {
	eventID, err := newID()
	if err != nil {
		return audit.Entry{}, err
	}
	return s.audit.Append(audit.Event{EventID: eventID, ExchangeID: exchangeID, RequestID: requestID, ConversationID: conversationID, Type: eventType, Status: status, ErrorCode: errorCode, Text: text, Details: details})
}
