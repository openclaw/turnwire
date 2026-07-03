package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/guard"
	"github.com/openclaw/turnwire/internal/identity"
)

type fakeGuard struct {
	mu      sync.Mutex
	verdict guard.Verdict
	err     error
	calls   int
}

type blockingGuard struct {
	started chan struct{}
	once    sync.Once
}

func (g *blockingGuard) Evaluate(ctx context.Context, _ guard.Input) (guard.Evaluation, error) {
	g.once.Do(func() { close(g.started) })
	<-ctx.Done()
	return guard.Evaluation{}, ctx.Err()
}

func (f *fakeGuard) Evaluate(_ context.Context, _ guard.Input) (guard.Evaluation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return guard.Evaluation{}, f.err
	}
	return guard.Evaluation{Verdict: f.verdict, Model: "gpt-5.4-2026-03-05", ProviderRequestID: "req-test", ResponseID: "resp-test"}, nil
}

func (f *fakeGuard) callCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type endpointFixture struct {
	service   *Service
	log       *audit.Log
	approvals *approval.Store
	signer    *identity.Signer
}

func newEndpoint(t *testing.T, name string, peers map[string]string, evaluator guard.Evaluator) endpointFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	signer, err := identity.LoadOrCreate(dir, name, true)
	if err != nil {
		t.Fatal(err)
	}
	approvals, err := approval.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = approvals.Close() })
	service, err := New(Options{Audit: log, Signer: signer, Peers: peers, Guard: evaluator, Approvals: approvals, Policy: "allow routine coordination only", PolicyVersion: "test-v1", MaxMessageBytes: 4096, Timeout: time.Second, MaxMessageAge: 24 * time.Hour, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	return endpointFixture{service: service, log: log, approvals: approvals, signer: signer}
}

func TestSignedGuardedRoundTripAndAuditReceipts(t *testing.T) {
	workGuard := &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Allowed."}}
	personalGuard := &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Allowed."}}
	workSeed := newEndpoint(t, "work", map[string]string{}, workGuard)
	personal := newEndpoint(t, "personal", map[string]string{"work": workSeed.signer.PublicKey()}, personalGuard)
	workSeed.service.peers["personal"] = personal.signer.PublicKey()

	input := SendInput{Destination: "personal", Text: "Meeting moved to 10:30.", RequestID: "request-1", ConversationID: "conversation-1"}
	sent, err := workSeed.service.Send(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if sent.Status != "released" || sent.Envelope == nil || sent.Envelope.Signature == "" {
		t.Fatalf("sent = %#v", sent)
	}
	received, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
	if err != nil {
		t.Fatal(err)
	}
	if received.Status != "accepted" || received.Acknowledgement == nil {
		t.Fatalf("received = %#v", received)
	}
	inbox, err := personal.service.Inbox(context.Background(), InboxInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 1 || inbox.Messages[0].Body != input.Text {
		t.Fatalf("inbox = %#v", inbox)
	}
	confirmed, err := workSeed.service.Confirm(context.Background(), ConfirmInput{Acknowledgement: *received.Acknowledgement})
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.Status != "confirmed" || confirmed.MessageID != sent.MessageID {
		t.Fatalf("confirmed = %#v", confirmed)
	}
	if workGuard.callCount() != 1 || personalGuard.callCount() != 1 {
		t.Fatalf("guard calls = %d/%d", workGuard.callCount(), personalGuard.callCount())
	}
	personalEntries, err := personal.log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var acceptedEntry, issuedEntry audit.Entry
	for _, entry := range personalEntries {
		switch entry.Type {
		case eventInboundAccepted:
			acceptedEntry = entry
		case eventAcknowledgementIssued:
			issuedEntry = entry
		}
	}
	if acceptedEntry.Seq == 0 || issuedEntry.Seq != acceptedEntry.Seq+1 || received.Acknowledgement.ReceiverAuditSequence != acceptedEntry.Seq || received.Acknowledgement.ReceiverAuditHead != acceptedEntry.EntryHash {
		t.Fatalf("receipt does not attest to committed acceptance: accepted=%#v issued=%#v ack=%#v", acceptedEntry, issuedEntry, received.Acknowledgement)
	}

	entries, err := workSeed.log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	foundModelEvidence := false
	foundSignedReceipt := false
	wantAck, err := json.Marshal(received.Acknowledgement)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Type == eventModelGuard && entry.Details["model"] == "gpt-5.4-2026-03-05" && entry.Details["provider_request_id"] == "req-test" {
			foundModelEvidence = true
		}
		if entry.Type == eventDeliveryConfirmed && entry.Details["acknowledgement"] == string(wantAck) {
			foundSignedReceipt = true
		}
	}
	if !foundModelEvidence {
		t.Fatal("audit lacks model and provider request evidence")
	}
	if !foundSignedReceipt {
		t.Fatal("audit lacks the signed delivery receipt")
	}

	tampered := *sent.Envelope
	tampered.Body = "different"
	if _, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: tampered}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered receive error = %v", err)
	}
}

func TestDeterministicSecretBlockSkipsModel(t *testing.T) {
	evaluator := &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed"}}
	endpoint := newEndpoint(t, "work", map[string]string{"personal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, evaluator)
	output, err := endpoint.service.Send(context.Background(), SendInput{Destination: "personal", Text: "token sk-abcdefghijklmnopqrstuvwxyz123456", RequestID: "secret-1"})
	if err != nil {
		t.Fatal(err)
	}
	if output.Status != "denied" || output.Envelope != nil || evaluator.callCount() != 0 {
		t.Fatalf("output = %#v, calls=%d", output, evaluator.callCount())
	}
	entries, err := endpoint.log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Type == eventOutboundReleased {
			t.Fatal("blocked secret was released")
		}
	}
}

func TestReviewRequiresOutOfBandLocalApproval(t *testing.T) {
	evaluator := &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionReview, ReasonCode: "ambiguous", DataClasses: []string{"personal"}, Explanation: "Needs review."}}
	endpoint := newEndpoint(t, "work", map[string]string{"personal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, evaluator)
	input := SendInput{Destination: "personal", Text: "Please bring the private document.", RequestID: "review-1"}
	first, err := endpoint.service.Send(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "review_required" || first.Envelope != nil {
		t.Fatalf("first = %#v", first)
	}
	pending, err := endpoint.approvals.Pending(first.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Body != input.Text || pending.BodySHA256 != first.BodySHA256 {
		t.Fatalf("pending = %#v", pending)
	}
	if err := endpoint.approvals.Approve(pending.Binding(), time.Now()); err != nil {
		t.Fatal(err)
	}
	second, err := endpoint.service.Send(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "released" || second.Envelope == nil || second.Envelope.GuardDecision != "review_approved" {
		t.Fatalf("second = %#v", second)
	}
	if evaluator.callCount() != 2 {
		t.Fatalf("guard calls = %d, want 2", evaluator.callCount())
	}
}

func TestInboundReviewRetryReturnsPendingState(t *testing.T) {
	work := newEndpoint(t, "work", map[string]string{}, &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Allowed."}})
	personalGuard := &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionReview, ReasonCode: "ambiguous", DataClasses: []string{"personal"}, Explanation: "Review."}}
	personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, personalGuard)
	work.service.peers["personal"] = personal.signer.PublicKey()
	sent, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "Please review this note.", RequestID: "review-retry", ConversationID: "review-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		received, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
		if err != nil {
			t.Fatalf("receive attempt %d: %v", attempt+1, err)
		}
		if received.Status != "review_required" || received.Acknowledgement != nil {
			t.Fatalf("receive attempt %d = %#v", attempt+1, received)
		}
	}
}

func TestGuardFailureFailsClosedWithoutRelease(t *testing.T) {
	evaluator := &fakeGuard{err: errors.New("provider unavailable")}
	endpoint := newEndpoint(t, "work", map[string]string{"personal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, evaluator)
	if _, err := endpoint.service.Send(context.Background(), SendInput{Destination: "personal", Text: "routine note", RequestID: "failed-1"}); err == nil {
		t.Fatal("guard failure released a message")
	}
	entries, err := endpoint.log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	foundFailure := false
	for _, entry := range entries {
		if entry.Type == eventGuardFailed {
			foundFailure = true
		}
		if entry.Type == eventOutboundReleased {
			t.Fatal("guard failure produced release")
		}
	}
	if !foundFailure {
		t.Fatal("guard failure was not audited")
	}
}

func TestShutdownCancelsGuardAndDrainsBeforeReturn(t *testing.T) {
	evaluator := &blockingGuard{started: make(chan struct{})}
	endpoint := newEndpoint(t, "work", map[string]string{"personal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, evaluator)
	done := make(chan error, 1)
	go func() {
		_, err := endpoint.service.Send(context.Background(), SendInput{Destination: "personal", Text: "routine note", RequestID: "shutdown-1"})
		done <- err
	}()
	select {
	case <-evaluator.started:
	case <-time.After(time.Second):
		t.Fatal("guard did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := endpoint.service.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("send error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("send did not drain")
	}
	if _, err := endpoint.service.Send(context.Background(), SendInput{Destination: "personal", Text: "later"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-shutdown error=%v", err)
	}
}

func TestRestartIssuesAcknowledgementForCommittedAcceptance(t *testing.T) {
	workGuard := &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Allowed."}}
	personalGuard := &fakeGuard{verdict: guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Allowed."}}
	work := newEndpoint(t, "work", map[string]string{}, workGuard)
	personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, personalGuard)
	work.service.peers["personal"] = personal.signer.PublicKey()
	sent, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "Meeting at 10:30.", RequestID: "restart-request", ConversationID: "restart-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	envelopeHash := hashJSON(*sent.Envelope)
	details := messageDetails("inbound", "work", "personal", sent.MessageID)
	details["envelope_sha256"] = envelopeHash
	details["decision"] = guard.DecisionAllow
	accepted, err := personal.service.appendEvent(sent.MessageID, sent.Envelope.RequestID, sent.Envelope.ConversationID, eventInboundAccepted, "accepted", "", sent.Envelope.Body, details)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(personal.log.Path())
	if err := personal.approvals.Close(); err != nil {
		t.Fatal(err)
	}
	if err := personal.log.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedLog.Close() })
	reopenedApprovals, err := approval.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedApprovals.Close() })
	reopenedSigner, err := identity.LoadOrCreate(dir, "personal", false)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := New(Options{Audit: reopenedLog, Signer: reopenedSigner, Peers: map[string]string{"work": work.signer.PublicKey()}, Guard: personalGuard, Approvals: reopenedApprovals, Policy: "allow routine coordination only", PolicyVersion: "test-v1", MaxMessageBytes: 4096, Timeout: time.Second, MaxMessageAge: 24 * time.Hour, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	received, err := reopened.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
	if err != nil {
		t.Fatal(err)
	}
	if received.Acknowledgement == nil || received.Acknowledgement.ReceiverAuditSequence != accepted.Seq || received.Acknowledgement.ReceiverAuditHead != accepted.EntryHash {
		t.Fatalf("recovered acknowledgement = %#v, accepted = %#v", received.Acknowledgement, accepted)
	}
	if personalGuard.callCount() != 0 {
		t.Fatalf("committed acceptance was re-guarded %d times", personalGuard.callCount())
	}
}

func TestOperationClaimNamespacesDoNotCollideWithRequestIDs(t *testing.T) {
	verdict := guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Allowed."}
	work := newEndpoint(t, "work", map[string]string{}, &fakeGuard{verdict: verdict})
	personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, &fakeGuard{verdict: verdict})
	work.service.peers["personal"] = personal.signer.PublicKey()
	sent, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "First message.", RequestID: "source-request", ConversationID: "namespace-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := personal.service.Send(context.Background(), SendInput{Destination: "work", Text: "Unrelated send.", RequestID: "receive:" + sent.MessageID, ConversationID: "namespace-conversation"}); err != nil {
		t.Fatal(err)
	}
	received, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
	if err != nil {
		t.Fatalf("receive after request-ID collision: %v", err)
	}
	if _, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "Another unrelated send.", RequestID: "confirm:" + sent.MessageID, ConversationID: "namespace-conversation"}); err != nil {
		t.Fatal(err)
	}
	if _, err := work.service.Confirm(context.Background(), ConfirmInput{Acknowledgement: *received.Acknowledgement}); err != nil {
		t.Fatalf("confirm after request-ID collision: %v", err)
	}
}

func TestRepeatedConfirmationStillChecksReceiptBinding(t *testing.T) {
	verdict := guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Allowed."}
	work := newEndpoint(t, "work", map[string]string{}, &fakeGuard{verdict: verdict})
	personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, &fakeGuard{verdict: verdict})
	attacker := newEndpoint(t, "attacker", map[string]string{}, &fakeGuard{verdict: verdict})
	work.service.peers["personal"] = personal.signer.PublicKey()
	work.service.peers["attacker"] = attacker.signer.PublicKey()
	sent, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "Routine note.", RequestID: "confirm-binding", ConversationID: "confirm-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	received, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := work.service.Confirm(context.Background(), ConfirmInput{Acknowledgement: *received.Acknowledgement}); err != nil {
		t.Fatal(err)
	}
	wrong := Acknowledgement{Version: 1, MessageID: sent.MessageID, Source: "attacker", Destination: "work", EnvelopeSHA256: hashText("different envelope"), ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano), ReceiverAuditSequence: 1, ReceiverAuditHead: hashText("different audit head")}
	if err := signAcknowledgement(attacker.signer, &wrong); err != nil {
		t.Fatal(err)
	}
	if _, err := work.service.Confirm(context.Background(), ConfirmInput{Acknowledgement: wrong}); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched repeated confirmation error = %v, want ErrConflict", err)
	}
}

func TestLiveOpenAIEndToEndChannel(t *testing.T) {
	if os.Getenv("TURNWIRE_LIVE_OPENAI") != "1" || os.Getenv("OPENAI_API_KEY") == "" {
		t.Skip("set TURNWIRE_LIVE_OPENAI=1 with OPENAI_API_KEY")
	}
	newLiveGuard := func() guard.Evaluator {
		model, err := guard.NewHTTP(guard.HTTPConfig{Endpoint: "https://api.openai.com/v1/responses", Model: "gpt-5.4-2026-03-05", APIKeyEnv: "OPENAI_API_KEY", PromptCacheRetention: "in_memory"})
		if err != nil {
			t.Fatal(err)
		}
		return model
	}
	work := newEndpoint(t, "work", map[string]string{}, newLiveGuard())
	personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, newLiveGuard())
	work.service.timeout = 60 * time.Second
	personal.service.timeout = 60 * time.Second
	work.service.peers["personal"] = personal.signer.PublicKey()
	sent, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "Routine coordination: move tomorrow's meeting to 10:30.", RequestID: "live-request", ConversationID: "live-conversation"})
	if err != nil {
		t.Fatal(err)
	}
	if sent.Status != "released" || sent.Envelope == nil {
		t.Fatalf("sent=%#v", sent)
	}
	received, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
	if err != nil {
		t.Fatal(err)
	}
	if received.Status != "accepted" || received.Acknowledgement == nil {
		t.Fatalf("received=%#v", received)
	}
	confirmed, err := work.service.Confirm(context.Background(), ConfirmInput{Acknowledgement: *received.Acknowledgement})
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.Status != "confirmed" {
		t.Fatalf("confirmed=%#v", confirmed)
	}
}
