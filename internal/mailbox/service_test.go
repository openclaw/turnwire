package mailbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/responder"
)

type fakeResponder struct {
	mu    sync.Mutex
	calls int
	reply string
	err   error
	wait  <-chan struct{}
}

type cancelThenBlockResponder struct {
	started     chan struct{}
	canceled    chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
}

type lateReplyResponder struct {
	started     chan struct{}
	contextDone chan error
	err         error
}

func newLateReplyResponder() *lateReplyResponder {
	return &lateReplyResponder{
		started:     make(chan struct{}),
		contextDone: make(chan error, 1),
	}
}

func (r *lateReplyResponder) Respond(ctx context.Context, _ string) (string, error) {
	close(r.started)
	<-ctx.Done()
	r.contextDone <- ctx.Err()
	return "late valid reply", r.err
}

func newCancelThenBlockResponder() *cancelThenBlockResponder {
	return &cancelThenBlockResponder{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (r *cancelThenBlockResponder) Respond(ctx context.Context, _ string) (string, error) {
	r.startedOnce.Do(func() { close(r.started) })
	<-ctx.Done()
	close(r.canceled)
	<-r.release
	return "", ctx.Err()
}

func (r *cancelThenBlockResponder) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func (f *fakeResponder) Respond(ctx context.Context, _ string) (string, error) {
	f.mu.Lock()
	f.calls++
	reply, err, wait := f.reply, f.err, f.wait
	f.mu.Unlock()
	if wait != nil {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-wait:
		}
	}
	return reply, err
}

func (f *fakeResponder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func waitForActiveWaiters(t *testing.T, service *Service, requestID string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		service.mu.Lock()
		state := service.requests[requestID]
		got := -1
		if state != nil {
			got = state.waiters
		}
		service.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active waiters for %q = %d, want %d", requestID, got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForRequestCleanup(t *testing.T, service *Service, requestID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		service.mu.Lock()
		_, active := service.requests[requestID]
		service.mu.Unlock()
		if !active {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("request %q was not cleaned up", requestID)
		}
		time.Sleep(time.Millisecond)
	}
}

func newTestService(t *testing.T, model responder.Responder, timeout time.Duration) (*Service, *audit.Log) {
	t.Helper()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	service, err := New(Options{
		Audit:          log,
		Responder:      model,
		MaxInputBytes:  16 * 1024,
		MaxOutputBytes: 16 * 1024,
		Timeout:        timeout,
		MaxConcurrent:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown test service: %v", err)
		}
	})
	return service, log
}

func TestTalkRejectsPreCanceledContextWithoutSideEffects(t *testing.T) {
	model := &fakeResponder{reply: "must not run"}
	service, log := newTestService(t, model, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.Talk(ctx, TalkInput{
		Text: "do not send", RequestID: "pre-canceled", ConversationID: "conversation",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Talk error = %v, want context.Canceled", err)
	}
	if calls := model.callCount(); calls != 0 {
		t.Fatalf("model calls = %d, want 0", calls)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("pre-canceled call wrote audit entries: %#v", entries)
	}
	service.mu.Lock()
	active := len(service.requests)
	service.mu.Unlock()
	if active != 0 || len(service.semaphore) != 0 {
		t.Fatalf("pre-canceled call retained state: requests=%d semaphore=%d", active, len(service.semaphore))
	}
}

func TestCanceledSharedContextAfterLookupHasNoSideEffects(t *testing.T) {
	model := &fakeResponder{reply: "must not run"}
	service, log := newTestService(t, model, time.Second)
	input := TalkInput{Text: "do not send", RequestID: "lookup-canceled", ConversationID: "conversation"}
	state, owner, err := service.claimRequest(
		input.RequestID,
		hashRequest(input.ConversationID, input.Text),
		true,
	)
	if err != nil || !owner {
		t.Fatalf("claim request = (%v, %v), want owner", owner, err)
	}
	state.cancel()

	service.executeRequest(state, input, true)
	<-state.done
	if !errors.Is(state.err, context.Canceled) {
		t.Fatalf("request error = %v, want context.Canceled", state.err)
	}
	service.releaseCaller(state, false)
	if calls := model.callCount(); calls != 0 {
		t.Fatalf("model calls = %d, want 0", calls)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("post-lookup cancellation wrote audit entries: %#v", entries)
	}
}

func TestTalkLogsExactRequestAndReply(t *testing.T) {
	model := &fakeResponder{reply: "reply 🌍\nline two"}
	service, log := newTestService(t, model, time.Second)
	input := TalkInput{Text: "request\r\ncombining e\u0301", RequestID: "req-1", ConversationID: "conversation-1"}

	output, err := service.Talk(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if output.Reply != model.reply || output.RequestID != input.RequestID {
		t.Fatalf("output = %#v", output)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Text != input.Text || entries[1].Text != model.reply {
		t.Fatalf("entries = %#v", entries)
	}
	if output.AuditHead != entries[1].EntryHash || output.AuditSequence != entries[1].Seq {
		t.Fatalf("receipt does not match audit tail: %#v", output)
	}
}

func TestTalkIsIdempotentForSameRequest(t *testing.T) {
	model := &fakeResponder{reply: "same reply"}
	service, _ := newTestService(t, model, time.Second)
	input := TalkInput{Text: "hello", RequestID: "same-request", ConversationID: "conversation"}
	first, err := service.Talk(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Talk(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("cached output changed: %#v != %#v", first, second)
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls = %d, want 1", calls)
	}
	service.mu.Lock()
	activeRequests := len(service.requests)
	service.mu.Unlock()
	if activeRequests != 0 {
		t.Fatalf("completed request retained in memory: %d active", activeRequests)
	}

	conflict := input
	conflict.Text = "different"
	if _, err := service.Talk(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	conflict = input
	conflict.ConversationID = "different-conversation"
	if _, err := service.Talk(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conversation conflict error = %v", err)
	}
}

func TestDurableIndexUsesStartupScanAndSuccessfulAppends(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	historical := TalkInput{
		Text: "historical request", RequestID: "historical-index", ConversationID: "conversation",
	}
	received, err := log.Append(audit.Event{
		EventID: "historical-received", ExchangeID: "historical-exchange",
		RequestID: historical.RequestID, ConversationID: historical.ConversationID,
		Type: eventRequestReceived, Status: "accepted", Text: historical.Text,
	})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := log.Append(audit.Event{
		EventID: "historical-reply", ExchangeID: "historical-exchange",
		RequestID: historical.RequestID, ConversationID: historical.ConversationID,
		Type: eventReplyCommitted, Status: "succeeded", Text: "historical reply",
	})
	if err != nil {
		t.Fatal(err)
	}

	model := &fakeResponder{reply: "live reply"}
	service, err := New(Options{
		Audit: log, Responder: model,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })

	wantHistorical := TalkOutput{
		ExchangeID:     "historical-exchange",
		RequestID:      historical.RequestID,
		ConversationID: historical.ConversationID,
		Reply:          "historical reply",
		CreatedAt:      received.Timestamp,
		RepliedAt:      committed.Timestamp,
		InputSHA256:    received.TextSHA256,
		OutputSHA256:   committed.TextSHA256,
		AuditSequence:  committed.Seq,
		AuditHead:      committed.EntryHash,
	}
	indexedHistorical, err := service.lookupRequest(context.Background(), historical.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if !indexedHistorical.completed || indexedHistorical.output != wantHistorical {
		t.Fatalf("startup index = %#v, want %#v", indexedHistorical, wantHistorical)
	}
	service.mu.Lock()
	storedHistorical := service.durable[historical.RequestID]
	service.mu.Unlock()
	if storedHistorical.output.Reply != "" || storedHistorical.replyReference == (audit.EntryReference{}) {
		t.Fatalf("startup index retained reply body or omitted reference: %#v", storedHistorical)
	}

	live := TalkInput{Text: "live request", RequestID: "live-index", ConversationID: "conversation"}
	wantLive, err := service.Talk(context.Background(), live)
	if err != nil {
		t.Fatal(err)
	}
	indexedLive, err := service.lookupRequest(context.Background(), live.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if !indexedLive.completed || indexedLive.output != wantLive {
		t.Fatalf("live index = %#v, want %#v", indexedLive, wantLive)
	}
	service.mu.Lock()
	storedLive := service.durable[live.RequestID]
	service.mu.Unlock()
	if storedLive.output.Reply != "" || storedLive.replyReference == (audit.EntryReference{}) {
		t.Fatalf("live index retained reply body or omitted reference: %#v", storedLive)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	// A compact hit must still read through the audit handle. Cached metadata
	// must never let a completed Talk bypass a closed log.
	for _, replay := range []TalkInput{historical, live} {
		output, err := service.Talk(context.Background(), replay)
		if !errors.Is(err, audit.ErrClosed) {
			t.Fatalf("Talk(%q) after audit close error = %v, want ErrClosed", replay.RequestID, err)
		}
		if output != (TalkOutput{}) {
			t.Fatalf("Talk(%q) after audit close output = %#v", replay.RequestID, output)
		}
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls after closed replay = %d, want 1", calls)
	}
}

func TestCompletedTalkRejectsInjectedPoisonedAuditRead(t *testing.T) {
	model := &fakeResponder{reply: "durable reply"}
	service, _ := newTestService(t, model, time.Second)
	input := TalkInput{Text: "request", RequestID: "poisoned-replay", ConversationID: "conversation"}
	if _, err := service.Talk(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	service.readAuditEntry = func(audit.EntryReference) (audit.Entry, error) {
		return audit.Entry{}, fmt.Errorf("%w: injected sync failure", audit.ErrUncertainDurability)
	}

	output, err := service.Talk(context.Background(), input)
	if !errors.Is(err, audit.ErrUncertainDurability) {
		t.Fatalf("Talk after poisoned audit read error = %v, want ErrUncertainDurability", err)
	}
	if output != (TalkOutput{}) {
		t.Fatalf("Talk after poisoned audit read output = %#v", output)
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls after poisoned replay = %d, want 1", calls)
	}
}

func TestCompletedTalkSurvivesCleanQuotaRejection(t *testing.T) {
	log, err := audit.OpenWithQuota(filepath.Join(t.TempDir(), "audit"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	model := &fakeResponder{reply: "durable reply"}
	service, err := New(Options{
		Audit: log, Responder: model,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })
	input := TalkInput{Text: "request", RequestID: "quota-replay", ConversationID: "conversation"}
	want, err := service.Talk(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(audit.Event{
		EventID: "oversized", ExchangeID: "oversized", RequestID: "oversized",
		ConversationID: "conversation", Type: eventRequestReceived, Status: "accepted",
		Text: string(bytes.Repeat([]byte("x"), 4096)),
	}); !errors.Is(err, audit.ErrQuotaExceeded) {
		t.Fatalf("oversized Append error = %v, want ErrQuotaExceeded", err)
	}

	got, err := service.Talk(context.Background(), input)
	if err != nil {
		t.Fatalf("Talk after clean quota rejection: %v", err)
	}
	if got != want {
		t.Fatalf("replayed output = %#v, want %#v", got, want)
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls after quota replay = %d, want 1", calls)
	}
}

func TestDurableIndexIgnoresFailedAppend(t *testing.T) {
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	model := &fakeResponder{reply: "must not run"}
	service, err := New(Options{
		Audit: log, Responder: model,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	input := TalkInput{Text: "not durable", RequestID: "failed-append", ConversationID: "conversation"}
	if _, err := service.Talk(context.Background(), input); err == nil {
		t.Fatal("Talk succeeded with a closed audit log")
	}
	service.mu.Lock()
	_, indexed := service.durable[input.RequestID]
	service.mu.Unlock()
	if indexed {
		t.Fatal("failed append created a durable request index entry")
	}
	if calls := model.callCount(); calls != 0 {
		t.Fatalf("model calls = %d, want 0", calls)
	}
}

func TestDurableReplayEnforcesCurrentOutputLimitWithoutAuditMutation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	firstLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	firstModel := &fakeResponder{reply: "reply longer than the restarted limit"}
	firstService, err := New(Options{
		Audit: firstLog, Responder: firstModel,
		MaxInputBytes: 1024, MaxOutputBytes: 128,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = firstService.Shutdown(context.Background())
		_ = firstLog.Close()
	})
	input := TalkInput{
		Text: "durable request", RequestID: "durable-output-limit", ConversationID: "conversation",
	}
	firstOutput, err := firstService.Talk(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if firstOutput.Reply != firstModel.reply {
		t.Fatalf("initial reply = %q, want %q", firstOutput.Reply, firstModel.reply)
	}
	if err := firstService.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	auditPath := firstLog.Path()
	before, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstLog.Close(); err != nil {
		t.Fatal(err)
	}

	secondLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondLog.Close() })
	secondModel := &fakeResponder{reply: "must not run"}
	restarted, err := New(Options{
		Audit: secondLog, Responder: secondModel,
		MaxInputBytes: 1024, MaxOutputBytes: 8,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Shutdown(context.Background()) })

	output, err := restarted.Talk(context.Background(), input)
	if !errors.Is(err, responder.ErrReplyTooLarge) {
		t.Fatalf("durable retry error = %v, want ErrReplyTooLarge", err)
	}
	if output != (TalkOutput{}) {
		t.Fatalf("durable retry returned output: %#v", output)
	}
	if calls := secondModel.callCount(); calls != 0 {
		t.Fatalf("replay responder calls = %d, want 0", calls)
	}
	after, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("output-limit replay mutated the audit log")
	}
}

func TestTalkRejectsExcessUniqueRequestWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	model := &fakeResponder{reply: "done", wait: release}
	service, log := newTestService(t, model, time.Second)
	firstDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(context.Background(), TalkInput{
			Text: "first", RequestID: "busy-first", ConversationID: "conversation",
		})
		firstDone <- err
	}()
	for model.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	started := time.Now()
	_, err := service.Talk(context.Background(), TalkInput{
		Text: "second", RequestID: "busy-second", ConversationID: "conversation",
	})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("second request error = %v, want ErrBusy", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("busy rejection blocked for %s", elapsed)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].RequestID != "busy-first" {
		t.Fatalf("audit entries before release = %#v", entries)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestFailedRequestBindsIDAcrossRetryAndRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	firstLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	model := &fakeResponder{err: errors.New("provider unavailable")}
	service, err := New(Options{
		Audit: firstLog, Responder: model,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	original := TalkInput{Text: "original", RequestID: "failed-request", ConversationID: "conversation"}
	if _, err := service.Talk(context.Background(), original); err == nil {
		t.Fatal("failed request unexpectedly succeeded")
	}
	different := original
	different.Text = "different"
	if _, err := service.Talk(context.Background(), different); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-process conflict error = %v", err)
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls after conflict = %d, want 1", calls)
	}

	if err := firstLog.Close(); err != nil {
		t.Fatal(err)
	}

	secondLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondLog.Close() })
	secondModel := &fakeResponder{reply: "retry succeeded"}
	restarted, err := New(Options{
		Audit: secondLog, Responder: secondModel,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Talk(context.Background(), different); !errors.Is(err, ErrConflict) {
		t.Fatalf("post-restart conflict error = %v", err)
	}
	got, err := restarted.Talk(context.Background(), original)
	if err != nil {
		t.Fatalf("identical retry after restart failed: %v", err)
	}
	if got.Reply != "retry succeeded" {
		t.Fatalf("post-restart retry output = %#v", got)
	}
	if secondModel.callCount() != 1 {
		t.Fatalf("model was called %d times after restart, want 1", secondModel.callCount())
	}
}

func TestIncompleteRequestBindsIDAndCanRetry(t *testing.T) {
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	original := TalkInput{Text: "interrupted", RequestID: "incomplete-request", ConversationID: "conversation"}
	if _, err := log.Append(audit.Event{
		EventID:        "incomplete-event",
		ExchangeID:     "incomplete-exchange",
		RequestID:      original.RequestID,
		ConversationID: original.ConversationID,
		Type:           eventRequestReceived,
		Status:         "accepted",
		Text:           original.Text,
	}); err != nil {
		t.Fatal(err)
	}
	model := &fakeResponder{reply: "recovered"}
	service, err := New(Options{
		Audit: log, Responder: model,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	different := original
	different.Text = "different"
	if _, err := service.Talk(context.Background(), different); !errors.Is(err, ErrConflict) {
		t.Fatalf("incomplete-attempt conflict error = %v", err)
	}
	got, err := service.Talk(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reply != "recovered" || model.callCount() != 1 {
		t.Fatalf("retry output = %#v, model calls = %d", got, model.callCount())
	}
}

func TestDurableBindingMakesMismatchedProvisionalOwnerRetryable(t *testing.T) {
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	durable := TalkInput{Text: "durable A", RequestID: "durable-binding", ConversationID: "conversation"}
	received, err := log.Append(audit.Event{
		EventID: "durable-received", ExchangeID: "durable-exchange",
		RequestID: durable.RequestID, ConversationID: durable.ConversationID,
		Type: eventRequestReceived, Status: "accepted", Text: durable.Text,
	})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := log.Append(audit.Event{
		EventID: "durable-reply", ExchangeID: "durable-exchange",
		RequestID: durable.RequestID, ConversationID: durable.ConversationID,
		Type: eventReplyCommitted, Status: "succeeded", Text: "durable reply",
	})
	if err != nil {
		t.Fatal(err)
	}

	model := &fakeResponder{reply: "must not run"}
	service, err := New(Options{
		Audit: log, Responder: model,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Shutdown(context.Background()) })

	provisional := durable
	provisional.Text = "provisional B"
	state, owner, err := service.claimRequest(
		provisional.RequestID,
		hashRequest(provisional.ConversationID, provisional.Text),
		true,
	)
	if err != nil || !owner {
		t.Fatalf("claim provisional owner = (%v, %v), want owner", owner, err)
	}
	if _, err := service.Talk(context.Background(), durable); !errors.Is(err, ErrBusy) {
		t.Fatalf("durable A during provisional B error = %v, want ErrBusy", err)
	}

	service.executeRequest(state, provisional, true)
	<-state.done
	if !errors.Is(state.err, ErrConflict) {
		t.Fatalf("provisional B error = %v, want ErrConflict", state.err)
	}
	service.releaseCaller(state, false)

	got, err := service.Talk(context.Background(), durable)
	if err != nil {
		t.Fatal(err)
	}
	want := TalkOutput{
		ExchangeID:     "durable-exchange",
		RequestID:      durable.RequestID,
		ConversationID: durable.ConversationID,
		Reply:          "durable reply",
		CreatedAt:      received.Timestamp,
		RepliedAt:      committed.Timestamp,
		InputSHA256:    received.TextSHA256,
		OutputSHA256:   committed.TextSHA256,
		AuditSequence:  committed.Seq,
		AuditHead:      committed.EntryHash,
	}
	if got != want {
		t.Fatalf("durable retry output = %#v, want %#v", got, want)
	}
	if calls := model.callCount(); calls != 0 {
		t.Fatalf("model calls = %d, want 0", calls)
	}
}

func TestVerifiedActiveRequestRejectsMismatchedJoiner(t *testing.T) {
	release := make(chan struct{})
	model := &fakeResponder{reply: "done", wait: release}
	service, _ := newTestService(t, model, time.Second)
	input := TalkInput{Text: "verified", RequestID: "verified-active", ConversationID: "conversation"}
	ownerDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(context.Background(), input)
		ownerDone <- err
	}()
	for model.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	mismatched := input
	mismatched.Text = "different"
	if _, err := service.Talk(context.Background(), mismatched); !errors.Is(err, ErrConflict) {
		t.Fatalf("verified mismatch error = %v, want ErrConflict", err)
	}
	close(release)
	if err := <-ownerDone; err != nil {
		t.Fatal(err)
	}
}

func TestTalkCoalescesConcurrentDuplicates(t *testing.T) {
	release := make(chan struct{})
	model := &fakeResponder{reply: "done", wait: release}
	service, _ := newTestService(t, model, time.Second)
	input := TalkInput{Text: "hello", RequestID: "concurrent", ConversationID: "conversation"}

	results := make(chan TalkOutput, 2)
	errs := make(chan error, 2)
	go func() {
		result, err := service.Talk(context.Background(), input)
		results <- result
		errs <- err
	}()
	for model.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	go func() {
		result, err := service.Talk(context.Background(), input)
		results <- result
		errs <- err
	}()
	waitForActiveWaiters(t, service, input.RequestID, 1)
	close(release)
	first, second := <-results, <-results
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if first != second || model.callCount() != 1 {
		t.Fatalf("results differ or calls != 1: %#v %#v calls=%d", first, second, model.callCount())
	}
}

func TestOwnerCancellationDoesNotCancelCoalescedWaiter(t *testing.T) {
	release := make(chan struct{})
	model := &fakeResponder{reply: "done", wait: release}
	service, log := newTestService(t, model, time.Second)
	input := TalkInput{Text: "hello", RequestID: "owner-canceled", ConversationID: "conversation"}
	type result struct {
		output TalkOutput
		err    error
	}

	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	ownerDone := make(chan result, 1)
	go func() {
		output, err := service.Talk(ownerCtx, input)
		ownerDone <- result{output: output, err: err}
	}()
	for model.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	waiterDone := make(chan result, 1)
	go func() {
		output, err := service.Talk(context.Background(), input)
		waiterDone <- result{output: output, err: err}
	}()
	waitForActiveWaiters(t, service, input.RequestID, 1)

	cancelOwner()
	select {
	case got := <-ownerDone:
		if !errors.Is(got.err, context.Canceled) || got.output != (TalkOutput{}) {
			t.Fatalf("canceled owner result = %#v, want context.Canceled", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("canceled owner did not return promptly")
	}
	select {
	case got := <-waiterDone:
		t.Fatalf("waiter completed before provider release: %#v", got)
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	select {
	case got := <-waiterDone:
		if got.err != nil || got.output.Reply != "done" {
			t.Fatalf("waiter result = %#v", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiter did not receive shared result")
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls = %d, want 1", calls)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Type != eventRequestReceived || entries[1].Type != eventReplyCommitted {
		t.Fatalf("audit entries = %#v", entries)
	}
}

func TestTalkRejectsExcessConcurrentDuplicateWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	model := &fakeResponder{reply: "done", wait: release}
	service, _ := newTestService(t, model, time.Second)
	input := TalkInput{Text: "hello", RequestID: "bounded-duplicate", ConversationID: "conversation"}

	ownerDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(context.Background(), input)
		ownerDone <- err
	}()
	for model.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	waiterDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(context.Background(), input)
		waiterDone <- err
	}()
	waitForActiveWaiters(t, service, input.RequestID, 1)

	started := time.Now()
	_, err := service.Talk(context.Background(), input)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("excess duplicate error = %v, want ErrBusy", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("busy rejection blocked for %s", elapsed)
	}

	close(release)
	if err := <-ownerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-waiterDone; err != nil {
		t.Fatal(err)
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls = %d, want 1", calls)
	}
}

func TestWaiterCancellationDoesNotCancelOwnerAndReleasesSlot(t *testing.T) {
	release := make(chan struct{})
	model := &fakeResponder{reply: "done", wait: release}
	service, _ := newTestService(t, model, time.Second)
	input := TalkInput{Text: "hello", RequestID: "canceled-waiter", ConversationID: "conversation"}

	ownerDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(context.Background(), input)
		ownerDone <- err
	}()
	for model.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(waiterCtx, input)
		waiterDone <- err
	}()
	waitForActiveWaiters(t, service, input.RequestID, 1)
	cancelWaiter()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
	}
	waitForActiveWaiters(t, service, input.RequestID, 0)

	replacementDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(context.Background(), input)
		replacementDone <- err
	}()
	waitForActiveWaiters(t, service, input.RequestID, 1)
	close(release)
	if err := <-ownerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-replacementDone; err != nil {
		t.Fatal(err)
	}
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls = %d, want 1", calls)
	}
}

func TestAllCallerCancellationsStopSharedRequest(t *testing.T) {
	model := &fakeResponder{reply: "unreachable", wait: make(chan struct{})}
	service, log := newTestService(t, model, 5*time.Second)
	input := TalkInput{Text: "hello", RequestID: "all-canceled", ConversationID: "conversation"}

	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	ownerDone := make(chan error, 1)
	waiterDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(ownerCtx, input)
		ownerDone <- err
	}()
	for model.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	go func() {
		_, err := service.Talk(waiterCtx, input)
		waiterDone <- err
	}()
	waitForActiveWaiters(t, service, input.RequestID, 1)

	cancelOwner()
	cancelWaiter()
	deadline := time.After(500 * time.Millisecond)
	for name, done := range map[string]<-chan error{"owner": ownerDone, "waiter": waiterDone} {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s error = %v, want context.Canceled", name, err)
			}
		case <-deadline:
			t.Fatalf("%s did not return promptly", name)
		}
	}
	waitForRequestCleanup(t, service, input.RequestID)
	if calls := model.callCount(); calls != 1 {
		t.Fatalf("model calls = %d, want 1", calls)
	}
	if got := len(service.semaphore); got != 0 {
		t.Fatalf("semaphore retains %d slot(s)", got)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].Type != eventRunFailed || entries[1].ErrorCode != "canceled" {
		t.Fatalf("failure audit = %#v", entries)
	}
}

func TestShutdownDrainsDetachedWorkerBeforeAuditClose(t *testing.T) {
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	model := newCancelThenBlockResponder()
	service, err := New(Options{
		Audit: log, Responder: model,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: 5 * time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		model.unblock()
		_ = service.Shutdown(context.Background())
	})

	talkDone := make(chan error, 1)
	go func() {
		_, err := service.Talk(context.Background(), TalkInput{
			Text: "drain me", RequestID: "shutdown-drain", ConversationID: "conversation",
		})
		talkDone <- err
	}()
	select {
	case <-model.started:
	case <-time.After(time.Second):
		t.Fatal("model did not start")
	}

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- service.Shutdown(context.Background()) }()
	select {
	case <-model.canceled:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel shared work")
	}
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before worker finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	model.unblock()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not drain worker")
	}
	if err := <-talkDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Talk error = %v, want context.Canceled", err)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].Type != eventRunFailed || entries[1].ErrorCode != "canceled" {
		t.Fatalf("drained audit entries = %#v", entries)
	}
	if _, err := service.Talk(context.Background(), TalkInput{Text: "late"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Talk after Shutdown error = %v, want ErrClosed", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close audit after drain: %v", err)
	}
}

func TestTalkLogsBoundedFailure(t *testing.T) {
	model := &fakeResponder{wait: make(chan struct{})}
	service, log := newTestService(t, model, 5*time.Millisecond)
	_, err := service.Talk(context.Background(), TalkInput{Text: "hello", RequestID: "timeout", ConversationID: "conversation"})
	if err == nil {
		t.Fatal("expected timeout")
	}
	entries, readErr := log.ReadAll()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 || entries[1].Type != eventRunFailed || entries[1].ErrorCode != "timeout" || entries[1].Text != "" {
		t.Fatalf("failure audit = %#v", entries)
	}
}

func TestTalkRejectsValidReplyReturnedAfterDeadline(t *testing.T) {
	model := newLateReplyResponder()
	service, log := newTestService(t, model, 5*time.Millisecond)

	output, err := service.Talk(context.Background(), TalkInput{
		Text: "hello", RequestID: "late-timeout", ConversationID: "conversation",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Talk error = %v, want context.DeadlineExceeded", err)
	}
	if output != (TalkOutput{}) {
		t.Fatalf("Talk output = %#v, want no output", output)
	}
	if callErr := <-model.contextDone; !errors.Is(callErr, context.DeadlineExceeded) {
		t.Fatalf("responder context error = %v, want context.DeadlineExceeded", callErr)
	}
	assertRunFailureAudit(t, log, "timeout")
}

func TestTalkClassifiesLateResponderErrorAsTimeout(t *testing.T) {
	providerErr := errors.New("late provider error")
	model := newLateReplyResponder()
	model.err = providerErr
	service, log := newTestService(t, model, 5*time.Millisecond)

	output, err := service.Talk(context.Background(), TalkInput{
		Text: "hello", RequestID: "late-provider-timeout", ConversationID: "conversation",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Talk error = %v, want context.DeadlineExceeded", err)
	}
	if errors.Is(err, providerErr) {
		t.Fatalf("Talk error = %v, must not preserve a provider error returned after the deadline", err)
	}
	if output != (TalkOutput{}) {
		t.Fatalf("Talk output = %#v, want no output", output)
	}
	if callErr := <-model.contextDone; !errors.Is(callErr, context.DeadlineExceeded) {
		t.Fatalf("responder context error = %v, want context.DeadlineExceeded", callErr)
	}
	assertRunFailureAudit(t, log, "timeout")
}

func TestTalkRejectsValidReplyReturnedAfterCancellation(t *testing.T) {
	model := newLateReplyResponder()
	service, log := newTestService(t, model, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		output TalkOutput
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := service.Talk(ctx, TalkInput{
			Text: "hello", RequestID: "late-canceled", ConversationID: "conversation",
		})
		done <- result{output: output, err: err}
	}()

	select {
	case <-model.started:
	case <-time.After(time.Second):
		t.Fatal("responder did not start")
	}
	cancel()
	select {
	case callErr := <-model.contextDone:
		if !errors.Is(callErr, context.Canceled) {
			t.Fatalf("responder context error = %v, want context.Canceled", callErr)
		}
	case <-time.After(time.Second):
		t.Fatal("responder did not observe cancellation")
	}
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("Talk error = %v, want context.Canceled", got.err)
		}
		if got.output != (TalkOutput{}) {
			t.Fatalf("Talk output = %#v, want no output", got.output)
		}
	case <-time.After(time.Second):
		t.Fatal("Talk did not return after cancellation")
	}
	waitForRequestCleanup(t, service, "late-canceled")
	assertRunFailureAudit(t, log, "canceled")
}

func assertRunFailureAudit(t *testing.T, log *audit.Log, errorCode string) {
	t.Helper()
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 ||
		entries[0].Type != eventRequestReceived ||
		entries[1].Type != eventRunFailed ||
		entries[1].ErrorCode != errorCode ||
		entries[1].Text != "" {
		t.Fatalf("failure audit = %#v", entries)
	}
}

func TestCompletedRequestSurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	firstLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	firstModel := &fakeResponder{reply: "persisted reply"}
	first, err := New(Options{
		Audit: firstLog, Responder: firstModel,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := TalkInput{Text: "persist me", RequestID: "restart-request", ConversationID: "restart-conversation"}
	want, err := first.Talk(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstLog.Close(); err != nil {
		t.Fatal(err)
	}

	secondLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondLog.Close() })
	secondModel := &fakeResponder{reply: "must not be called"}
	second, err := New(Options{
		Audit: secondLog, Responder: secondModel,
		MaxInputBytes: 1024, MaxOutputBytes: 1024,
		Timeout: time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Talk(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("restored output = %#v, want %#v", got, want)
	}
	if secondModel.callCount() != 0 {
		t.Fatalf("model was called %d times after restart", secondModel.callCount())
	}
}
