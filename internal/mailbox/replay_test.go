package mailbox

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/guard"
)

func restartService(t *testing.T, endpoint endpointFixture) endpointFixture {
	t.Helper()
	old := endpoint.service
	if err := old.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{
		Audit: endpoint.log, Signer: endpoint.signer, Peers: old.peers, Guard: old.guard,
		Approvals: endpoint.approvals, Policy: old.policy, PolicyVersion: old.policyVersion,
		DeploymentSHA256: old.deploymentSHA256, MaxMessageBytes: old.maxMessageBytes,
		Timeout: old.timeout, MaxMessageAge: old.maxMessageAge, MaxConcurrent: cap(old.semaphore),
		MaxRequestsPerMinute: maxRequestsPerMinute, MaxGuardCallsPerHour: maxGuardCallsPerHour,
		Now: old.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	endpoint.service = service
	return endpoint
}

func approvePending(t *testing.T, endpoint endpointFixture, messageID string) {
	t.Helper()
	pending, err := endpoint.approvals.Pending(messageID)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.approvals.Approve(pending.Binding(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestRestartPreservesCompleteTransferResults(t *testing.T) {
	for _, test := range []struct{ name, text, decision, reason string }{
		{"allowed", "Meeting at 10:30.", guard.DecisionAllow, "allowed"},
		{"model review", "Review this scheduling note.", guard.DecisionReview, "ambiguous"},
		{"deterministic review", "Card 4111 1111 1111 1111", guard.DecisionAllow, "allowed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := guard.Verdict{Decision: test.decision, ReasonCode: test.reason, DataClasses: []string{"coordination"}, Explanation: "Synthetic fixture."}
			work := newEndpoint(t, "work", map[string]string{}, &fakeGuard{verdict: verdict})
			personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, &fakeGuard{verdict: verdict})
			work.service.peers["personal"] = personal.signer.PublicKey()
			input := SendInput{Destination: "personal", Text: test.text, RequestID: "restart-result"}
			sent, err := work.service.Send(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if sent.Status == "review_required" {
				approvePending(t, work, sent.MessageID)
				sent, err = work.service.Send(context.Background(), input)
				if err != nil {
					t.Fatal(err)
				}
			}
			if sent.Envelope == nil {
				t.Fatalf("send status = %s", sent.Status)
			}
			received, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
			if err != nil {
				t.Fatal(err)
			}
			if received.Status == "review_required" {
				approvePending(t, personal, sent.MessageID)
				received, err = personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
				if err != nil {
					t.Fatal(err)
				}
			}
			work = restartService(t, work)
			personal = restartService(t, personal)
			retriedSend, err := work.service.Send(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(retriedSend, sent) {
				t.Errorf("send result changed after restart: reason %q -> %q", sent.ReasonCode, retriedSend.ReasonCode)
			}
			retriedReceive, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(retriedReceive, received) {
				t.Errorf("receive result changed after restart: reason %q -> %q", received.ReasonCode, retriedReceive.ReasonCode)
			}
		})
	}
}

func TestLegacyReleaseRecoversDeterministicReviewReason(t *testing.T) {
	endpoint := newEndpoint(t, "work", map[string]string{"personal": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, &fakeGuard{})
	input := SendInput{Destination: "personal", Text: "Card 4111 1111 1111 1111", RequestID: "legacy-request", ConversationID: "legacy-conversation"}
	details := messageDetails("outbound", "work", "personal", "legacy-message")
	appendEvent := func(kind, text, code string, fields map[string]string) audit.Entry {
		t.Helper()
		entry, err := endpoint.service.appendEvent("legacy-message", input.RequestID, input.ConversationID, kind, "completed", code, text, fields)
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	submitted := appendEvent(eventMessageSubmitted, input.Text, "", details)
	for _, evaluation := range []struct{ kind, decision, reason string }{
		{eventDeterministicGuard, "review", "payment_card"},
		{eventModelGuard, "allow", "allowed"},
	} {
		fields := messageDetails("outbound", "work", "personal", "legacy-message")
		fields["decision"], fields["reason_code"] = evaluation.decision, evaluation.reason
		appendEvent(evaluation.kind, "", "", fields)
	}
	approved := appendEvent(eventApprovalConsumed, "", "payment_card", details)
	envelope := Envelope{Version: 1, MessageID: "legacy-message", RequestID: input.RequestID, ConversationID: input.ConversationID,
		Source: "work", Destination: "personal", CreatedAt: submitted.Timestamp, Body: input.Text, BodySHA256: hashText(input.Text),
		PolicyVersion: "test-v1", GuardModel: "gpt-5.4-2026-03-05", GuardDecision: "review_approved", SourceAuditSequence: approved.Seq, SourceAuditHead: approved.EntryHash}
	if err := signEnvelope(endpoint.signer, &envelope); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	appendEvent(eventOutboundReleased, string(encoded), "", details)
	endpoint = restartService(t, endpoint)
	result, err := endpoint.service.Send(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReasonCode != "payment_card" {
		t.Fatalf("legacy reason = %q, want payment_card", result.ReasonCode)
	}
}
