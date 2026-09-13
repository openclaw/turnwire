package mailbox

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/guard"
	"github.com/openclaw/turnwire/internal/identity"
)

func rotateFixture(t *testing.T, endpoint endpointFixture, recordTransition bool) endpointFixture {
	t.Helper()
	if err := endpoint.service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(endpoint.log.Path())
	plan, err := identity.PrepareRotation(dir, endpoint.signer.Name(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rotation := plan.Certificate()
	if recordTransition {
		_, err = endpoint.log.Append(audit.Event{
			EventID: "rotation:" + rotation.NewPublicKey, ExchangeID: "identity:" + rotation.Identity,
			RequestID: "identity-rotation", ConversationID: "deployment:test",
			Type: "identity_rotation_prepared", Status: "prepared",
			Details: map[string]string{
				"previous_public_key": rotation.PreviousPublicKey, "new_public_key": rotation.NewPublicKey,
				"created_at": rotation.CreatedAt, "previous_signature": rotation.PreviousSignature, "new_signature": rotation.NewSignature,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := plan.Commit(); err != nil {
		t.Fatal(err)
	}
	endpoint.signer, err = identity.LoadOrCreate(dir, rotation.Identity, false)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func TestAcceptedInboxSurvivesIdentityRotations(t *testing.T) {
	verdict := guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Synthetic note."}
	receiverGuard := &fakeGuard{verdict: verdict}
	work := newEndpoint(t, "work", map[string]string{}, &fakeGuard{verdict: verdict})
	personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, receiverGuard)
	work.service.peers["personal"] = personal.signer.PublicKey()
	sent, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "Meeting at 10:30.", RequestID: "rotate-receipt"})
	if err != nil {
		t.Fatal(err)
	}
	received, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
	if err != nil {
		t.Fatal(err)
	}
	original := *received.Acknowledgement
	for range 2 {
		personal = restartService(t, rotateFixture(t, personal, true))
		work.service.peers["personal"] = personal.signer.PublicKey()
		refreshed, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
		if err != nil {
			t.Fatal(err)
		}
		ack := refreshed.Acknowledgement
		if ack == nil {
			t.Fatal("missing refreshed receipt")
		}
		if err := verifyAcknowledgement(personal.signer.PublicKey(), *ack); err != nil {
			t.Fatalf("receipt is not signed by current key: %v", err)
		}
		if ack.ReceiverAuditSequence != original.ReceiverAuditSequence || ack.ReceiverAuditHead != original.ReceiverAuditHead || ack.ReceivedAt != original.ReceivedAt {
			t.Fatal("refreshed receipt changed original acceptance")
		}
		if _, err := work.service.Confirm(context.Background(), ConfirmInput{Acknowledgement: *ack}); err != nil {
			t.Fatal(err)
		}
		personal = restartService(t, personal)
		retried, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(retried, refreshed) {
			t.Fatal("refreshed receipt changed on restart")
		}
	}
	inbox, err := personal.service.Inbox(context.Background(), InboxInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 1 || receiverGuard.callCount() != 1 {
		t.Fatalf("inbox=%d guard calls=%d", len(inbox.Messages), receiverGuard.callCount())
	}
}

func TestReceiptRecoveryRejectsUnprovenIdentityReplacement(t *testing.T) {
	verdict := guard.Verdict{Decision: guard.DecisionAllow, ReasonCode: "allowed"}
	work := newEndpoint(t, "work", map[string]string{}, &fakeGuard{verdict: verdict})
	personal := newEndpoint(t, "personal", map[string]string{"work": work.signer.PublicKey()}, &fakeGuard{verdict: verdict})
	work.service.peers["personal"] = personal.signer.PublicKey()
	sent, err := work.service.Send(context.Background(), SendInput{Destination: "personal", Text: "Meeting.", RequestID: "unproven-key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := personal.service.Receive(context.Background(), ReceiveInput{Envelope: *sent.Envelope}); err != nil {
		t.Fatal(err)
	}
	personal = rotateFixture(t, personal, false)
	personal.service.signer = personal.signer
	if err := personal.service.rebuildIndex(); err == nil {
		t.Fatal("accepted a historical receipt without a signed key transition")
	}
}

func TestLocalSigningHistoryRejectsInvalidTransitionSignature(t *testing.T) {
	endpoint := newEndpoint(t, "personal", nil, &fakeGuard{})
	endpoint = rotateFixture(t, endpoint, true)
	entries, err := endpoint.log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	transition := entries[len(entries)-1]
	transition.Details["new_signature"] = "invalid"
	_, err = endpoint.log.Append(audit.Event{
		EventID: "invalid-transition", ExchangeID: transition.ExchangeID,
		RequestID: transition.RequestID, ConversationID: transition.ConversationID,
		Type: transition.Type, Status: transition.Status, Details: transition.Details,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint.service.signer = endpoint.signer
	if _, err := endpoint.service.localSigningKeys(); err == nil {
		t.Fatal("accepted an invalid countersignature")
	}
}
