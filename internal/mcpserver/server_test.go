package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openclaw/turnwire/internal/identity"
	"github.com/openclaw/turnwire/internal/mailbox"
)

type stubChannel struct {
	input  mailbox.SendInput
	output mailbox.SendOutput
}

func (s *stubChannel) Send(_ context.Context, input mailbox.SendInput) (mailbox.SendOutput, error) {
	s.input = input
	return s.output, nil
}
func (*stubChannel) Receive(context.Context, mailbox.ReceiveInput) (mailbox.ReceiveOutput, error) {
	return mailbox.ReceiveOutput{}, nil
}
func (*stubChannel) Confirm(context.Context, mailbox.ConfirmInput) (mailbox.ConfirmOutput, error) {
	return mailbox.ConfirmOutput{}, nil
}
func (*stubChannel) Inbox(context.Context, mailbox.InboxInput) (mailbox.InboxOutput, error) {
	return mailbox.InboxOutput{}, nil
}
func (*stubChannel) Checkpoint() (identity.Checkpoint, error) { return identity.Checkpoint{}, nil }

type stuckShutdownChannel struct {
	stubChannel
	release chan struct{}
}

func (s *stuckShutdownChannel) Shutdown(context.Context) error {
	<-s.release
	return nil
}

func TestRunBoundsStuckShutdown(t *testing.T) {
	channel := &stuckShutdownChannel{release: make(chan struct{})}
	defer close(channel.release)
	started := time.Now()
	err := run(context.Background(), channel, "test", bytes.NewReader(nil), io.Discard, filepath.Join(t.TempDir(), "state"), 1024, 1, 60, 25*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want shutdown deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Run took %v, want one bounded shutdown wait", elapsed)
	}
}

func TestSignedMailboxToolsOverInMemoryTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input := mailbox.SendInput{Destination: "personal", Text: "hello", RequestID: "request-1"}
	want := mailbox.SendOutput{Status: "review_required", MessageID: "message-1", RequestID: "request-1", BodySHA256: "hash", Decision: "review", ReasonCode: "ambiguous", AuditSequence: 3, AuditHead: "head"}
	channel := &stubChannel{output: want}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := New(channel, "test").Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"audit_checkpoint", "confirm_delivery", "list_messages", "receive_message", "send_message"}
	gotNames := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		gotNames = append(gotNames, tool.Name)
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("tools=%v", gotNames)
	}
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "send_message", Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("result=%#v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("result duplicated structured output into content: %#v", result.Content)
	}
	if !reflect.DeepEqual(channel.input, input) {
		t.Fatalf("input=%#v", channel.input)
	}
	structured, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var got mailbox.SendOutput
	if err := json.Unmarshal(structured, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestPublicToolErrorRedactsRateLimitDetails(t *testing.T) {
	err := publicToolError(mailbox.ErrRateLimited)
	if got, want := err.Error(), "rate_limited: relay request budget exhausted"; got != want {
		t.Fatalf("publicToolError = %q, want %q", got, want)
	}
}
