package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/mailbox"
)

type stubTalker struct {
	input  mailbox.TalkInput
	output mailbox.TalkOutput
	err    error
}

func TestRunEOFPreservesIndependentWriteFailure(t *testing.T) {
	stdoutFailure := errors.New("stdout failed sentinel")
	for _, test := range []struct {
		name     string
		writeErr error
	}{
		{name: "clean EOF"},
		{name: "EOF with stdout failure", writeErr: stdoutFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			talker := newEOFProbeTalker()
			writer := &shutdownGatedWriter{
				started:  make(chan struct{}),
				shutdown: talker.shutdownStarted,
				err:      test.writeErr,
			}
			reader := &eofAfterWriteReader{
				data:         []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}` + "\n"),
				writeStarted: writer.started,
			}

			err := Run(context.Background(), talker, "test", reader, writer, 1024, 1)
			if test.writeErr == nil {
				if err != nil {
					t.Fatalf("clean EOF error = %v, want nil", err)
				}
			} else if !errors.Is(err, test.writeErr) {
				t.Fatalf("EOF plus stdout failure error = %v, want %v", err, test.writeErr)
			}
			select {
			case <-talker.shutdownStarted:
			default:
				t.Fatal("EOF did not initiate lifecycle shutdown")
			}
		})
	}
}

func TestResolveRunErrorNormalizesOnlySDKCloseAfterEOF(t *testing.T) {
	sdkClosing := fmt.Errorf("SDK closing after EOF: %w", &jsonrpc.Error{
		Code:    sdkServerClosingCode,
		Message: "server is closing",
	})
	transportFailure := errors.New("independent transport failure")
	unexpectedFailure := errors.New("unexpected SDK failure")

	if err := resolveRunError(sdkClosing, nil, io.EOF, nil); err != nil {
		t.Fatalf("SDK close after EOF resolved to %v, want nil", err)
	}
	if err := resolveRunError(sdkClosing, nil, io.EOF, transportFailure); !errors.Is(err, transportFailure) {
		t.Fatalf("tracked transport failure was masked: %v", err)
	}
	if err := resolveRunError(unexpectedFailure, nil, io.EOF, nil); !errors.Is(err, unexpectedFailure) {
		t.Fatalf("unexpected failure after EOF was masked: %v", err)
	}
}

func TestRunPreservesNativeIOTransportBatchPolicy(t *testing.T) {
	for _, test := range []struct {
		name      string
		version   string
		wantCalls int32
		wantError string
	}{
		{
			name:      "new protocol rejects batches",
			version:   "2025-06-18",
			wantError: "JSON-RPC batching is not supported in 2025-06-18 and later",
		},
		{
			name:      "old protocol accepts batches",
			version:   "2024-11-05",
			wantCalls: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stdin, input := io.Pipe()
			output, stdout := io.Pipe()
			defer stdin.Close()
			defer input.Close()
			defer output.Close()
			defer stdout.Close()

			talker := &countingTalker{}
			runDone := make(chan error, 1)
			go func() {
				runDone <- Run(ctx, talker, "test", stdin, stdout, 4096, 1)
			}()

			initialize := fmt.Sprintf(
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":%q,"capabilities":{},"clientInfo":{"name":"batch-policy-test","version":"1"}}}`+"\n",
				test.version,
			)
			writePipeString(t, input, initialize)
			reader := bufio.NewReader(output)
			initializeResponse := readPipeLine(t, reader)
			if !strings.Contains(initializeResponse, `"id":1`) {
				t.Fatalf("initialize response = %q", initializeResponse)
			}

			writePipeString(t, input, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n")
			batch := `[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"talk","arguments":{"text":"first"}}},{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"talk","arguments":{"text":"second"}}}]` + "\n"
			writePipeString(t, input, batch)

			if test.wantError == "" {
				batchResponse := readPipeLine(t, reader)
				if !strings.Contains(batchResponse, `"id":2`) || !strings.Contains(batchResponse, `"id":3`) {
					t.Fatalf("batch response = %q", batchResponse)
				}
				if err := input.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				go func() { _, _ = io.Copy(io.Discard, reader) }()
				if err := input.Close(); err != nil {
					t.Fatal(err)
				}
			}

			select {
			case err := <-runDone:
				if test.wantError == "" {
					if err != nil {
						t.Fatalf("Run error = %v, want nil", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("Run error = %v, want %q", err, test.wantError)
				}
			case <-ctx.Done():
				t.Fatalf("Run did not finish: %v", ctx.Err())
			}
			if got := talker.calls.Load(); got != test.wantCalls {
				t.Fatalf("Talk calls = %d, want %d", got, test.wantCalls)
			}
		})
	}
}

func TestRunRejectsLegacyBatchContainingNotificationWithoutHanging(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stdin, input := io.Pipe()
	output, stdout := io.Pipe()
	defer stdin.Close()
	defer input.Close()
	defer output.Close()
	defer stdout.Close()

	talker := &countingTalker{}
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, talker, "test", stdin, stdout, 4096, 1)
	}()

	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"legacy-mixed-batch-test","version":"1"}}}` + "\n"
	writePipeString(t, input, initialize)
	reader := bufio.NewReader(output)
	if response := readPipeLine(t, reader); !strings.Contains(response, `"id":1`) {
		t.Fatalf("initialize response = %q", response)
	}
	writePipeString(t, input, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n")
	batch := `[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"talk","arguments":{"text":"must not run"}}},{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}]` + "\n"
	writePipeString(t, input, batch)

	select {
	case err := <-runDone:
		if !errors.Is(err, errBatchContainsNotification) {
			t.Fatalf("Run error = %v, want %v", err, errBatchContainsNotification)
		}
	case <-ctx.Done():
		t.Fatalf("Run hung on legacy mixed batch: %v", ctx.Err())
	}
	if got := talker.calls.Load(); got != 0 {
		t.Fatalf("Talk calls = %d, want 0", got)
	}
}

func writePipeString(t *testing.T, writer *io.PipeWriter, value string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, value)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write pipe: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pipe write timed out")
	}
}

func readPipeLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := reader.ReadString('\n')
		done <- result{line: line, err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("read pipe: %v", result.err)
		}
		return result.line
	case <-time.After(time.Second):
		t.Fatal("pipe read timed out")
		return ""
	}
}

func (s *stubTalker) Talk(_ context.Context, input mailbox.TalkInput) (mailbox.TalkOutput, error) {
	s.input = input
	return s.output, s.err
}

func TestTalkToolOverInMemoryTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	input := mailbox.TalkInput{
		Text:           "hello from work",
		RequestID:      "request-1",
		ConversationID: "conversation-1",
	}
	wantOutput := mailbox.TalkOutput{
		ExchangeID:     "exchange-1",
		RequestID:      input.RequestID,
		ConversationID: input.ConversationID,
		Reply:          "hello from home",
		CreatedAt:      "2026-06-30T12:00:00Z",
		RepliedAt:      "2026-06-30T12:00:01Z",
		InputSHA256:    "input-hash",
		OutputSHA256:   "output-hash",
		AuditSequence:  2,
		AuditHead:      "audit-head",
	}
	talker := &stubTalker{output: wantOutput}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := New(talker, "test").Connect(ctx, serverTransport, nil)
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

	initResult := clientSession.InitializeResult()
	if initResult == nil {
		t.Fatal("InitializeResult is nil")
	}
	wantCapabilities := &mcp.ServerCapabilities{
		Tools: &mcp.ToolCapabilities{ListChanged: true},
	}
	if !reflect.DeepEqual(initResult.Capabilities, wantCapabilities) {
		t.Fatalf("initialize capabilities = %#v, want tools only %#v", initResult.Capabilities, wantCapabilities)
	}

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "talk" {
		t.Fatalf("unexpected tools: %#v", tools.Tools)
	}
	annotations := tools.Tools[0].Annotations
	if annotations == nil {
		t.Fatal("talk tool has no annotations")
	}
	if annotations.ReadOnlyHint || annotations.IdempotentHint {
		t.Fatalf("logging tool must not be read-only or idempotent: %#v", annotations)
	}
	if annotations.DestructiveHint == nil || *annotations.DestructiveHint {
		t.Fatalf("talk should be explicitly non-destructive: %#v", annotations)
	}
	if annotations.OpenWorldHint == nil || !*annotations.OpenWorldHint {
		t.Fatalf("talk should disclose its open-world interaction: %#v", annotations)
	}

	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "talk",
		Arguments: input,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("talk returned a tool error: %#v", result)
	}
	if !reflect.DeepEqual(talker.input, input) {
		t.Fatalf("talk input mismatch: got %#v, want %#v", talker.input, input)
	}
	if len(result.Content) != 1 {
		t.Fatalf("unexpected content: %#v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != wantOutput.Reply {
		t.Fatalf("unexpected text content: %#v", result.Content[0])
	}

	structuredJSON, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var gotOutput mailbox.TalkOutput
	if err := json.Unmarshal(structuredJSON, &gotOutput); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotOutput, wantOutput) {
		t.Fatalf("structured output mismatch: got %#v, want %#v", gotOutput, wantOutput)
	}
}

func TestTransportHeadroomAllowsCoalescedRetryAndControlCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log, err := audit.Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	model := newBlockingResponder()
	service, err := mailbox.New(mailbox.Options{
		Audit:          log,
		Responder:      model,
		MaxInputBytes:  16 * 1024,
		MaxOutputBytes: 16 * 1024,
		Timeout:        4 * time.Second,
		MaxConcurrent:  1,
	})
	if err != nil {
		t.Fatal(err)
	}

	serverInput, clientOutput := io.Pipe()
	clientInput, serverOutput := io.Pipe()
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, service, "test", serverInput, serverOutput, 16*1024, 1)
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, &mcp.IOTransport{
		Reader: clientInput,
		Writer: clientOutput,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		model.unblock()
		_ = clientSession.Close()
		_ = clientOutput.Close()
		_ = clientInput.Close()
		_ = serverInput.Close()
		_ = serverOutput.Close()
		cancel()
	})

	input := mailbox.TalkInput{
		Text:           "coalesce this",
		RequestID:      "same-request",
		ConversationID: "conversation",
	}
	results := make(chan toolCallResult, 2)
	call := func(input mailbox.TalkInput) {
		result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "talk", Arguments: input})
		results <- toolCallResult{result: result, err: err}
	}
	go call(input)
	select {
	case <-model.started:
	case <-ctx.Done():
		t.Fatal("first talk did not reach the model")
	}
	go call(input)

	if err := clientSession.Ping(ctx, nil); err != nil {
		t.Fatalf("ping while owner and retry are active: %v", err)
	}
	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "talk" {
		t.Fatalf("tool discovery while owner and retry are active = (%#v, %v)", tools, err)
	}
	unique := input
	unique.RequestID = "unique-request"
	busy, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "talk", Arguments: unique})
	if err != nil {
		t.Fatalf("unique talk transport error: %v", err)
	}
	if !busy.IsError || len(busy.Content) != 1 {
		t.Fatalf("unique talk result = %#v, want tool-level busy error", busy)
	}
	busyText, ok := busy.Content[0].(*mcp.TextContent)
	if !ok || busyText.Text != "busy: relay is at capacity; retry later" {
		t.Fatalf("unique talk busy content = %#v", busy.Content)
	}

	model.unblock()
	var outputs [2]mailbox.TalkOutput
	for i := range outputs {
		select {
		case callResult := <-results:
			if callResult.err != nil {
				t.Fatalf("coalesced talk %d transport error: %v", i, callResult.err)
			}
			if callResult.result == nil || callResult.result.IsError {
				t.Fatalf("coalesced talk %d result = %#v", i, callResult.result)
			}
			data, err := json.Marshal(callResult.result.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &outputs[i]); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("coalesced talks did not complete")
		}
	}
	if outputs[0] != outputs[1] || outputs[0].Reply != "coalesced reply" {
		t.Fatalf("coalesced outputs differ: %#v %#v", outputs[0], outputs[1])
	}
	if calls := model.calls.Load(); calls != 1 {
		t.Fatalf("model calls = %d, want 1", calls)
	}
	if err := clientSession.Close(); err != nil {
		t.Fatalf("close client session: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("Run did not finish after client close: %v", ctx.Err())
	}
}

func TestTalkToolDoesNotExposeUnderlyingError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const sentinel = "TOP-SECRET-synthetic-endpoint"
	talker := &stubTalker{err: errors.New("Post https://" + sentinel + "/v1: connection refused")}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := New(talker, "test").Connect(ctx, serverTransport, nil)
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

	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "talk",
		Arguments: mailbox.TalkInput{Text: "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("talk result IsError = false, want true: %#v", result)
	}
	if len(result.Content) != 1 {
		t.Fatalf("unexpected error content: %#v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content type = %T, want *mcp.TextContent", result.Content[0])
	}
	if strings.Contains(text.Text, sentinel) {
		t.Fatalf("MCP error exposed sentinel: %q", text.Text)
	}
	if text.Text != "turnwire_error: relay request failed" {
		t.Fatalf("MCP error = %q, want fixed safe message", text.Text)
	}
}

func TestPublicToolErrorReportsBusySafely(t *testing.T) {
	if got := publicToolError(mailbox.ErrBusy).Error(); got != "busy: relay is at capacity; retry later" {
		t.Fatalf("busy error = %q", got)
	}
	if got := publicToolError(mailbox.ErrClosed).Error(); got != "unavailable: relay is shutting down" {
		t.Fatalf("closed error = %q", got)
	}
	if got := publicToolError(fmt.Errorf("record inbound: %w", audit.ErrQuotaExceeded)).Error(); got != "unavailable: audit log quota reached" {
		t.Fatalf("quota error = %q", got)
	}
}

type blockingResponder struct {
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
	calls       atomic.Int32
}

func newBlockingResponder() *blockingResponder {
	return &blockingResponder{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *blockingResponder) Respond(ctx context.Context, _ string) (string, error) {
	r.calls.Add(1)
	r.startedOnce.Do(func() { close(r.started) })
	select {
	case <-r.release:
		return "coalesced reply", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (r *blockingResponder) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

type toolCallResult struct {
	result *mcp.CallToolResult
	err    error
}

type eofProbeTalker struct {
	shutdownStarted chan struct{}
	shutdownOnce    sync.Once
}

func newEOFProbeTalker() *eofProbeTalker {
	return &eofProbeTalker{shutdownStarted: make(chan struct{})}
}

func (*eofProbeTalker) Talk(context.Context, mailbox.TalkInput) (mailbox.TalkOutput, error) {
	return mailbox.TalkOutput{}, nil
}

func (t *eofProbeTalker) Shutdown(context.Context) error {
	t.shutdownOnce.Do(func() { close(t.shutdownStarted) })
	return nil
}

type eofAfterWriteReader struct {
	data         []byte
	writeStarted <-chan struct{}
}

func (r *eofAfterWriteReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	<-r.writeStarted
	return 0, io.EOF
}

type shutdownGatedWriter struct {
	started     chan struct{}
	shutdown    <-chan struct{}
	err         error
	startedOnce sync.Once
}

func (w *shutdownGatedWriter) Write(p []byte) (int, error) {
	w.startedOnce.Do(func() { close(w.started) })
	<-w.shutdown
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}
