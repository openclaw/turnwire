package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/identity"
	"github.com/openclaw/turnwire/internal/mailbox"
)

const transportControlHeadroom = 4

// sdkServerClosingCode is the go-sdk JSON-RPC extension used when a handler
// finishes after its peer has closed the read side. The SDK does not export
// its sentinel, but exposes its structured JSON-RPC error through jsonrpc.
const sdkServerClosingCode int64 = -32004

// Channel exposes the complete signed mailbox protocol.
type Channel interface {
	Send(context.Context, mailbox.SendInput) (mailbox.SendOutput, error)
	Receive(context.Context, mailbox.ReceiveInput) (mailbox.ReceiveOutput, error)
	Confirm(context.Context, mailbox.ConfirmInput) (mailbox.ConfirmOutput, error)
	Inbox(context.Context, mailbox.InboxInput) (mailbox.InboxOutput, error)
	Checkpoint() (identity.Checkpoint, error)
}

type shutdowner interface {
	Shutdown(context.Context) error
}

// New creates the text-only Turnwire MCP server.
func New(channel Channel, version string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "turnwire",
		Title:   "Turnwire",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "Transfer only signed, policy-guarded text envelopes between configured Turnwire peers. Carry send_message envelopes to receive_message on the destination, then carry acknowledgements back to confirm_delivery.",
		// Override the SDK's historical default logging capability. Turnwire
		// exposes only its explicitly registered tool over MCP.
		Capabilities: &mcp.ServerCapabilities{},
	})

	nonDestructive := false
	openWorld := true
	mcp.AddTool(server, &mcp.Tool{
		Name:        "send_message",
		Title:       "Send message",
		Description: "Guard and sign text for one configured peer. Transfer only a returned released envelope; review_required needs local CLI approval.",
		Annotations: &mcp.ToolAnnotations{
			// Every call appends audit records, so it is neither read-only nor idempotent.
			ReadOnlyHint:    false,
			DestructiveHint: &nonDestructive,
			IdempotentHint:  false,
			OpenWorldHint:   &openWorld,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input mailbox.SendInput) (*mcp.CallToolResult, mailbox.SendOutput, error) {
		output, err := channel.Send(ctx, input)
		if err != nil {
			return nil, mailbox.SendOutput{}, publicToolError(err)
		}
		return structuredResult(), output, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "receive_message", Title: "Receive message",
		Description: "Verify a configured peer's signature, run the inbound guards, and commit the accepted message. Return a signed acknowledgement.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &nonDestructive, IdempotentHint: false, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input mailbox.ReceiveInput) (*mcp.CallToolResult, mailbox.ReceiveOutput, error) {
		output, err := channel.Receive(ctx, input)
		if err != nil {
			return nil, mailbox.ReceiveOutput{}, publicToolError(err)
		}
		return structuredResult(), output, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "confirm_delivery", Title: "Confirm delivery",
		Description: "Verify and record the destination peer's signed acknowledgement for a released message.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &nonDestructive, IdempotentHint: false, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input mailbox.ConfirmInput) (*mcp.CallToolResult, mailbox.ConfirmOutput, error) {
		output, err := channel.Confirm(ctx, input)
		if err != nil {
			return nil, mailbox.ConfirmOutput{}, publicToolError(err)
		}
		return structuredResult(), output, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "list_messages", Title: "List messages",
		Description: "Read guard-accepted messages from this endpoint's inbox. Every read is audited.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &nonDestructive, IdempotentHint: false, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input mailbox.InboxInput) (*mcp.CallToolResult, mailbox.InboxOutput, error) {
		output, err := channel.Inbox(ctx, input)
		if err != nil {
			return nil, mailbox.InboxOutput{}, publicToolError(err)
		}
		return structuredResult(), output, nil
	})

	type checkpointInput struct{}
	closedWorld := false
	mcp.AddTool(server, &mcp.Tool{
		Name: "audit_checkpoint", Title: "Audit checkpoint",
		Description: "Return a signed checkpoint of the current local audit-chain head for independent storage and reconciliation.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &nonDestructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ checkpointInput) (*mcp.CallToolResult, identity.Checkpoint, error) {
		output, err := channel.Checkpoint()
		if err != nil {
			return nil, identity.Checkpoint{}, publicToolError(err)
		}
		return structuredResult(), output, nil
	})

	return server
}

func structuredResult() *mcp.CallToolResult {
	// A non-nil empty content array prevents the SDK from duplicating the
	// structured payload into text content.
	return &mcp.CallToolResult{Content: []mcp.Content{}}
}

// publicToolError is the privacy boundary for failures returned over MCP.
// Underlying errors may contain provider URLs, environment-variable names,
// filesystem paths, or other guard-side details and must remain local.
func publicToolError(err error) error {
	switch {
	case errors.Is(err, mailbox.ErrInvalidInput):
		return errors.New("invalid_input: invalid turnwire input")
	case errors.Is(err, mailbox.ErrConflict):
		return errors.New("request_conflict: request ID conflicts with an existing message")
	case errors.Is(err, mailbox.ErrBusy):
		return errors.New("busy: relay is at capacity; retry later")
	case errors.Is(err, mailbox.ErrRateLimited):
		return errors.New("rate_limited: relay request budget exhausted")
	case errors.Is(err, mailbox.ErrClosed):
		return errors.New("unavailable: relay is shutting down")
	case errors.Is(err, mailbox.ErrUnauthorized):
		return errors.New("unauthorized: peer identity or signature is invalid")
	case errors.Is(err, audit.ErrQuotaExceeded):
		return errors.New("unavailable: audit log quota reached")
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("timeout: relay request timed out")
	case errors.Is(err, context.Canceled):
		return errors.New("canceled: relay request canceled")
	default:
		return errors.New("turnwire_error: relay request failed")
	}
}

// Run serves Turnwire over the provided stdin/stdout streams until the
// client disconnects or ctx is canceled. Incoming JSON frames are bounded and
// validated before the MCP SDK decodes them. If t also implements Shutdown,
// Run starts that shutdown as soon as transport teardown is observed and waits
// for both the MCP session and relay workers before returning.
func Run(ctx context.Context, channel Channel, version string, stdin io.Reader, stdout io.Writer, maxInputBytes, maxConcurrent, maxRequestsPerMinute int) error {
	if stdin == nil {
		return errors.New("MCP input is required")
	}
	if stdout == nil {
		return errors.New("MCP output is required")
	}
	if maxRequestsPerMinute <= 0 {
		return errors.New("MCP request budget must be positive")
	}
	limit, err := frameByteLimit(maxInputBytes)
	if err != nil {
		return fmt.Errorf("configure MCP input limit: %w", err)
	}
	callLimit, err := transportCallLimit(maxConcurrent)
	if err != nil {
		return err
	}

	transportErrors := &firstError{}
	stream := newRequestLimitedStream(
		newBoundedFrameReadCloser(stdin, limit),
		nopWriteCloser{Writer: stdout},
		callLimit,
		mailbox.MaxMCPOutputBytes,
		maxRequestsPerMinute,
	)
	stream.reportError = transportErrors.Record
	reader := newTeardownReadCloser(stream)
	runDone := make(chan struct{})
	var shutdownDone <-chan error
	if lifecycle, ok := channel.(shutdowner); ok {
		done := make(chan error, 1)
		shutdownDone = done
		go func() {
			select {
			case <-ctx.Done():
			case <-reader.Terminated():
			case <-runDone:
			}
			done <- lifecycle.Shutdown(context.WithoutCancel(ctx))
		}()
	}

	runErr := New(channel, version).Run(ctx, &mcp.IOTransport{
		Reader: reader,
		Writer: stream,
	})
	close(runDone)
	var shutdownErr error
	if shutdownDone != nil {
		shutdownErr = <-shutdownDone
	}
	return resolveRunError(runErr, shutdownErr, reader.TerminalError(), transportErrors.Err())
}

// resolveRunError normalizes only the SDK's structured server-closing error
// caused by peer EOF. Errors observed at the transport boundary always win,
// even if the SDK races them with its own close sentinel.
func resolveRunError(runErr, shutdownErr, readTerminalErr, transportErr error) error {
	if shutdownErr != nil {
		shutdownErr = fmt.Errorf("shutdown relay: %w", shutdownErr)
	}
	if transportErr != nil {
		if runErr == nil || errors.Is(runErr, transportErr) {
			return errors.Join(transportErr, shutdownErr)
		}
		return errors.Join(runErr, transportErr, shutdownErr)
	}
	if errors.Is(readTerminalErr, io.EOF) && isSDKServerClosing(runErr) {
		return shutdownErr
	}
	return errors.Join(runErr, shutdownErr)
}

func isSDKServerClosing(err error) bool {
	var rpcErr *jsonrpc.Error
	return errors.As(err, &rpcErr) && rpcErr.Code == sdkServerClosingCode
}

type firstError struct {
	mu  sync.Mutex
	err error
}

func (e *firstError) Record(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	if e.err == nil {
		e.err = err
	}
	e.mu.Unlock()
}

func (e *firstError) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// teardownReadCloser reports the first terminal read or close. The lifecycle
// watcher uses this signal to stop detached relay work while the MCP SDK is
// still waiting for active handlers to finish.
type teardownReadCloser struct {
	inner       io.ReadCloser
	terminated  chan struct{}
	once        sync.Once
	errMu       sync.Mutex
	terminalErr error
}

func newTeardownReadCloser(inner io.ReadCloser) *teardownReadCloser {
	return &teardownReadCloser{inner: inner, terminated: make(chan struct{})}
}

func (r *teardownReadCloser) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if err != nil {
		r.signal(err)
	}
	return n, err
}

func (r *teardownReadCloser) Close() error {
	r.signal(nil)
	return r.inner.Close()
}

func (r *teardownReadCloser) Terminated() <-chan struct{} {
	return r.terminated
}

func (r *teardownReadCloser) TerminalError() error {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.terminalErr
}

func (r *teardownReadCloser) signal(err error) {
	r.once.Do(func() {
		r.errMu.Lock()
		r.terminalErr = err
		r.errMu.Unlock()
		close(r.terminated)
	})
}

// transportCallLimit leaves bounded protocol headroom above model execution
// concurrency. Each active model call may have one coalesced retry, while the
// fixed allowance keeps ping, discovery, and immediate busy responses live.
func transportCallLimit(maxConcurrent int) (int, error) {
	if maxConcurrent <= 0 {
		return 0, errors.New("MCP concurrency limit must be positive")
	}
	if maxConcurrent > (math.MaxInt-transportControlHeadroom)/2 {
		return math.MaxInt, nil
	}
	return 2*maxConcurrent + transportControlHeadroom, nil
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
