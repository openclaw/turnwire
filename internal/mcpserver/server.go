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
	"github.com/openclaw/turnwire/internal/mailbox"
)

const transportControlHeadroom = 4

// sdkServerClosingCode is the go-sdk JSON-RPC extension used when a handler
// finishes after its peer has closed the read side. The SDK does not export
// its sentinel, but exposes its structured JSON-RPC error through jsonrpc.
const sdkServerClosingCode int64 = -32004

// Talker handles one logged text exchange with the paired language model.
type Talker interface {
	Talk(context.Context, mailbox.TalkInput) (mailbox.TalkOutput, error)
}

type shutdowner interface {
	Shutdown(context.Context) error
}

// New creates the text-only Turnwire MCP server.
func New(t Talker, version string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "turnwire",
		Title:   "Turnwire",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "Send text to the paired language model with talk. Both the request and reply are durably logged.",
		// Override the SDK's historical default logging capability. Turnwire
		// exposes only its explicitly registered tool over MCP.
		Capabilities: &mcp.ServerCapabilities{},
	})

	nonDestructive := false
	openWorld := true
	mcp.AddTool(server, &mcp.Tool{
		Name:        "talk",
		Title:       "Talk",
		Description: "Send text to the paired language model and return its reply. Both directions are durably logged.",
		Annotations: &mcp.ToolAnnotations{
			// Every call appends audit records, so it is neither read-only nor idempotent.
			ReadOnlyHint:    false,
			DestructiveHint: &nonDestructive,
			IdempotentHint:  false,
			OpenWorldHint:   &openWorld,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input mailbox.TalkInput) (*mcp.CallToolResult, mailbox.TalkOutput, error) {
		output, err := t.Talk(ctx, input)
		if err != nil {
			return nil, mailbox.TalkOutput{}, publicToolError(err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: output.Reply}},
		}, output, nil
	})

	return server
}

// publicToolError is the privacy boundary for failures returned over MCP.
// Underlying errors may contain provider URLs, environment-variable names,
// filesystem paths, or other responder-side details and must remain local.
func publicToolError(err error) error {
	switch {
	case errors.Is(err, mailbox.ErrInvalidInput):
		return errors.New("invalid_input: invalid turnwire input")
	case errors.Is(err, mailbox.ErrConflict):
		return errors.New("request_conflict: request ID conflicts with an existing message")
	case errors.Is(err, mailbox.ErrBusy):
		return errors.New("busy: relay is at capacity; retry later")
	case errors.Is(err, mailbox.ErrClosed):
		return errors.New("unavailable: relay is shutting down")
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
func Run(ctx context.Context, t Talker, version string, stdin io.Reader, stdout io.Writer, maxInputBytes, maxConcurrent int) error {
	if stdin == nil {
		return errors.New("MCP input is required")
	}
	if stdout == nil {
		return errors.New("MCP output is required")
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
	)
	stream.reportError = transportErrors.Record
	reader := newTeardownReadCloser(stream)
	runDone := make(chan struct{})
	var shutdownDone <-chan error
	if lifecycle, ok := t.(shutdowner); ok {
		done := make(chan error, 1)
		shutdownDone = done
		go func() {
			select {
			case <-ctx.Done():
			case <-reader.Terminated():
			case <-runDone:
			}
			done <- lifecycle.Shutdown(context.Background())
		}()
	}

	runErr := New(t, version).Run(ctx, &mcp.IOTransport{
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
