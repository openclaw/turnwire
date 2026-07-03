package mcpserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const (
	// This lifetime-wide fail-closed budget deliberately includes notifications
	// and inbound responses. It bounds every peer-controlled message admitted to
	// the SDK outside the separately capped call set, including control floods.
	maxInboundNonCallMessages = 16
	serverBusyCode            = -32000
	serverBusyMessage         = "server busy"
)

var (
	errDuplicateInFlightRequest = errors.New("duplicate in-flight MCP request ID")
	errNonCallBudgetExhausted   = errors.New("inbound MCP non-call message budget exhausted")
	errRequestBudgetExhausted   = errors.New("inbound MCP request budget exhausted")
	errBatchUnsupported         = errors.New("JSON-RPC batches are not supported")
	errOutputTooLarge           = errors.New("MCP output frame exceeds byte limit")
)

// requestLimitedStream enforces admission below the MCP SDK's IOTransport.
// The SDK therefore retains its native connection and private session-update
// hooks, while only bounded, classified frames can reach its dispatch queue.
type requestLimitedStream struct {
	reader *boundedFrameReadCloser
	writer io.WriteCloser

	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once

	mu             sync.Mutex
	stopped        bool
	maxInFlight    int
	maxOutputBytes int
	requestBudget  *windowBudget
	pending        map[jsonrpc.ID]struct{}
	responding     int
	nonCalls       int
	readBuffer     []byte
	closeErr       error
	reportError    func(error)
}

func newRequestLimitedStream(reader *boundedFrameReadCloser, writer io.WriteCloser, maxInFlight, maxOutputBytes, maxRequestsPerMinute int) *requestLimitedStream {
	return &requestLimitedStream{
		reader:         reader,
		writer:         writer,
		maxInFlight:    maxInFlight,
		maxOutputBytes: maxOutputBytes,
		requestBudget:  newWindowBudget(maxRequestsPerMinute, time.Minute),
		pending:        make(map[jsonrpc.ID]struct{}),
	}
}

func (s *requestLimitedStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.isStopped() {
		s.readBuffer = nil
		return 0, io.EOF
	}

	for len(s.readBuffer) == 0 {
		if s.isStopped() {
			return 0, io.EOF
		}
		frame, err := s.reader.ReadFrame()
		if err != nil {
			s.failRead(err)
			return 0, err
		}
		filtered, busy, err := s.admitFrame(frame)
		if err != nil {
			s.recordError(err)
			return 0, err
		}
		if len(busy) != 0 {
			encoded, err := encodeBusyResponse(busy[0])
			if err != nil {
				s.recordError(err)
				return 0, err
			}
			if _, err := s.writeUntrackedFrame(encoded); err != nil {
				s.recordError(err)
				_ = s.Close()
				return 0, err
			}
		}
		if len(filtered) == 0 {
			continue
		}
		s.readBuffer = filtered
	}

	n := copy(p, s.readBuffer)
	s.readBuffer = s.readBuffer[n:]
	return n, nil
}

func (s *requestLimitedStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.isStopped() {
		return 0, io.ErrClosedPipe
	}
	if len(p) > s.maxOutputBytes {
		err := errOutputTooLarge
		s.recordError(err)
		_ = s.Close()
		return 0, err
	}
	ids, err := responseIDs(p)
	if err != nil {
		err = fmt.Errorf("classify MCP output: %w", err)
		s.recordError(err)
		_ = s.Close()
		return 0, err
	}
	s.writeMu.Lock()
	if s.isStopped() {
		s.writeMu.Unlock()
		return 0, io.ErrClosedPipe
	}
	responding := s.beginResponses(ids)
	n, err := s.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	s.finishResponses(responding)
	s.writeMu.Unlock()
	if err != nil {
		s.recordError(err)
		_ = s.Close()
	}
	return n, err
}

func (s *requestLimitedStream) Close() error {
	s.closeOnce.Do(func() {
		s.stop()
		s.closeErr = errors.Join(s.reader.Close(), s.writer.Close())
		if s.closeErr != nil {
			s.recordError(s.closeErr)
		}
	})
	return s.closeErr
}

func (s *requestLimitedStream) admitFrame(frame []byte) ([]byte, []*jsonrpc.Response, error) {
	// Charge every bounded JSON frame before JSON-RPC decoding. This includes
	// malformed call-shaped objects that the SDK would reject before dispatch.
	if !s.requestBudget.take(time.Now()) {
		return nil, nil, errRequestBudgetExhausted
	}
	message, decoded, err := decodeJSONRPCFrame(frame)
	if err != nil {
		return nil, nil, err
	}
	if !decoded {
		// Let the native SDK return its canonical parse or protocol-version
		// error. A JSON-RPC batch is rejected above before any SDK allocation.
		return frame, nil, nil
	}
	request, isRequest := message.(*jsonrpc.Request)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, nil, io.ErrClosedPipe
	}
	if !isRequest || !request.IsCall() {
		if s.nonCalls >= maxInboundNonCallMessages {
			return nil, nil, errNonCallBudgetExhausted
		}
		s.nonCalls++
		return frame, nil, nil
	}
	if _, duplicate := s.pending[request.ID]; duplicate {
		return nil, nil, errDuplicateInFlightRequest
	}
	if len(s.pending)+s.responding >= s.maxInFlight {
		return nil, []*jsonrpc.Response{busyResponse(request.ID)}, nil
	}
	s.pending[request.ID] = struct{}{}
	return frame, nil, nil
}

func decodeJSONRPCFrame(frame []byte) (jsonrpc.Message, bool, error) {
	payload := frame
	if len(payload) > 0 && payload[len(payload)-1] == '\n' {
		payload = payload[:len(payload)-1]
		if len(payload) > 0 && payload[len(payload)-1] == '\r' {
			payload = payload[:len(payload)-1]
		}
	}

	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, false, errBatchUnsupported
	}

	message, err := jsonrpc.DecodeMessage(payload)
	if err != nil {
		return nil, false, nil
	}
	return message, true, nil
}

func responseIDs(frame []byte) ([]jsonrpc.ID, error) {
	message, decoded, err := decodeJSONRPCFrame(frame)
	if err != nil {
		return nil, err
	}
	if !decoded {
		return nil, errors.New("invalid JSON-RPC output frame")
	}
	if response, ok := message.(*jsonrpc.Response); ok && response != nil {
		return []jsonrpc.ID{response.ID}, nil
	}
	return nil, nil
}

func busyResponse(id jsonrpc.ID) *jsonrpc.Response {
	return &jsonrpc.Response{
		ID: id,
		Error: &jsonrpc.Error{
			Code:    serverBusyCode,
			Message: serverBusyMessage,
		},
	}
}

func encodeBusyResponse(response *jsonrpc.Response) ([]byte, error) {
	encoded, err := jsonrpc.EncodeMessage(response)
	if err != nil {
		return nil, fmt.Errorf("encode busy response: %w", err)
	}
	return append(encoded, '\n'), nil
}

func (s *requestLimitedStream) beginResponses(ids []jsonrpc.ID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, id := range ids {
		if _, ok := s.pending[id]; !ok {
			continue
		}
		delete(s.pending, id)
		s.responding++
		count++
	}
	return count
}

func (s *requestLimitedStream) finishResponses(count int) {
	if count == 0 {
		return
	}
	s.mu.Lock()
	s.responding -= count
	if s.responding < 0 {
		s.responding = 0
	}
	s.mu.Unlock()
}

func (s *requestLimitedStream) writeUntrackedFrame(frame []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.isStopped() {
		return 0, io.ErrClosedPipe
	}
	n, err := s.writer.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (s *requestLimitedStream) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

func (s *requestLimitedStream) stop() {
	s.mu.Lock()
	s.stopped = true
	clear(s.pending)
	s.responding = 0
	s.mu.Unlock()
}

func (s *requestLimitedStream) failRead(err error) {
	if !errors.Is(err, io.EOF) {
		s.recordError(err)
	}
}

func (s *requestLimitedStream) recordError(err error) {
	if err != nil && s.reportError != nil {
		s.reportError(err)
	}
}
