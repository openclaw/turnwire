package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const (
	// This lifetime-wide fail-closed budget deliberately includes notifications
	// and inbound responses. It bounds every peer-controlled message admitted to
	// the SDK outside the separately capped call set, including control floods.
	maxInboundNonCallMessages = 16
	// Production settings currently require at most 36 batch elements: 20
	// calls plus the non-call budget above. Keep a separate hard ceiling so an
	// internal caller cannot turn an unexpectedly large concurrency value into
	// an unbounded batch-classification allocation.
	maxJSONRPCBatchMessages = 64
	serverBusyCode          = -32000
	serverBusyMessage       = "server busy"
)

var (
	errDuplicateInFlightRequest  = errors.New("duplicate in-flight MCP request ID")
	errNonCallBudgetExhausted    = errors.New("inbound MCP non-call message budget exhausted")
	errBatchCapacityExhausted    = errors.New("JSON-RPC batch exceeds MCP request capacity")
	errBatchContainsNotification = errors.New("JSON-RPC batches containing notifications are not supported")
	errInvalidBatchMessage       = errors.New("JSON-RPC batch contains an invalid message")
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

	mu          sync.Mutex
	stopped     bool
	maxInFlight int
	pending     map[jsonrpc.ID]struct{}
	responding  int
	nonCalls    int
	readBuffer  []byte
	closeErr    error
	reportError func(error)
}

func newRequestLimitedStream(reader *boundedFrameReadCloser, writer io.WriteCloser, maxInFlight int) *requestLimitedStream {
	return &requestLimitedStream{
		reader:      reader,
		writer:      writer,
		maxInFlight: maxInFlight,
		pending:     make(map[jsonrpc.ID]struct{}),
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
	ids, err := responseIDs(p, batchMessageLimit(s.maxInFlight))
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
	messages, _, batch, decoded, err := decodeJSONRPCFrame(frame, batchMessageLimit(s.maxInFlight))
	if err != nil {
		return nil, nil, err
	}
	if !decoded || len(messages) == 0 {
		// Let the native SDK return its canonical parse, empty-batch, or
		// protocol-version error. No unclassified call is dispatched because a
		// frame with any undecodable member terminates there.
		return frame, nil, nil
	}
	if batch {
		for _, message := range messages {
			request, isRequest := message.(*jsonrpc.Request)
			if isRequest && !request.IsCall() {
				// The legacy MCP batch implementation waits for one response per
				// element, but notifications intentionally produce no response.
				// Reject the complete frame before reserving call or non-call state.
				return nil, nil, errBatchContainsNotification
			}
		}
	}

	busy := make([]*jsonrpc.Response, 0)
	added := make(map[jsonrpc.ID]struct{})

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil, nil, io.ErrClosedPipe
	}
	nonCalls := s.nonCalls
	occupancy := len(s.pending) + s.responding
	for _, message := range messages {
		request, isRequest := message.(*jsonrpc.Request)
		if !isRequest || !request.IsCall() {
			if nonCalls >= maxInboundNonCallMessages {
				s.mu.Unlock()
				return nil, nil, errNonCallBudgetExhausted
			}
			nonCalls++
			continue
		}

		if _, duplicate := s.pending[request.ID]; duplicate {
			s.mu.Unlock()
			return nil, nil, errDuplicateInFlightRequest
		}
		if _, duplicate := added[request.ID]; duplicate {
			s.mu.Unlock()
			return nil, nil, errDuplicateInFlightRequest
		}
		if occupancy >= s.maxInFlight {
			busy = append(busy, busyResponse(request.ID))
			continue
		}
		added[request.ID] = struct{}{}
		occupancy++
	}
	if batch && len(busy) != 0 {
		s.mu.Unlock()
		return nil, nil, errBatchCapacityExhausted
	}
	for id := range added {
		s.pending[id] = struct{}{}
	}
	s.nonCalls = nonCalls
	s.mu.Unlock()

	if len(busy) == 0 {
		return frame, nil, nil
	}
	return nil, busy, nil
}

func batchMessageLimit(maxInFlight int) int {
	if maxInFlight <= 0 {
		return maxInboundNonCallMessages
	}
	if maxInFlight >= maxJSONRPCBatchMessages-maxInboundNonCallMessages {
		return maxJSONRPCBatchMessages
	}
	return maxInFlight + maxInboundNonCallMessages
}

func decodeJSONRPCFrame(frame []byte, maxBatchMessages int) ([]jsonrpc.Message, []json.RawMessage, bool, bool, error) {
	payload := frame
	if len(payload) > 0 && payload[len(payload)-1] == '\n' {
		payload = payload[:len(payload)-1]
		if len(payload) > 0 && payload[len(payload)-1] == '\r' {
			payload = payload[:len(payload)-1]
		}
	}

	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		rawBatch, ok, err := decodeBatchElements(trimmed, maxBatchMessages)
		if err != nil {
			return nil, nil, true, false, err
		}
		if !ok {
			return nil, nil, true, false, nil
		}
		messages := make([]jsonrpc.Message, 0, len(rawBatch))
		for i, raw := range rawBatch {
			message, err := jsonrpc.DecodeMessage(raw)
			if err != nil {
				// The whole array is valid JSON, so forwarding it to the SDK would
				// only decode the same attacker-controlled batch a second time.
				return nil, rawBatch, true, false, fmt.Errorf("%w at element %d", errInvalidBatchMessage, i+1)
			}
			messages = append(messages, message)
		}
		return messages, rawBatch, true, true, nil
	}

	message, err := jsonrpc.DecodeMessage(payload)
	if err != nil {
		return nil, nil, false, false, nil
	}
	return []jsonrpc.Message{message}, []json.RawMessage{append(json.RawMessage(nil), payload...)}, false, true, nil
}

// decodeBatchElements counts and captures only a bounded prefix. In
// particular, it never unmarshals a peer-controlled array into an unbounded
// []json.RawMessage before checking cardinality.
func decodeBatchElements(payload []byte, maxMessages int) ([]json.RawMessage, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil {
		return nil, false, nil
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return nil, false, nil
	}

	limit := maxMessages
	if limit < 0 {
		limit = 0
	}
	if limit > maxJSONRPCBatchMessages {
		limit = maxJSONRPCBatchMessages
	}
	rawBatch := make([]json.RawMessage, 0, limit)
	for decoder.More() {
		if len(rawBatch) >= limit {
			return nil, true, errBatchCapacityExhausted
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, false, nil
		}
		rawBatch = append(rawBatch, raw)
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, false, nil
	}
	delim, ok = token.(json.Delim)
	if !ok || delim != ']' {
		return nil, false, nil
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false, nil
	}
	return rawBatch, true, nil
}

func responseIDs(frame []byte, maxBatchMessages int) ([]jsonrpc.ID, error) {
	messages, _, _, decoded, err := decodeJSONRPCFrame(frame, maxBatchMessages)
	if err != nil {
		return nil, err
	}
	if !decoded {
		return nil, errors.New("invalid JSON-RPC output frame")
	}
	ids := make([]jsonrpc.ID, 0, len(messages))
	for _, message := range messages {
		if response, ok := message.(*jsonrpc.Response); ok && response != nil {
			ids = append(ids, response.ID)
		}
	}
	return ids, nil
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
