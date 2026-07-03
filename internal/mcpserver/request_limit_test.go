package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestTransportCallLimit(t *testing.T) {
	for _, test := range []struct {
		model int
		want  int
	}{
		{model: 1, want: 6},
		{model: 8, want: 20},
		{model: math.MaxInt, want: math.MaxInt},
	} {
		got, err := transportCallLimit(test.model)
		if err != nil || got != test.want {
			t.Fatalf("transportCallLimit(%d) = (%d, %v), want (%d, nil)", test.model, got, err, test.want)
		}
	}
	for _, model := range []int{0, -1} {
		if _, err := transportCallLimit(model); err == nil {
			t.Fatalf("transportCallLimit(%d) error = nil, want validation failure", model)
		}
	}
}

func TestDerivedTransportLimitBoundsOutstandingCalls(t *testing.T) {
	limit, err := transportCallLimit(1)
	if err != nil {
		t.Fatal(err)
	}
	var input strings.Builder
	for i := 0; i <= limit; i++ {
		input.WriteString(callFrame(t, float64(i+1), "tools/call"))
	}
	input.WriteString(notificationFrame(t, "notifications/cancelled"))
	output := &lockedWriteCloser{}
	stream := newStaticLimitedStream(input.String(), output, limit)
	t.Cleanup(func() { _ = stream.Close() })

	for i := 0; i < limit; i++ {
		message := mustReadOneMessage(t, stream)
		request, ok := message.(*jsonrpc.Request)
		if !ok || !request.IsCall() {
			t.Fatalf("admitted message %d = %#v, want call", i, message)
		}
	}
	message := mustReadOneMessage(t, stream)
	request, ok := message.(*jsonrpc.Request)
	if !ok || request.Method != "notifications/cancelled" {
		t.Fatalf("message after overload = %#v, want cancellation", message)
	}
	pending, responding := limiterCounts(stream)
	if pending != limit || responding != 0 {
		t.Fatalf("state = pending %d responding %d, want %d/0", pending, responding, limit)
	}
	assertBusyOutput(t, []byte(output.String()), mustID(t, float64(limit+1)))
}

func TestImmediateRequestIDReuseBeforeResponseWriteReturns(t *testing.T) {
	stdin, input := io.Pipe()
	output := newGatedWriteCloser()
	stream := newLimitedStream(stdin, output, 2)
	t.Cleanup(func() {
		_ = stream.Close()
		_ = input.Close()
	})
	id := mustID(t, "reused-id")
	writeAndReadOneMessage(t, input, stream, callFrame(t, id.Raw(), "tools/call"))

	const generations = 100
	for generation := 0; generation < generations; generation++ {
		writeDone := make(chan error, 1)
		go func() { writeDone <- writeResponse(stream, id) }()
		observation := receiveWrite(t, output.visible)
		assertResponseID(t, observation.frame, id)

		if generation+1 < generations {
			message := writeAndReadOneMessage(t, input, stream, callFrame(t, id.Raw(), "tools/call"))
			request, ok := message.(*jsonrpc.Request)
			if !ok || !reflect.DeepEqual(request.ID.Raw(), id.Raw()) {
				t.Fatalf("generation %d reuse = %#v", generation, message)
			}
			pending, responding := limiterCounts(stream)
			if pending != 1 || responding != 1 || pending+responding > stream.maxInFlight {
				t.Fatalf("generation %d state: pending=%d responding=%d", generation, pending, responding)
			}
		}

		close(observation.release)
		if err := <-writeDone; err != nil {
			t.Fatalf("generation %d Write: %v", generation, err)
		}
	}
	pending, responding := limiterCounts(stream)
	if pending != 0 || responding != 0 {
		t.Fatalf("final state: pending=%d responding=%d", pending, responding)
	}
}

func TestIDReuseWaitsForResponseToEnterOutputLane(t *testing.T) {
	stdin, input := io.Pipe()
	output := newGatedWriteCloser()
	stream := newLimitedStream(stdin, output, 2)
	t.Cleanup(func() {
		_ = stream.Close()
		_ = input.Close()
	})
	id := mustID(t, "bounded-reuse")
	writeAndReadOneMessage(t, input, stream, callFrame(t, id.Raw(), "tools/call"))

	writesDone := make(chan error, 2)
	go func() { writesDone <- writeResponse(stream, id) }()
	first := receiveWrite(t, output.visible)

	writeAndReadOneMessage(t, input, stream, callFrame(t, id.Raw(), "tools/call"))
	go func() { writesDone <- writeResponse(stream, id) }()
	waitForLimiterCounts(t, stream, 1, 1)

	inputDone := writePipeFrames(input, callFrame(t, id.Raw(), "tools/call"))
	if _, err := readOneMessage(stream); !errors.Is(err, errDuplicateInFlightRequest) {
		t.Fatalf("same ID while response waits for output lane = %v, want %v", err, errDuplicateInFlightRequest)
	}
	if err := <-inputDone; err != nil {
		t.Fatal(err)
	}
	// The queued response is still pending, so pending plus the response in the
	// output lane remains exactly at the configured cap.
	waitForLimiterCounts(t, stream, 1, 1)

	close(first.release)
	second := receiveWrite(t, output.visible)
	assertResponseID(t, second.frame, id)
	close(second.release)
	for i := 0; i < 2; i++ {
		if err := <-writesDone; err != nil {
			t.Fatalf("response Write %d: %v", i, err)
		}
	}
	pending, responding := limiterCounts(stream)
	if pending != 0 || responding != 0 {
		t.Fatalf("final state: pending=%d responding=%d", pending, responding)
	}
}

func TestRequestLimitedStreamReadsCancellationAtCallCap(t *testing.T) {
	first := mustID(t, float64(1))
	input := callFrame(t, first.Raw(), "tools/call") + notificationFrame(t, "notifications/cancelled")
	output := &lockedWriteCloser{}
	stream := newStaticLimitedStream(input, output, 1)
	t.Cleanup(func() { _ = stream.Close() })

	mustReadOneMessage(t, stream)
	message := mustReadOneMessage(t, stream)
	request, ok := message.(*jsonrpc.Request)
	if !ok || request.Method != "notifications/cancelled" {
		t.Fatalf("second message = %#v, want cancellation", message)
	}
	if err := writeResponse(stream, first); err != nil {
		t.Fatal(err)
	}
	pending, _ := limiterCounts(stream)
	if pending != 0 {
		t.Fatalf("pending calls = %d, want 0", pending)
	}
}

func TestRequestLimitedStreamRejectsOverloadWithoutSDKDispatch(t *testing.T) {
	active := mustID(t, "active")
	overloaded := mustID(t, "overloaded")
	input := callFrame(t, active.Raw(), "tools/call") +
		callFrame(t, overloaded.Raw(), "tools/call") +
		notificationFrame(t, "notifications/cancelled")
	output := &lockedWriteCloser{}
	stream := newStaticLimitedStream(input, output, 1)
	t.Cleanup(func() { _ = stream.Close() })

	first := mustReadOneMessage(t, stream)
	if request, ok := first.(*jsonrpc.Request); !ok || !reflect.DeepEqual(request.ID.Raw(), active.Raw()) {
		t.Fatalf("first message = %#v", first)
	}
	second := mustReadOneMessage(t, stream)
	if request, ok := second.(*jsonrpc.Request); !ok || request.Method != "notifications/cancelled" {
		t.Fatalf("second SDK-visible message = %#v, want cancellation", second)
	}
	assertBusyOutput(t, []byte(output.String()), overloaded)
}

func TestRequestLimitedStreamBoundsNonCallLifetime(t *testing.T) {
	var input strings.Builder
	for i := 0; i <= maxInboundNonCallMessages; i++ {
		input.WriteString(notificationFrame(t, "notifications/cancelled"))
	}
	stream := newStaticLimitedStream(input.String(), &lockedWriteCloser{}, 1)
	t.Cleanup(func() { _ = stream.Close() })
	for i := 0; i < maxInboundNonCallMessages; i++ {
		mustReadOneMessage(t, stream)
	}
	if _, err := readOneMessage(stream); !errors.Is(err, errNonCallBudgetExhausted) {
		t.Fatalf("Read past non-call budget = %v, want %v", err, errNonCallBudgetExhausted)
	}
	if _, err := readOneMessage(stream); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after budget failure = %v, want EOF", err)
	}
}

func TestRequestLimitedStreamAllowsNormalNotifications(t *testing.T) {
	input := notificationFrame(t, "notifications/initialized") +
		notificationFrame(t, "notifications/cancelled") +
		callFrame(t, "after-notifications", "tools/call")
	stream := newStaticLimitedStream(input, &lockedWriteCloser{}, 1)
	t.Cleanup(func() { _ = stream.Close() })
	for _, method := range []string{"notifications/initialized", "notifications/cancelled", "tools/call"} {
		message := mustReadOneMessage(t, stream)
		request, ok := message.(*jsonrpc.Request)
		if !ok || request.Method != method {
			t.Fatalf("message = %#v, want %q", message, method)
		}
	}
}

func TestRequestLimitedStreamCountsInboundResponsesAsNonCalls(t *testing.T) {
	var input strings.Builder
	for i := 0; i <= maxInboundNonCallMessages; i++ {
		input.WriteString(responseFrame(t, float64(i+1)))
	}
	stream := newStaticLimitedStream(input.String(), &lockedWriteCloser{}, 1)
	t.Cleanup(func() { _ = stream.Close() })
	for i := 0; i < maxInboundNonCallMessages; i++ {
		if _, ok := mustReadOneMessage(t, stream).(*jsonrpc.Response); !ok {
			t.Fatalf("message %d is not a response", i)
		}
	}
	if _, err := readOneMessage(stream); !errors.Is(err, errNonCallBudgetExhausted) {
		t.Fatalf("Read past response budget = %v, want %v", err, errNonCallBudgetExhausted)
	}
}

func TestRequestLimitedStreamRejectsOverCapacityBatchAtomically(t *testing.T) {
	first := mustID(t, float64(1))
	second := mustID(t, float64(2))
	input := batchFrame(t,
		&jsonrpc.Request{ID: first, Method: "first"},
		&jsonrpc.Request{ID: second, Method: "second"},
		&jsonrpc.Response{ID: mustID(t, float64(99))},
	)
	output := &lockedWriteCloser{}
	stream := newStaticLimitedStream(input, output, 1)
	t.Cleanup(func() { _ = stream.Close() })

	if _, err := readStreamFrame(stream); !errors.Is(err, errBatchCapacityExhausted) {
		t.Fatalf("over-capacity batch error = %v, want %v", err, errBatchCapacityExhausted)
	}
	if output.String() != "" {
		t.Fatalf("over-capacity batch produced partial output: %q", output.String())
	}
	pending, responding := limiterCounts(stream)
	stream.mu.Lock()
	nonCalls := stream.nonCalls
	stream.mu.Unlock()
	if pending != 0 || responding != 0 || nonCalls != 0 {
		t.Fatalf("over-capacity batch changed state: pending=%d responding=%d nonCalls=%d", pending, responding, nonCalls)
	}
}

func TestRequestLimitedStreamRejectsHugeTinyElementBatchBeforeForwarding(t *testing.T) {
	// This models a configured frame of roughly six megabytes, but contains
	// millions of elements. Classification must stop at the batch cardinality cap
	// instead of materializing an attacker-sized []json.RawMessage.
	frame := "[" + strings.Repeat("0,", 3<<20) + "0]\n"
	output := &lockedWriteCloser{}
	stream := newRequestLimitedStream(
		newBoundedFrameReadCloser(strings.NewReader(frame), len(frame)),
		output,
		1,
	)
	t.Cleanup(func() { _ = stream.Close() })

	buffer := make([]byte, 1)
	if n, err := stream.Read(buffer); n != 0 || !errors.Is(err, errBatchCapacityExhausted) {
		t.Fatalf("huge batch Read = (%d, %v), want (0, %v)", n, err, errBatchCapacityExhausted)
	}
	if output.String() != "" {
		t.Fatalf("huge batch produced output: %q", output.String())
	}
	pending, responding := limiterCounts(stream)
	stream.mu.Lock()
	nonCalls := stream.nonCalls
	stream.mu.Unlock()
	if pending != 0 || responding != 0 || nonCalls != 0 {
		t.Fatalf("huge batch changed state: pending=%d responding=%d nonCalls=%d", pending, responding, nonCalls)
	}
}

func TestRequestLimitedStreamRejectsValidJSONInvalidBatchWithoutForwarding(t *testing.T) {
	call := strings.TrimSuffix(callFrame(t, "must-not-be-dispatched", "tools/call"), "\n")
	input := "[" + call + ",0]\n"
	output := &lockedWriteCloser{}
	stream := newStaticLimitedStream(input, output, 1)
	t.Cleanup(func() { _ = stream.Close() })

	if _, err := readStreamFrame(stream); !errors.Is(err, errInvalidBatchMessage) {
		t.Fatalf("invalid batch error = %v, want %v", err, errInvalidBatchMessage)
	}
	if output.String() != "" {
		t.Fatalf("invalid batch produced output: %q", output.String())
	}
	pending, responding := limiterCounts(stream)
	if pending != 0 || responding != 0 {
		t.Fatalf("invalid batch changed state: pending=%d responding=%d", pending, responding)
	}
}

func TestBatchMessageLimitIsDerivedAndHardCapped(t *testing.T) {
	if got, want := batchMessageLimit(1), 1+maxInboundNonCallMessages; got != want {
		t.Fatalf("batchMessageLimit(1) = %d, want %d", got, want)
	}
	if got := batchMessageLimit(math.MaxInt); got != maxJSONRPCBatchMessages {
		t.Fatalf("batchMessageLimit(MaxInt) = %d, want %d", got, maxJSONRPCBatchMessages)
	}
	payload := []byte("[" + strings.Repeat("0,", maxJSONRPCBatchMessages) + "0]")
	if _, ok, err := decodeBatchElements(payload, math.MaxInt); !ok || !errors.Is(err, errBatchCapacityExhausted) {
		t.Fatalf("uncapped decodeBatchElements = (ok=%t, err=%v), want hard-cap error", ok, err)
	}
}

func TestRequestLimitedStreamRejectsNotificationBatchAtomically(t *testing.T) {
	for _, test := range []struct {
		name     string
		messages func(t *testing.T, callID jsonrpc.ID) []jsonrpc.Message
	}{
		{
			name: "call before notification",
			messages: func(t *testing.T, callID jsonrpc.ID) []jsonrpc.Message {
				return []jsonrpc.Message{
					&jsonrpc.Request{ID: callID, Method: "tools/call"},
					&jsonrpc.Request{Method: "notifications/cancelled"},
				}
			},
		},
		{
			name: "notification before call",
			messages: func(t *testing.T, callID jsonrpc.ID) []jsonrpc.Message {
				return []jsonrpc.Message{
					&jsonrpc.Request{Method: "notifications/cancelled"},
					&jsonrpc.Request{ID: callID, Method: "tools/call"},
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rejectedID := mustID(t, "rejected")
			nextID := mustID(t, "next")
			input := batchFrame(t, test.messages(t, rejectedID)...)
			input += callFrame(t, nextID.Raw(), "tools/call")
			output := &lockedWriteCloser{}
			stream := newStaticLimitedStream(input, output, 1)
			t.Cleanup(func() { _ = stream.Close() })

			if _, err := readStreamFrame(stream); !errors.Is(err, errBatchContainsNotification) {
				t.Fatalf("notification batch error = %v, want %v", err, errBatchContainsNotification)
			}
			if output.String() != "" {
				t.Fatalf("notification batch produced output: %q", output.String())
			}
			pending, responding := limiterCounts(stream)
			stream.mu.Lock()
			nonCalls := stream.nonCalls
			stream.mu.Unlock()
			if pending != 0 || responding != 0 || nonCalls != 0 {
				t.Fatalf("notification batch changed state: pending=%d responding=%d nonCalls=%d", pending, responding, nonCalls)
			}

			message := mustReadOneMessage(t, stream)
			request, ok := message.(*jsonrpc.Request)
			if !ok || !reflect.DeepEqual(request.ID.Raw(), nextID.Raw()) {
				t.Fatalf("message after rejected batch = %#v, want call ID %#v", message, nextID.Raw())
			}
			if err := writeResponse(stream, nextID); err != nil {
				t.Fatal(err)
			}
			pending, responding = limiterCounts(stream)
			if pending != 0 || responding != 0 {
				t.Fatalf("final state: pending=%d responding=%d", pending, responding)
			}
		})
	}
}

func TestRequestLimitedStreamPassesAdmissibleBatchUnchanged(t *testing.T) {
	first := mustID(t, float64(1))
	second := mustID(t, float64(2))
	input := batchFrame(t,
		&jsonrpc.Request{ID: first, Method: "first"},
		&jsonrpc.Request{ID: second, Method: "second"},
		&jsonrpc.Response{ID: mustID(t, float64(99))},
	)
	output := &lockedWriteCloser{}
	stream := newStaticLimitedStream(input, output, 2)
	t.Cleanup(func() { _ = stream.Close() })

	frame, err := readStreamFrame(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(frame) != input {
		t.Fatalf("admissible batch changed:\n got %q\nwant %q", frame, input)
	}
	pending, responding := limiterCounts(stream)
	if pending != 2 || responding != 0 {
		t.Fatalf("admissible batch state: pending=%d responding=%d", pending, responding)
	}

	responseBatch := batchFrame(t, &jsonrpc.Response{ID: first}, &jsonrpc.Response{ID: second})
	if _, err := stream.Write([]byte(responseBatch)); err != nil {
		t.Fatal(err)
	}
	pending, responding = limiterCounts(stream)
	if pending != 0 || responding != 0 {
		t.Fatalf("batch response state: pending=%d responding=%d", pending, responding)
	}
	if output.String() != responseBatch {
		t.Fatalf("batch response output = %q, want %q", output.String(), responseBatch)
	}
}

func TestRequestLimitedStreamWriteFailureUnblocksReaders(t *testing.T) {
	stdin, input := io.Pipe()
	writeFailure := errors.New("stopped stdout")
	output := &errorWriteCloser{err: writeFailure}
	stream := newLimitedStream(stdin, output, 1)
	tracked := &firstError{}
	stream.reportError = tracked.Record
	t.Cleanup(func() {
		_ = stream.Close()
		_ = input.Close()
	})
	id := mustID(t, float64(1))
	writeAndReadOneMessage(t, input, stream, callFrame(t, id.Raw(), "tools/call"))

	readDone := make(chan error, 1)
	go func() {
		_, err := readOneMessage(stream)
		readDone <- err
	}()
	if err := writeResponse(stream, id); !errors.Is(err, writeFailure) {
		t.Fatalf("Write error = %v, want %v", err, writeFailure)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked Read returned nil error after Write failure")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Read did not stop after Write failure")
	}
	if !errors.Is(tracked.Err(), writeFailure) {
		t.Fatalf("tracked error = %v, want %v", tracked.Err(), writeFailure)
	}
}

func TestRequestLimitedStreamObservesEOFDuringActiveCall(t *testing.T) {
	id := mustID(t, float64(1))
	stream := newStaticLimitedStream(callFrame(t, id.Raw(), "tools/call"), &lockedWriteCloser{}, 1)
	t.Cleanup(func() { _ = stream.Close() })
	mustReadOneMessage(t, stream)
	if _, err := readOneMessage(stream); !errors.Is(err, io.EOF) {
		t.Fatalf("Read at call cap = %v, want EOF", err)
	}
	if _, err := readOneMessage(stream); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after EOF = %v, want EOF", err)
	}
}

func TestRequestLimitedStreamEOFLeavesOutputLaneOpenForActiveResponse(t *testing.T) {
	id := mustID(t, float64(1))
	output := &lockedWriteCloser{}
	stream := newStaticLimitedStream(callFrame(t, id.Raw(), "tools/call"), output, 1)
	t.Cleanup(func() { _ = stream.Close() })
	mustReadOneMessage(t, stream)
	if _, err := readOneMessage(stream); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal Read = %v, want EOF", err)
	}
	if err := writeResponse(stream, id); err != nil {
		t.Fatalf("active response after input EOF: %v", err)
	}
	assertResponseID(t, []byte(output.String()), id)
	pending, responding := limiterCounts(stream)
	if pending != 0 || responding != 0 {
		t.Fatalf("state after EOF response: pending=%d responding=%d", pending, responding)
	}
}

func TestRequestLimitedStreamCloseDiscardsBufferedFrameRemainder(t *testing.T) {
	stream := newStaticLimitedStream(callFrame(t, "buffered", strings.Repeat("m", 1024)), &lockedWriteCloser{}, 1)
	var first [1]byte
	if n, err := stream.Read(first[:]); n != 1 || err != nil {
		t.Fatalf("first partial Read = (%d, %v), want (1, nil)", n, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	if n, err := stream.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read after Close = (%d, %v), want (0, EOF)", n, err)
	}
}

func TestResponseQueuedBehindBusyOutputDoesNotRetireID(t *testing.T) {
	active := mustID(t, "active")
	overloaded := mustID(t, "overloaded")
	output := newGatedWriteCloser()
	stream := newStaticLimitedStream(
		callFrame(t, active.Raw(), "tools/call")+callFrame(t, overloaded.Raw(), "tools/call"),
		output,
		1,
	)
	t.Cleanup(func() { _ = stream.Close() })
	mustReadOneMessage(t, stream)

	readDone := make(chan error, 1)
	go func() {
		_, err := readOneMessage(stream)
		readDone <- err
	}()
	busy := receiveWrite(t, output.visible)
	assertBusyOutput(t, busy.frame, overloaded)

	responseDone := make(chan error, 1)
	go func() { responseDone <- writeResponse(stream, active) }()
	waitForLimiterCounts(t, stream, 1, 0)
	if _, _, err := stream.admitFrame([]byte(callFrame(t, active.Raw(), "tools/call"))); !errors.Is(err, errDuplicateInFlightRequest) {
		t.Fatalf("same ID while response queued behind busy = %v, want %v", err, errDuplicateInFlightRequest)
	}

	close(busy.release)
	response := receiveWrite(t, output.visible)
	assertResponseID(t, response.frame, active)
	close(response.release)
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; !errors.Is(err, io.EOF) {
		t.Fatalf("Read after busy output = %v, want EOF", err)
	}
}

func TestRequestLimitedStreamBlockedBusyOutputBoundsReadPath(t *testing.T) {
	stdin, input := io.Pipe()
	output := newGatedWriteCloser()
	stream := newLimitedStream(stdin, output, 1)
	t.Cleanup(func() {
		_ = stream.Close()
		_ = input.Close()
	})
	writeAndReadOneMessage(t, input, stream, callFrame(t, "active", "tools/call"))

	inputDone := writePipeFrames(input,
		callFrame(t, "overloaded", "tools/call")+notificationFrame(t, "notifications/cancelled"),
	)
	firstRead := make(chan streamReadResult, 1)
	go func() {
		message, err := readOneMessage(stream)
		firstRead <- streamReadResult{message: message, err: err}
	}()
	busy := receiveWrite(t, output.visible)
	assertBusyOutput(t, busy.frame, mustID(t, "overloaded"))

	secondRead := make(chan streamReadResult, 1)
	go func() {
		message, err := readOneMessage(stream)
		secondRead <- streamReadResult{message: message, err: err}
	}()
	select {
	case result := <-firstRead:
		t.Fatalf("busy Read returned while output blocked: %#v", result)
	case result := <-secondRead:
		t.Fatalf("serialized Read returned while output blocked: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}

	close(busy.release)
	select {
	case result := <-firstRead:
		request, ok := result.message.(*jsonrpc.Request)
		if result.err != nil || !ok || request.Method != "notifications/cancelled" {
			t.Fatalf("Read after busy = (%#v, %v), want cancellation", result.message, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("busy Read remained blocked")
	}
	if err := <-inputDone; err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-secondRead:
		if !errors.Is(result.err, io.EOF) {
			t.Fatalf("serialized Read = (%#v, %v), want EOF", result.message, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("serialized Read remained blocked")
	}
}

func TestRequestLimitedStreamRejectsDuplicateInFlightID(t *testing.T) {
	id := mustID(t, "same")
	input := callFrame(t, id.Raw(), "first") + callFrame(t, id.Raw(), "duplicate")
	stream := newStaticLimitedStream(input, &lockedWriteCloser{}, 2)
	t.Cleanup(func() { _ = stream.Close() })
	mustReadOneMessage(t, stream)
	if _, err := readOneMessage(stream); !errors.Is(err, errDuplicateInFlightRequest) {
		t.Fatalf("duplicate Read = %v, want %v", err, errDuplicateInFlightRequest)
	}
	if _, err := readOneMessage(stream); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after duplicate = %v, want EOF", err)
	}
}

type streamReadResult struct {
	message jsonrpc.Message
	err     error
}

type rawWriteObservation struct {
	frame   []byte
	release chan struct{}
}

type gatedWriteCloser struct {
	visible   chan rawWriteObservation
	closed    chan struct{}
	closeOnce sync.Once
}

func newGatedWriteCloser() *gatedWriteCloser {
	return &gatedWriteCloser{
		visible: make(chan rawWriteObservation, 256),
		closed:  make(chan struct{}),
	}
}

func (w *gatedWriteCloser) Write(p []byte) (int, error) {
	observation := rawWriteObservation{
		frame:   append([]byte(nil), p...),
		release: make(chan struct{}),
	}
	select {
	case w.visible <- observation:
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
	select {
	case <-observation.release:
		return len(p), nil
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
}

func (w *gatedWriteCloser) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return nil
}

type lockedWriteCloser struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedWriteCloser) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *lockedWriteCloser) Close() error { return nil }

func (w *lockedWriteCloser) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

type errorWriteCloser struct {
	err error
}

func (w *errorWriteCloser) Write([]byte) (int, error) { return 0, w.err }
func (*errorWriteCloser) Close() error                { return nil }

func newLimitedStream(input io.Reader, output io.WriteCloser, limit int) *requestLimitedStream {
	return newRequestLimitedStream(newBoundedFrameReadCloser(input, 1<<20), output, limit)
}

func newStaticLimitedStream(input string, output io.WriteCloser, limit int) *requestLimitedStream {
	return newLimitedStream(strings.NewReader(input), output, limit)
}

func callFrame(t *testing.T, id any, method string) string {
	t.Helper()
	return messageFrame(t, &jsonrpc.Request{ID: mustID(t, id), Method: method})
}

func notificationFrame(t *testing.T, method string) string {
	t.Helper()
	return messageFrame(t, &jsonrpc.Request{Method: method})
}

func responseFrame(t *testing.T, id any) string {
	t.Helper()
	return messageFrame(t, &jsonrpc.Response{ID: mustID(t, id)})
}

func messageFrame(t *testing.T, message jsonrpc.Message) string {
	t.Helper()
	encoded, err := jsonrpc.EncodeMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

func batchFrame(t *testing.T, messages ...jsonrpc.Message) string {
	t.Helper()
	raw := make([]json.RawMessage, 0, len(messages))
	for _, message := range messages {
		encoded, err := jsonrpc.EncodeMessage(message)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

func mustID(t *testing.T, raw any) jsonrpc.ID {
	t.Helper()
	switch value := raw.(type) {
	case int:
		raw = float64(value)
	case int32:
		raw = float64(value)
	case int64:
		raw = float64(value)
	}
	id, err := jsonrpc.MakeID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func writeResponse(stream *requestLimitedStream, id jsonrpc.ID) error {
	encoded, err := jsonrpc.EncodeMessage(&jsonrpc.Response{ID: id})
	if err != nil {
		return err
	}
	_, err = stream.Write(append(encoded, '\n'))
	return err
}

func readStreamFrame(stream *requestLimitedStream) ([]byte, error) {
	buffer := make([]byte, 1<<20)
	n, err := stream.Read(buffer)
	return append([]byte(nil), buffer[:n]...), err
}

func readOneMessage(stream *requestLimitedStream) (jsonrpc.Message, error) {
	frame, err := readStreamFrame(stream)
	if err != nil {
		return nil, err
	}
	messages, _, batch, decoded, err := decodeJSONRPCFrame(frame, maxJSONRPCBatchMessages)
	if err != nil {
		return nil, err
	}
	if !decoded || batch || len(messages) != 1 {
		return nil, errors.New("stream did not return one JSON-RPC message")
	}
	return messages[0], nil
}

func mustReadOneMessage(t *testing.T, stream *requestLimitedStream) jsonrpc.Message {
	t.Helper()
	message, err := readOneMessage(stream)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func writeAndReadOneMessage(t *testing.T, input *io.PipeWriter, stream *requestLimitedStream, frame string) jsonrpc.Message {
	t.Helper()
	done := writePipeFrames(input, frame)
	message := mustReadOneMessage(t, stream)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return message
}

func writePipeFrames(input *io.PipeWriter, frames string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(input, frames)
		done <- err
	}()
	return done
}

func limiterCounts(stream *requestLimitedStream) (int, int) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return len(stream.pending), stream.responding
}

func waitForLimiterCounts(t *testing.T, stream *requestLimitedStream, wantPending, wantResponding int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		pending, responding := limiterCounts(stream)
		if pending == wantPending && responding == wantResponding {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state = pending %d responding %d, want %d/%d", pending, responding, wantPending, wantResponding)
		}
		time.Sleep(time.Millisecond)
	}
}

func receiveWrite(t *testing.T, observations <-chan rawWriteObservation) rawWriteObservation {
	t.Helper()
	select {
	case observation := <-observations:
		return observation
	case <-time.After(time.Second):
		t.Fatal("output write did not start")
		return rawWriteObservation{}
	}
}

func assertResponseID(t *testing.T, frame []byte, want jsonrpc.ID) {
	t.Helper()
	messages, _, _, decoded, err := decodeJSONRPCFrame(frame, maxJSONRPCBatchMessages)
	if err != nil {
		t.Fatalf("response frame classification: %v", err)
	}
	if !decoded || len(messages) != 1 {
		t.Fatalf("response frame = %q", frame)
	}
	response, ok := messages[0].(*jsonrpc.Response)
	if !ok || !reflect.DeepEqual(response.ID.Raw(), want.Raw()) {
		t.Fatalf("response = %#v, want ID %#v", messages[0], want.Raw())
	}
}

func assertBusyOutput(t *testing.T, frame []byte, wantID jsonrpc.ID) {
	t.Helper()
	messages, _, _, decoded, err := decodeJSONRPCFrame(frame, maxJSONRPCBatchMessages)
	if err != nil {
		t.Fatalf("busy output classification: %v", err)
	}
	if !decoded {
		t.Fatalf("busy output is not JSON-RPC: %q", frame)
	}
	for _, message := range messages {
		response, ok := message.(*jsonrpc.Response)
		if !ok || !reflect.DeepEqual(response.ID.Raw(), wantID.Raw()) {
			continue
		}
		var wireError *jsonrpc.Error
		if !errors.As(response.Error, &wireError) {
			t.Fatalf("busy response error = %#v", response.Error)
		}
		if wireError.Code != serverBusyCode || wireError.Message != serverBusyMessage || len(wireError.Data) != 0 {
			t.Fatalf("busy error = %#v", wireError)
		}
		return
	}
	t.Fatalf("busy response for ID %#v not found in %q", wantID.Raw(), frame)
}
