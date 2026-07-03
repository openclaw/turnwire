package mcpserver

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/openclaw/turnwire/internal/strictjson"
)

const (
	// The allowance covers JSON-RPC metadata and non-message MCP methods.
	// Six bytes per input byte covers the worst-case JSON \u00XX representation.
	frameEnvelopeOverheadBytes = 64 * 1024
	jsonEscapeExpansion        = 6
)

var (
	errFrameTooLarge    = errors.New("MCP frame exceeds the configured limit")
	errInvalidJSONFrame = errors.New("MCP frame is not exactly one complete JSON value")
	errInvalidUTF8      = strictjson.ErrInvalidUTF8
	errInvalidSurrogate = strictjson.ErrInvalidSurrogate
)

func frameByteLimit(maxInputBytes int) (int, error) {
	if maxInputBytes <= 0 {
		return 0, errors.New("maximum input bytes must be positive")
	}
	if maxInputBytes > (math.MaxInt-frameEnvelopeOverheadBytes)/jsonEscapeExpansion {
		return math.MaxInt, nil
	}
	return frameEnvelopeOverheadBytes + jsonEscapeExpansion*maxInputBytes, nil
}

// boundedFrameReadCloser validates complete newline-delimited frames before
// exposing any bytes to the SDK's JSON decoder.
type boundedFrameReadCloser struct {
	reader *bufio.Reader
	closer io.Closer
	limit  int

	pending   []byte
	afterErr  error
	closeOnce sync.Once
	closeErr  error
}

func newBoundedFrameReadCloser(input io.Reader, limit int) *boundedFrameReadCloser {
	closer, ok := input.(io.Closer)
	if !ok {
		closer = nopCloser{}
	}
	return &boundedFrameReadCloser{
		reader: bufio.NewReader(input),
		closer: closer,
		limit:  limit,
	}
}

func (r *boundedFrameReadCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		frame, err := r.ReadFrame()
		if err != nil {
			return 0, err
		}
		r.pending = frame
	}

	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// ReadFrame returns exactly one validated JSON frame. It is used by the
// admission layer so classification happens only after the size and strict
// encoding checks have succeeded.
func (r *boundedFrameReadCloser) ReadFrame() ([]byte, error) {
	if r.afterErr != nil {
		return nil, r.afterErr
	}
	frame, afterErr, err := r.readFrame()
	if err != nil {
		r.afterErr = err
		return nil, err
	}
	r.afterErr = afterErr
	return frame, nil
}

func (r *boundedFrameReadCloser) readFrame() ([]byte, error, error) {
	var frame []byte
	for {
		fragment, readErr := r.reader.ReadSlice('\n')
		hasNewline := len(fragment) > 0 && fragment[len(fragment)-1] == '\n'

		if !frameFragmentFits(len(frame), fragment, r.limit, hasNewline) {
			return nil, nil, errFrameTooLarge
		}
		frame = append(frame, fragment...)

		if hasNewline {
			payload := frame[:len(frame)-1]
			if len(payload) > 0 && payload[len(payload)-1] == '\r' {
				payload = payload[:len(payload)-1]
			}
			if len(payload) > r.limit {
				return nil, nil, errFrameTooLarge
			}
			if err := validateStrictJSONText(payload); err != nil {
				return nil, nil, err
			}
			return frame, nil, nil
		}

		switch readErr {
		case nil:
			// ReadSlice returns without a newline only when it fills its buffer.
			continue
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(frame) == 0 {
				return nil, nil, io.EOF
			}
			if len(frame) > r.limit {
				return nil, nil, errFrameTooLarge
			}
			if err := validateStrictJSONText(frame); err != nil {
				return nil, nil, err
			}
			return frame, io.EOF, nil
		default:
			return nil, nil, fmt.Errorf("read MCP frame: %w", readErr)
		}
	}
}

func frameFragmentFits(current int, fragment []byte, limit int, hasNewline bool) bool {
	if len(fragment) > math.MaxInt-current {
		return false
	}
	total := current + len(fragment)
	if hasNewline {
		payloadBytes := total - 1
		if payloadBytes <= limit {
			return true
		}
		if payloadBytes-limit != 1 {
			return false
		}
		if len(fragment) >= 2 {
			return fragment[len(fragment)-2] == '\r'
		}
		// The newline may be in a fresh fragment after a trailing CR. The
		// exact check after append rejects the frame if that byte was not CR.
		return current > 0
	}

	if total <= limit {
		return true
	}
	// One extra byte is allowed only while it may become the CR in CRLF.
	return total-limit == 1 && len(fragment) > 0 && fragment[len(fragment)-1] == '\r'
}

func validateStrictJSONText(data []byte) error {
	if err := strictjson.ValidateText(data); err != nil {
		return err
	}
	if !json.Valid(data) {
		return errInvalidJSONFrame
	}
	return nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func (r *boundedFrameReadCloser) Close() error {
	r.closeOnce.Do(func() {
		r.closeErr = r.closer.Close()
	})
	return r.closeErr
}
