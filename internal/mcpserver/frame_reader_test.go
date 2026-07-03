package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openclaw/turnwire/internal/mailbox"
)

func TestFrameByteLimit(t *testing.T) {
	got, err := frameByteLimit(10)
	if err != nil {
		t.Fatal(err)
	}
	want := frameEnvelopeOverheadBytes + jsonEscapeExpansion*10
	if got != want {
		t.Fatalf("frameByteLimit(10) = %d, want %d", got, want)
	}

	got, err = frameByteLimit(math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	if got != math.MaxInt {
		t.Fatalf("overflow-safe frame limit = %d, want %d", got, math.MaxInt)
	}
}

func TestBoundedFrameReaderAcceptsExactCap(t *testing.T) {
	limit, err := frameByteLimit(1)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`"` + strings.Repeat("a", limit-2) + `"`)
	for name, ending := range map[string]string{"LF": "\n", "CRLF": "\r\n"} {
		t.Run(name, func(t *testing.T) {
			frame := append(append([]byte(nil), payload...), ending...)
			reader := newBoundedFrameReadCloser(bytes.NewReader(frame), limit)
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, frame) {
				t.Fatalf("exact-cap frame changed: got %d bytes, want %d", len(got), len(frame))
			}
		})
	}
}

func TestBoundedFrameReaderRejectsOversizedFrame(t *testing.T) {
	limit, err := frameByteLimit(1)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`"` + strings.Repeat("a", limit-1) + `"` + "\n")
	reader := newBoundedFrameReadCloser(bytes.NewReader(payload), limit)
	if _, err := io.ReadAll(reader); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("oversized frame error = %v, want %v", err, errFrameTooLarge)
	}
}

func TestBoundedFrameReaderRejectsIncompleteJSONPerFrame(t *testing.T) {
	// Each newline-delimited payload is individually below the frame limit. The
	// first incomplete value must be rejected before any bytes reach the SDK;
	// otherwise its decoder can accumulate subsequent frames without a bound.
	input := []byte("[\n[\n[\n")
	reader := newBoundedFrameReadCloser(bytes.NewReader(input), 1)
	got, err := io.ReadAll(reader)
	if !errors.Is(err, errInvalidJSONFrame) {
		t.Fatalf("incomplete frame error = %v, want %v", err, errInvalidJSONFrame)
	}
	if len(got) != 0 {
		t.Fatalf("reader released %d bytes from an incomplete frame", len(got))
	}
}

func TestBoundedFrameReaderRejectsMultipleJSONValues(t *testing.T) {
	reader := newBoundedFrameReadCloser(bytes.NewReader([]byte("{}{}\n")), 4)
	if _, err := io.ReadAll(reader); !errors.Is(err, errInvalidJSONFrame) {
		t.Fatalf("multiple-value frame error = %v, want %v", err, errInvalidJSONFrame)
	}
}

func TestBoundedFrameReaderRejectsInvalidTextEncoding(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{
			name:  "raw invalid UTF-8",
			frame: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}', '\n'},
			want:  errInvalidUTF8,
		},
		{
			name:  "lone high surrogate",
			frame: []byte(`{"x":"\uD800"}` + "\n"),
			want:  errInvalidSurrogate,
		},
		{
			name:  "lone low surrogate",
			frame: []byte(`{"x":"\uDC00"}` + "\n"),
			want:  errInvalidSurrogate,
		},
		{
			name:  "mismatched surrogate pair",
			frame: []byte(`{"x":"\uD800\u0041"}` + "\n"),
			want:  errInvalidSurrogate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newBoundedFrameReadCloser(bytes.NewReader(test.frame), 1024)
			if _, err := io.ReadAll(reader); !errors.Is(err, test.want) {
				t.Fatalf("frame error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestBoundedFrameReaderAcceptsSurrogatePair(t *testing.T) {
	frame := []byte(`{"x":"\uD83D\uDE00"}` + "\n")
	reader := newBoundedFrameReadCloser(bytes.NewReader(frame), 1024)
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("valid surrogate-pair frame changed: got %q, want %q", got, frame)
	}
}

type countingTalker struct {
	calls atomic.Int32
}

func (t *countingTalker) Talk(context.Context, mailbox.TalkInput) (mailbox.TalkOutput, error) {
	t.calls.Add(1)
	return mailbox.TalkOutput{}, nil
}

func TestRunRejectsInvalidFrameBeforeSDKDecode(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{
			name:  "invalid raw UTF-8",
			frame: []byte{'{', '"', 'j', 's', 'o', 'n', 'r', 'p', 'c', '"', ':', '"', '2', '.', '0', '"', ',', '"', 'x', '"', ':', '"', 0xff, '"', '}', '\n'},
			want:  errInvalidUTF8,
		},
		{
			name:  "lone surrogate",
			frame: []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"\uD800","version":"1"}}}` + "\n"),
			want:  errInvalidSurrogate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			talker := &countingTalker{}
			err := Run(context.Background(), talker, "test", bytes.NewReader(test.frame), io.Discard, 32, 1)
			if !errors.Is(err, test.want) && (err == nil || !strings.Contains(err.Error(), test.want.Error())) {
				t.Fatalf("Run error = %v, want %v", err, test.want)
			}
			if got := talker.calls.Load(); got != 0 {
				t.Fatalf("Talk calls = %d, want 0", got)
			}
		})
	}
}
