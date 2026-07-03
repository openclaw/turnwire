package mailbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidInput = errors.New("invalid relay input")
	ErrConflict     = errors.New("request id conflicts with an existing message")
	ErrBusy         = errors.New("relay is at its concurrency limit")
	ErrClosed       = errors.New("relay service is shutting down")
)

type TalkInput struct {
	Text           string `json:"text" jsonschema:"the exact text to send to the configured responder"`
	RequestID      string `json:"request_id,omitempty" jsonschema:"optional idempotency key using 1-64 ASCII letters, digits, dot, underscore, colon, or hyphen"`
	ConversationID string `json:"conversation_id,omitempty" jsonschema:"optional correlation id using 1-64 ASCII letters, digits, dot, underscore, colon, or hyphen"`
}

type TalkOutput struct {
	ExchangeID     string `json:"exchange_id"`
	RequestID      string `json:"request_id"`
	ConversationID string `json:"conversation_id"`
	Reply          string `json:"reply"`
	CreatedAt      string `json:"created_at"`
	RepliedAt      string `json:"replied_at"`
	InputSHA256    string `json:"input_sha256"`
	OutputSHA256   string `json:"output_sha256"`
	AuditSequence  uint64 `json:"audit_sequence"`
	AuditHead      string `json:"audit_head"`
}

func normalizeInput(input TalkInput, maxInputBytes int) (TalkInput, error) {
	if maxInputBytes <= 0 {
		return TalkInput{}, fmt.Errorf("%w: server input limit is invalid", ErrInvalidInput)
	}
	if !utf8.ValidString(input.Text) || strings.ContainsRune(input.Text, '\x00') {
		return TalkInput{}, fmt.Errorf("%w: text must be valid UTF-8 without NUL", ErrInvalidInput)
	}
	if strings.TrimSpace(input.Text) == "" {
		return TalkInput{}, fmt.Errorf("%w: text is empty", ErrInvalidInput)
	}
	if len(input.Text) > maxInputBytes {
		return TalkInput{}, fmt.Errorf("%w: text exceeds %d bytes", ErrInvalidInput, maxInputBytes)
	}
	if input.RequestID == "" {
		var err error
		input.RequestID, err = newID()
		if err != nil {
			return TalkInput{}, err
		}
	} else if !validID(input.RequestID) {
		return TalkInput{}, fmt.Errorf("%w: request_id has an invalid format", ErrInvalidInput)
	}
	if input.ConversationID == "" {
		// Deriving the default from request_id keeps automatic retries stable.
		input.ConversationID = input.RequestID
	} else if !validID(input.ConversationID) {
		return TalkInput{}, fmt.Errorf("%w: conversation_id has an invalid format", ErrInvalidInput)
	}
	return input, nil
}

func validID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '.', '_', ':', '-':
			continue
		default:
			return false
		}
	}
	return true
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	var dst [36]byte
	hex.Encode(dst[0:8], raw[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], raw[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], raw[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], raw[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], raw[10:16])
	return string(dst[:]), nil
}
