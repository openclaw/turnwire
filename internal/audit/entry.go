// Package audit provides a small append-only, tamper-evident event log.
package audit

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"time"
	"unicode/utf8"
)

// Event contains the caller-controlled fields for a new audit entry. Timestamp,
// sequence number, hashes, and the previous-chain link are assigned by Append.
type Event struct {
	EventID        string
	ExchangeID     string
	RequestID      string
	ConversationID string
	Type           string
	Status         string
	ErrorCode      string
	Text           string
	Details        map[string]string
}

// Entry is the durable representation of an audit event.
type Entry struct {
	Seq            uint64            `json:"seq"`
	EventID        string            `json:"event_id"`
	ExchangeID     string            `json:"exchange_id"`
	RequestID      string            `json:"request_id"`
	ConversationID string            `json:"conversation_id"`
	Type           string            `json:"type"`
	Status         string            `json:"status"`
	ErrorCode      string            `json:"error_code"`
	Timestamp      string            `json:"timestamp"`
	Text           string            `json:"text"`
	TextSHA256     string            `json:"text_sha256"`
	Details        map[string]string `json:"details,omitempty"`
	PreviousHash   string            `json:"previous_hash"`
	EntryHash      string            `json:"entry_hash"`
}

// storedEntry is the only on-disk audit representation. Sensitive fields are
// never serialized in plaintext; the entry hash is authenticated as AES-GCM
// associated data and still binds the decrypted payload and chain metadata.
type storedEntry struct {
	Seq               uint64 `json:"seq"`
	Timestamp         string `json:"timestamp"`
	PayloadCiphertext string `json:"payload_ciphertext"`
	PayloadNonce      string `json:"payload_nonce"`
	PreviousHash      string `json:"previous_hash"`
	EntryHash         string `json:"entry_hash"`
}

type storedPayload struct {
	EventID        string            `json:"event_id"`
	ExchangeID     string            `json:"exchange_id"`
	RequestID      string            `json:"request_id"`
	ConversationID string            `json:"conversation_id"`
	Type           string            `json:"type"`
	Status         string            `json:"status"`
	ErrorCode      string            `json:"error_code"`
	Text           string            `json:"text"`
	TextSHA256     string            `json:"text_sha256"`
	Details        map[string]string `json:"details,omitempty"`
}

type hashableEntry struct {
	Seq            uint64            `json:"seq"`
	EventID        string            `json:"event_id"`
	ExchangeID     string            `json:"exchange_id"`
	RequestID      string            `json:"request_id"`
	ConversationID string            `json:"conversation_id"`
	Type           string            `json:"type"`
	Status         string            `json:"status"`
	ErrorCode      string            `json:"error_code"`
	Timestamp      string            `json:"timestamp"`
	Text           string            `json:"text"`
	TextSHA256     string            `json:"text_sha256"`
	Details        map[string]string `json:"details,omitempty"`
	PreviousHash   string            `json:"previous_hash"`
}

func validateEvent(event Event) error {
	required := []struct {
		name  string
		value string
	}{
		{"event ID", event.EventID},
		{"exchange ID", event.ExchangeID},
		{"request ID", event.RequestID},
		{"conversation ID", event.ConversationID},
		{"event type", event.Type},
	}
	for _, field := range required {
		if field.value == "" {
			return fmt.Errorf("%s is required", field.name)
		}
		if !utf8.ValidString(field.value) {
			return fmt.Errorf("%s must be valid UTF-8", field.name)
		}
	}
	if !utf8.ValidString(event.Status) {
		return errors.New("status must be valid UTF-8")
	}
	if !utf8.ValidString(event.ErrorCode) {
		return errors.New("error code must be valid UTF-8")
	}
	if !utf8.ValidString(event.Text) {
		return errors.New("text must be valid UTF-8")
	}
	if len(event.Details) > 32 {
		return errors.New("audit details must not exceed 32 fields")
	}
	for key, value := range event.Details {
		if key == "" || len(key) > 64 || !utf8.ValidString(key) {
			return errors.New("audit detail key is invalid")
		}
		if len(value) > 4096 || !utf8.ValidString(value) {
			return fmt.Errorf("audit detail %q is invalid", key)
		}
	}
	return nil
}

func cloneDetails(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	return maps.Clone(details)
}

func encryptEntry(aead cipher.AEAD, entry Entry) (storedEntry, error) {
	if aead == nil {
		return storedEntry{}, errors.New("audit cipher is required")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return storedEntry{}, fmt.Errorf("generate audit nonce: %w", err)
	}
	payload, err := json.Marshal(storedPayload{
		EventID: entry.EventID, ExchangeID: entry.ExchangeID, RequestID: entry.RequestID,
		ConversationID: entry.ConversationID, Type: entry.Type, Status: entry.Status,
		ErrorCode: entry.ErrorCode, Text: entry.Text, TextSHA256: entry.TextSHA256,
		Details: entry.Details,
	})
	if err != nil {
		return storedEntry{}, fmt.Errorf("encode audit payload: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, payload, []byte(entry.EntryHash))
	return storedEntry{
		Seq: entry.Seq, Timestamp: entry.Timestamp,
		PayloadCiphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
		PayloadNonce:      base64.RawStdEncoding.EncodeToString(nonce),
		PreviousHash:      entry.PreviousHash, EntryHash: entry.EntryHash,
	}, nil
}

func decodeEntry(line []byte, aead cipher.AEAD) (Entry, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var stored storedEntry
	if err := decoder.Decode(&stored); err != nil {
		return Entry{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Entry{}, errors.New("multiple JSON values in one entry")
		}
		return Entry{}, fmt.Errorf("trailing data: %w", err)
	}
	canonical, err := json.Marshal(stored)
	if err != nil {
		return Entry{}, fmt.Errorf("encode canonical entry: %w", err)
	}
	if !bytes.Equal(line, canonical) {
		return Entry{}, errors.New("entry is not canonical JSON")
	}
	if aead == nil {
		return Entry{}, errors.New("audit cipher is required")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(stored.PayloadNonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return Entry{}, errors.New("audit text nonce is invalid")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(stored.PayloadCiphertext)
	if err != nil || len(ciphertext) < aead.Overhead() {
		return Entry{}, errors.New("audit text ciphertext is invalid")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(stored.EntryHash))
	if err != nil {
		return Entry{}, errors.New("audit text authentication failed")
	}
	var payload storedPayload
	payloadDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	payloadDecoder.DisallowUnknownFields()
	if err := payloadDecoder.Decode(&payload); err != nil {
		return Entry{}, errors.New("audit payload is invalid")
	}
	var payloadExtra any
	if err := payloadDecoder.Decode(&payloadExtra); !errors.Is(err, io.EOF) {
		return Entry{}, errors.New("audit payload has trailing data")
	}
	entry := Entry{
		Seq: stored.Seq, EventID: payload.EventID, ExchangeID: payload.ExchangeID,
		RequestID: payload.RequestID, ConversationID: payload.ConversationID,
		Type: payload.Type, Status: payload.Status, ErrorCode: payload.ErrorCode,
		Timestamp: stored.Timestamp, Text: payload.Text, TextSHA256: payload.TextSHA256,
		Details: payload.Details, PreviousHash: stored.PreviousHash, EntryHash: stored.EntryHash,
	}
	return entry, nil
}

func verifyEntry(entry Entry, expectedSeq uint64, previousHash string) error {
	if entry.Seq != expectedSeq {
		return fmt.Errorf("sequence is %d, want %d", entry.Seq, expectedSeq)
	}
	if entry.PreviousHash != previousHash {
		return errors.New("previous hash does not match chain head")
	}
	if err := validateEvent(Event{
		EventID:        entry.EventID,
		ExchangeID:     entry.ExchangeID,
		RequestID:      entry.RequestID,
		ConversationID: entry.ConversationID,
		Type:           entry.Type,
		Status:         entry.Status,
		ErrorCode:      entry.ErrorCode,
		Text:           entry.Text,
		Details:        entry.Details,
	}); err != nil {
		return err
	}
	parsedTimestamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	if parsedTimestamp.Location() != time.UTC || parsedTimestamp.Format(time.RFC3339Nano) != entry.Timestamp {
		return errors.New("timestamp is not canonical UTC")
	}
	textHash := sha256.Sum256([]byte(entry.Text))
	if entry.TextSHA256 != hex.EncodeToString(textHash[:]) {
		return errors.New("text hash does not match text")
	}
	if !validHash(entry.PreviousHash) {
		return errors.New("previous hash is not lowercase SHA-256")
	}
	if !validHash(entry.EntryHash) {
		return errors.New("entry hash is not lowercase SHA-256")
	}
	expectedHash, err := calculateEntryHash(entry)
	if err != nil {
		return err
	}
	if entry.EntryHash != expectedHash {
		return errors.New("entry hash does not match content")
	}
	return nil
}

func calculateEntryHash(entry Entry) (string, error) {
	canonical, err := json.Marshal(hashableEntry{
		Seq:            entry.Seq,
		EventID:        entry.EventID,
		ExchangeID:     entry.ExchangeID,
		RequestID:      entry.RequestID,
		ConversationID: entry.ConversationID,
		Type:           entry.Type,
		Status:         entry.Status,
		ErrorCode:      entry.ErrorCode,
		Timestamp:      entry.Timestamp,
		Text:           entry.Text,
		TextSHA256:     entry.TextSHA256,
		Details:        entry.Details,
		PreviousHash:   entry.PreviousHash,
	})
	if err != nil {
		return "", fmt.Errorf("encode canonical audit entry: %w", err)
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
