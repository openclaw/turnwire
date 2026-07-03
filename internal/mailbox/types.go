package mailbox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openclaw/turnwire/internal/identity"
)

var (
	ErrInvalidInput = errors.New("invalid channel input")
	ErrConflict     = errors.New("identifier conflicts with an existing message")
	ErrBusy         = errors.New("channel is at its concurrency limit")
	ErrRateLimited  = errors.New("channel request budget exhausted")
	ErrClosed       = errors.New("channel service is shutting down")
	ErrUnauthorized = errors.New("message signature or peer identity is invalid")
)

const (
	// MaxMessageBytes is the protocol-wide decoded text ceiling.
	MaxMessageBytes = 1 << 20
	// MaxInboxOutputBytes bounds the encoded structured result of list_messages.
	// It admits one maximally escaped protocol message plus fixed metadata.
	MaxInboxOutputBytes = 6*MaxMessageBytes + 64*1024
	// MaxMCPOutputBytes adds fixed JSON-RPC and MCP result framing headroom.
	MaxMCPOutputBytes = MaxInboxOutputBytes + 64*1024
)

type SendInput struct {
	Destination    string `json:"destination" jsonschema:"configured peer identity"`
	Text           string `json:"text" jsonschema:"exact text proposed for transfer"`
	RequestID      string `json:"request_id,omitempty" jsonschema:"optional idempotency key"`
	ConversationID string `json:"conversation_id,omitempty" jsonschema:"optional correlation ID"`
}

type Envelope struct {
	Version             int    `json:"version"`
	MessageID           string `json:"message_id"`
	RequestID           string `json:"request_id"`
	ConversationID      string `json:"conversation_id"`
	Source              string `json:"source"`
	Destination         string `json:"destination"`
	CreatedAt           string `json:"created_at"`
	Body                string `json:"body"`
	BodySHA256          string `json:"body_sha256"`
	PolicyVersion       string `json:"policy_version"`
	GuardModel          string `json:"guard_model"`
	GuardDecision       string `json:"guard_decision"`
	SourceAuditSequence uint64 `json:"source_audit_sequence"`
	SourceAuditHead     string `json:"source_audit_head"`
	Signature           string `json:"signature"`
}

type unsignedEnvelope struct {
	Version             int    `json:"version"`
	MessageID           string `json:"message_id"`
	RequestID           string `json:"request_id"`
	ConversationID      string `json:"conversation_id"`
	Source              string `json:"source"`
	Destination         string `json:"destination"`
	CreatedAt           string `json:"created_at"`
	Body                string `json:"body"`
	BodySHA256          string `json:"body_sha256"`
	PolicyVersion       string `json:"policy_version"`
	GuardModel          string `json:"guard_model"`
	GuardDecision       string `json:"guard_decision"`
	SourceAuditSequence uint64 `json:"source_audit_sequence"`
	SourceAuditHead     string `json:"source_audit_head"`
}

func (e Envelope) unsigned() unsignedEnvelope {
	return unsignedEnvelope{
		Version: e.Version, MessageID: e.MessageID, RequestID: e.RequestID,
		ConversationID: e.ConversationID, Source: e.Source, Destination: e.Destination,
		CreatedAt: e.CreatedAt, Body: e.Body, BodySHA256: e.BodySHA256,
		PolicyVersion: e.PolicyVersion, GuardModel: e.GuardModel, GuardDecision: e.GuardDecision,
		SourceAuditSequence: e.SourceAuditSequence, SourceAuditHead: e.SourceAuditHead,
	}
}

func signEnvelope(signer *identity.Signer, envelope *Envelope) error {
	signature, err := signer.Sign(envelope.unsigned())
	if err != nil {
		return err
	}
	envelope.Signature = signature
	return nil
}

func verifyEnvelope(publicKey string, envelope Envelope) error {
	return identity.Verify(publicKey, envelope.unsigned(), envelope.Signature)
}

type SendOutput struct {
	Status        string    `json:"status"`
	MessageID     string    `json:"message_id"`
	RequestID     string    `json:"request_id"`
	BodySHA256    string    `json:"body_sha256"`
	Decision      string    `json:"decision"`
	ReasonCode    string    `json:"reason_code"`
	Envelope      *Envelope `json:"envelope,omitempty"`
	AuditSequence uint64    `json:"audit_sequence"`
	AuditHead     string    `json:"audit_head"`
}

type ReceiveInput struct {
	Envelope Envelope `json:"envelope"`
}

type Acknowledgement struct {
	Version               int    `json:"version"`
	MessageID             string `json:"message_id"`
	Source                string `json:"source"`
	Destination           string `json:"destination"`
	EnvelopeSHA256        string `json:"envelope_sha256"`
	ReceivedAt            string `json:"received_at"`
	ReceiverAuditSequence uint64 `json:"receiver_audit_sequence"`
	ReceiverAuditHead     string `json:"receiver_audit_head"`
	Signature             string `json:"signature"`
}

type unsignedAcknowledgement struct {
	Version               int    `json:"version"`
	MessageID             string `json:"message_id"`
	Source                string `json:"source"`
	Destination           string `json:"destination"`
	EnvelopeSHA256        string `json:"envelope_sha256"`
	ReceivedAt            string `json:"received_at"`
	ReceiverAuditSequence uint64 `json:"receiver_audit_sequence"`
	ReceiverAuditHead     string `json:"receiver_audit_head"`
}

func (a Acknowledgement) unsigned() unsignedAcknowledgement {
	return unsignedAcknowledgement{
		Version: a.Version, MessageID: a.MessageID, Source: a.Source,
		Destination: a.Destination, EnvelopeSHA256: a.EnvelopeSHA256,
		ReceivedAt: a.ReceivedAt, ReceiverAuditSequence: a.ReceiverAuditSequence,
		ReceiverAuditHead: a.ReceiverAuditHead,
	}
}

func signAcknowledgement(signer *identity.Signer, ack *Acknowledgement) error {
	signature, err := signer.Sign(ack.unsigned())
	if err != nil {
		return err
	}
	ack.Signature = signature
	return nil
}

func verifyAcknowledgement(publicKey string, ack Acknowledgement) error {
	return identity.Verify(publicKey, ack.unsigned(), ack.Signature)
}

type ReceiveOutput struct {
	Status          string           `json:"status"`
	MessageID       string           `json:"message_id"`
	Decision        string           `json:"decision"`
	ReasonCode      string           `json:"reason_code"`
	Acknowledgement *Acknowledgement `json:"acknowledgement,omitempty"`
	AuditSequence   uint64           `json:"audit_sequence"`
	AuditHead       string           `json:"audit_head"`
}

type ConfirmInput struct {
	Acknowledgement Acknowledgement `json:"acknowledgement"`
}

type ConfirmOutput struct {
	Status        string `json:"status"`
	MessageID     string `json:"message_id"`
	AuditSequence uint64 `json:"audit_sequence"`
	AuditHead     string `json:"audit_head"`
}

type InboxInput struct {
	AfterSequence uint64 `json:"after_sequence,omitempty"`
	Limit         int    `json:"limit,omitempty"`
}

type Message struct {
	MessageID      string `json:"message_id"`
	ConversationID string `json:"conversation_id"`
	Source         string `json:"source"`
	Destination    string `json:"destination"`
	Body           string `json:"body"`
	BodySHA256     string `json:"body_sha256"`
	ReceivedAt     string `json:"received_at"`
	AuditSequence  uint64 `json:"audit_sequence"`
}

type InboxOutput struct {
	Messages      []Message `json:"messages"`
	AuditSequence uint64    `json:"audit_sequence"`
	AuditHead     string    `json:"audit_head"`
}

func normalizeSend(input SendInput, maxBytes int) (SendInput, error) {
	if !validText(input.Text, maxBytes) {
		return SendInput{}, fmt.Errorf("%w: text is invalid", ErrInvalidInput)
	}
	if !validID(input.Destination) {
		return SendInput{}, fmt.Errorf("%w: destination is invalid", ErrInvalidInput)
	}
	if input.RequestID == "" {
		var err error
		input.RequestID, err = newID()
		if err != nil {
			return SendInput{}, err
		}
	} else if !validID(input.RequestID) {
		return SendInput{}, fmt.Errorf("%w: request_id is invalid", ErrInvalidInput)
	}
	if input.ConversationID == "" {
		input.ConversationID = input.RequestID
	} else if !validID(input.ConversationID) {
		return SendInput{}, fmt.Errorf("%w: conversation_id is invalid", ErrInvalidInput)
	}
	return input, nil
}

func validText(text string, maxBytes int) bool {
	return maxBytes > 0 && len(text) <= maxBytes && utf8.ValidString(text) &&
		!strings.ContainsRune(text, '\x00') && strings.TrimSpace(text) != ""
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

func hashText(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}
