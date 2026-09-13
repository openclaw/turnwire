package mailbox

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/identity"
)

// localSigningKeys anchors historical local receipt verification in the current
// private key. Prepared transitions cover a crash after key replacement but
// before the completion event; an uncommitted transition cannot extend the chain.
func (s *Service) localSigningKeys() ([]string, error) {
	transitions := make(map[string]identity.Rotation)
	if err := s.audit.Scan(func(entry audit.Entry) error {
		if entry.Type == "identity_rotation_prepared" {
			rotation := identity.Rotation{
				Identity:          strings.TrimPrefix(entry.ExchangeID, "identity:"),
				PreviousPublicKey: entry.Details["previous_public_key"], NewPublicKey: entry.Details["new_public_key"],
				CreatedAt: entry.Details["created_at"], PreviousSignature: entry.Details["previous_signature"], NewSignature: entry.Details["new_signature"],
			}
			transitions[rotation.NewPublicKey] = rotation
		}
		return nil
	}); err != nil {
		return nil, err
	}
	key := s.signer.PublicKey()
	keys := []string{key}
	seen := map[string]bool{key: true}
	for {
		rotation, ok := transitions[key]
		if !ok {
			return keys, nil
		}
		if err := identity.VerifyRotation(rotation, s.signer.Name(), rotation.PreviousPublicKey); err != nil {
			return nil, fmt.Errorf("verify local identity history: %w", err)
		}
		key = rotation.PreviousPublicKey
		if seen[key] {
			return nil, errors.New("local identity history contains a cycle")
		}
		seen[key] = true
		keys = append(keys, key)
	}
}

func verifyHistoricalAcknowledgement(keys []string, ack Acknowledgement) bool {
	for _, key := range keys {
		if verifyAcknowledgement(key, ack) == nil {
			return true
		}
	}
	return false
}
