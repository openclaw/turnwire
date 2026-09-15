package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

// ValidateUniqueKeys rejects object members that encoding/json could overwrite
// while decoding. Case-folded aliases count as duplicates because struct field
// matching is case-insensitive. Keys in separate objects remain independent.
func ValidateUniqueKeys(data []byte) error {
	// Validate syntax first, including encoding/json's maximum nesting depth,
	// before recursively traversing untrusted values.
	if !json.Valid(data) {
		return errors.New("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := uniqueValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func uniqueValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			folded := strings.Map(func(r rune) rune {
				for {
					next := unicode.SimpleFold(r)
					if next <= r {
						return next
					}
					r = next
				}
			}, name)
			if seen[folded] {
				return errors.New("JSON object contains duplicate keys")
			}
			seen[folded] = true
			if err := uniqueValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case json.Delim('['):
		for decoder.More() {
			if err := uniqueValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	return nil
}
