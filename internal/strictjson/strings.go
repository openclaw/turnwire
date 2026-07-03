// Package strictjson rejects text encodings that Go's JSON decoders would
// otherwise repair lossily before callers can enforce exact-text guarantees.
package strictjson

import (
	"errors"
	"unicode/utf8"
)

var (
	ErrInvalidUTF8      = errors.New("JSON text is not valid UTF-8")
	ErrInvalidSurrogate = errors.New("JSON text contains an invalid Unicode surrogate escape")
)

// ValidateText checks raw JSON text for valid UTF-8 and correctly paired
// UTF-16 surrogate escapes. The normal JSON decoder remains responsible for
// all other syntax validation.
func ValidateText(data []byte) error {
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}

	inString := false
	for i := 0; i < len(data); {
		switch data[i] {
		case '"':
			inString = !inString
			i++
		case '\\':
			if !inString {
				i++
				continue
			}
			next, err := consumeStringEscape(data, i)
			if err != nil {
				return err
			}
			i = next
		default:
			i++
		}
	}
	return nil
}

func consumeStringEscape(data []byte, slash int) (int, error) {
	if slash+1 >= len(data) {
		return 0, ErrInvalidSurrogate
	}
	if data[slash+1] != 'u' {
		return slash + 2, nil
	}

	value, next, ok := decodeUnicodeEscape(data, slash)
	if !ok {
		return 0, ErrInvalidSurrogate
	}
	if value >= 0xdc00 && value <= 0xdfff {
		return 0, ErrInvalidSurrogate
	}
	if value < 0xd800 || value > 0xdbff {
		return next, nil
	}

	low, afterLow, ok := decodeUnicodeEscape(data, next)
	if !ok || low < 0xdc00 || low > 0xdfff {
		return 0, ErrInvalidSurrogate
	}
	return afterLow, nil
}

func decodeUnicodeEscape(data []byte, slash int) (uint16, int, bool) {
	if slash < 0 || slash > len(data)-6 || data[slash] != '\\' || data[slash+1] != 'u' {
		return 0, 0, false
	}
	var value uint16
	for _, b := range data[slash+2 : slash+6] {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value |= uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			value |= uint16(b-'A') + 10
		default:
			return 0, 0, false
		}
	}
	return value, slash + 6, true
}
