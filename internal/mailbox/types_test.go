package mailbox

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeInputPreservesExactText(t *testing.T) {
	text := "first\r\ncombining: e\u0301 🌍"
	got, err := normalizeInput(TalkInput{Text: text}, len(text))
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != text {
		t.Fatalf("text changed: %q", got.Text)
	}
	if !validID(got.RequestID) || !validID(got.ConversationID) {
		t.Fatalf("generated ids are invalid: %#v", got)
	}
}

func TestNormalizeInputBoundary(t *testing.T) {
	text := strings.Repeat("é", 8)
	if len(text) != 16 || !utf8.ValidString(text) {
		t.Fatal("bad fixture")
	}
	if _, err := normalizeInput(TalkInput{Text: text}, 16); err != nil {
		t.Fatalf("at boundary: %v", err)
	}
	if _, err := normalizeInput(TalkInput{Text: text}, 15); err == nil {
		t.Fatal("expected byte-limit error")
	}
}

func TestNormalizeInputRejectsInvalidValues(t *testing.T) {
	tests := []TalkInput{
		{Text: ""},
		{Text: " \n\t"},
		{Text: "hello\x00world"},
		{Text: "hello", RequestID: "bad/id"},
		{Text: "hello", ConversationID: strings.Repeat("x", 65)},
	}
	for _, test := range tests {
		if _, err := normalizeInput(test, 1024); err == nil {
			t.Fatalf("expected error for %#v", test)
		}
	}
}
