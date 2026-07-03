package guard

import (
	"strings"
	"testing"
)

func TestScanBlocksSecretsBeforeModel(t *testing.T) {
	tests := []string{
		strings.Join([]string{"Authorization: Bearer", "abcdefghijklmnopqrstuvwxyz"}, " "),
		strings.Join([]string{"api", "key=abcdefghijklmnop"}, "_"),
		strings.Join([]string{"-----BEGIN", "PRIVATE KEY-----"}, " "),
		strings.Join([]string{"eyJabcdefghij", "abcdefghijkl", "abcdefghijkl"}, "."),
	}
	for _, text := range tests {
		findings := Scan(text)
		if len(findings) == 0 || findings[0].Decision != DecisionDeny {
			t.Fatalf("Scan(%q) = %#v", text, findings)
		}
	}
}

func TestScanReviewsLuhnPaymentCard(t *testing.T) {
	findings := Scan("card 4111 1111 1111 1111")
	if len(findings) == 0 || findings[0].Code != "payment_card" || findings[0].Decision != DecisionReview {
		t.Fatalf("findings = %#v", findings)
	}
}
