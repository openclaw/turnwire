package guard

import (
	"regexp"
	"strings"
)

// Finding is one deterministic high-risk content match.
type Finding struct {
	Code     string
	Decision string
}

var deterministicRules = []struct {
	code     string
	decision string
	pattern  *regexp.Regexp
}{
	{"private_key", DecisionDeny, regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)},
	{"bearer_token", DecisionDeny, regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}`)},
	{"known_token", DecisionDeny, regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[A-Z0-9]{16})\b`)},
	{"jwt", DecisionDeny, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"credential_assignment", DecisionDeny, regexp.MustCompile(`(?i)\b(?:api[_ -]?key|secret|password|passwd|access[_ -]?token|client[_ -]?secret)\s*[:=]\s*[^\s,;]{8,}`)},
	{"credential_url", DecisionDeny, regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@`)},
	{"social_security_number", DecisionReview, regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"payment_card", DecisionReview, regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)},
}

// Scan blocks obvious secrets before any model call. It returns codes only,
// never matched content.
func Scan(text string) []Finding {
	findings := make([]Finding, 0, 2)
	seen := make(map[string]struct{})
	for _, rule := range deterministicRules {
		if !rule.pattern.MatchString(text) {
			continue
		}
		if rule.code == "payment_card" && !containsLuhnCandidate(text) {
			continue
		}
		if _, ok := seen[rule.code]; ok {
			continue
		}
		seen[rule.code] = struct{}{}
		findings = append(findings, Finding{Code: rule.code, Decision: rule.decision})
	}
	return findings
}

func containsLuhnCandidate(text string) bool {
	for _, field := range strings.FieldsFunc(text, func(r rune) bool {
		return (r < '0' || r > '9') && r != ' ' && r != '-'
	}) {
		digits := strings.NewReplacer(" ", "", "-", "").Replace(field)
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			return true
		}
	}
	return false
}

func luhn(digits string) bool {
	sum := 0
	parity := len(digits) % 2
	for i, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
		value := int(r - '0')
		if i%2 == parity {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
	}
	return sum%10 == 0
}
