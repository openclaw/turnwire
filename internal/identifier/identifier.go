// Package identifier defines the shared grammar for endpoint and message IDs.
package identifier

// Valid reports whether value is 1-64 ASCII letters, digits, dots, underscores,
// colons, or hyphens. The same grammar applies at the CLI and wire boundaries.
func Valid(value string) bool {
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
