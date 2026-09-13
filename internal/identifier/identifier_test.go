package identifier

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for _, value := range []string{"a", "A0._:-", strings.Repeat("x", 64)} {
		if !Valid(value) {
			t.Errorf("rejected valid identifier %q", value)
		}
	}
	for _, value := range []string{"", strings.Repeat("x", 65), "a/b", "a\\b", "a b", "a\x00b", "é", "a\n", "a\t"} {
		if Valid(value) {
			t.Errorf("accepted invalid identifier %q", value)
		}
	}
}
