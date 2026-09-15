package strictjson

import "testing"

func TestValidateUniqueKeys(t *testing.T) {
	for _, input := range []string{
		`{"a":1,"a":2}`, `{"a":1,"A":2}`, `{"a":1,"\u0061":2}`,
		`{"K":1,"K":2}`, `{"ſ":1,"S":2}`, `[{"nested":{"a":1,"a":2}}]`,
		`{"a":1} {}`, `{"a":`, `{"a":[}`, ``,
	} {
		if err := ValidateUniqueKeys([]byte(input)); err == nil {
			t.Errorf("accepted ambiguous or invalid JSON: %s", input)
		}
	}
	for _, input := range []string{
		`{"a":1,"b":2}`, `[{"a":1},{"a":2}]`, `{"a":{"a":1}}`,
		`{"a":[null,true,"text",1e9999]}`, `[]`, `null`,
	} {
		if err := ValidateUniqueKeys([]byte(input)); err != nil {
			t.Errorf("rejected valid JSON %s: %v", input, err)
		}
	}
}
