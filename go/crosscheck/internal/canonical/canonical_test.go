package canonical

import (
	"encoding/json"
	"testing"
)

func TestMarshalOrdersAndEscapesDeterministically(t *testing.T) {
	value := map[string]any{
		"b": json.Number("2"),
		"a": "<>&\n",
	}
	encoded, err := Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	const want = `{"a":"<>&\n","b":2}`
	if string(encoded) != want {
		t.Fatalf("Marshal() = %s; want %s", encoded, want)
	}
}

func TestMarshalUsesUTF16KeyOrder(t *testing.T) {
	value := map[string]any{
		"\uE000":     2,
		"\U0001F600": 1,
	}
	encoded, err := Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	const want = "{\"😀\":1,\"\":2}"
	if string(encoded) != want {
		t.Fatalf("Marshal() = %q; want %q", encoded, want)
	}
}

func TestDigestIsStableAcrossInsertionOrder(t *testing.T) {
	first := map[string]any{"a": 1, "b": []any{true, nil}}
	second := map[string]any{"b": []any{true, nil}, "a": 1}
	left, err := Digest(first)
	if err != nil {
		t.Fatalf("Digest(first) error = %v", err)
	}
	right, err := Digest(second)
	if err != nil {
		t.Fatalf("Digest(second) error = %v", err)
	}
	if left != right {
		t.Fatalf("digests differ: %s != %s", left, right)
	}
}

func TestMarshalRejectsNonIntegerNumber(t *testing.T) {
	if _, err := Marshal(json.Number("1.25")); err == nil {
		t.Fatal("Marshal() accepted floating-point number")
	}
}
