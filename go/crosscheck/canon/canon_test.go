package canon_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func TestCanonicalSuite(t *testing.T) {
	for _, vector := range vectors.Suite(t, "canonical").Vectors {
		value, err := strict.Parse(vectors.Read(t, vector.Path))
		if vector.Expected == "fail" {
			var refusal *strict.Error
			if !errors.As(err, &refusal) || refusal.RuleID != vector.Primary {
				t.Errorf("%s: %v", vector.ID, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		digest, err := canon.Digest(value)
		if err != nil || digest != vector.CanonicalHash {
			t.Errorf("%s: %s %v", vector.ID, digest, err)
		}
	}
}

func TestMemberOrderIsByUTF16CodeUnits(t *testing.T) {
	value, err := strict.Parse([]byte(`{"\u20ac":1,"\r":2,"\ufb33":3,"1":4,"\ud83d\ude00":5,"\u0080":6,"\u00f6":7}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canon.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\r\":2,\"1\":4,\"\u0080\":6,\"\u00f6\":7,\"\u20ac\":1,\"\U0001F600\":5,\"\ufb33\":3}"
	if string(encoded) != want {
		t.Fatalf("got %s", encoded)
	}
}

func TestOnlyExactIntegers(t *testing.T) {
	for _, value := range []any{json.Number("9007199254740992"), json.Number("1.5"), int64(1 << 53), []any{json.Number("-9007199254740992")}} {
		if _, err := canon.Marshal(value); err == nil {
			t.Errorf("accepted %v", value)
		}
	}
	if encoded, err := canon.Marshal([]any{json.Number("-9007199254740991"), int64(1<<53 - 1)}); err != nil || string(encoded) != "[-9007199254740991,9007199254740991]" {
		t.Fatalf("%s %v", encoded, err)
	}
}

// TestNoncharactersAreOutsideTheRestrictedProfile: the restricted profile
// excludes the 66 Unicode noncharacters from strings and member names (IE1-002), as the reference's
// canonicalize does, so content that holds one has no restricted canonical form and an exchange
// record holds it in the encoded form of MG1-012. A string that is not UTF-8, such as a lone
// surrogate in the WTF-8 form that ParseJWSJSON can return, has none either.
func TestNoncharactersAreOutsideTheRestrictedProfile(t *testing.T) {
	for _, code := range []rune{0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x1FFFF, 0x10FFFE, 0x10FFFF} {
		text := "id-" + string(code)
		for _, value := range []any{text, []any{"a", text}, map[string]any{"id": text}, map[string]any{text: json.Number("1")}} {
			if _, err := canon.Marshal(value); err == nil {
				t.Errorf("U+%04X: accepted %v", code, value)
			}
			if _, err := canon.Digest(value); err == nil {
				t.Errorf("U+%04X: digest of %v", code, value)
			}
		}
	}
	for _, code := range []rune{0xFDCF, 0xFDF0, 0xFFFD, 0x10000, 0x1FFFD, 0x10FFFD} {
		text := "id-" + string(code)
		if _, err := canon.Marshal(map[string]any{text: text}); err != nil {
			t.Errorf("U+%04X: %v", code, err)
		}
	}
	for _, text := range []string{"\xed\xa0\x80", "\xff"} {
		if _, err := canon.Marshal(map[string]any{"id": text}); err == nil {
			t.Errorf("accepted the bytes %q", text)
		}
		if _, err := canon.Marshal(map[string]any{text: "id"}); err == nil {
			t.Errorf("accepted the member name %q", text)
		}
	}
}

func ExampleDigest() {
	value, _ := strict.Parse([]byte(`{"b": [1, 2], "a": "x"}`))
	encoded, _ := canon.Marshal(value)
	digest, _ := canon.Digest(value)
	fmt.Println(string(encoded))
	fmt.Println(digest)
	// Output:
	// {"a":"x","b":[1,2]}
	// 721ef82f2d6c0997bffb7a8ab3f40f8fb45b0b52ce2af3afa6b0f05efbdc317f
}
