// Package canon serializes JSON values in the canonical form that ECL-1 digests and signatures
// cover (RFC 8785 restricted to integers, with no noncharacter in a string or member name):
// members ordered by UTF-16 code units, no insignificant whitespace, and the shortest string
// escapes.
package canon

import (
	"encoding/json"
	"fmt"
	"math/big"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"
)

// DigestAlgorithm is the registered identifier of the digest that Digest computes.
const DigestAlgorithm = "ecl.digest.sha-256.v1"

// maxExact is 2^53 - 1, the largest integer that every JSON implementation reads exactly.
var maxExact = big.NewInt(1<<53 - 1)

// checkString refuses a string or member name that is not UTF-8 or that holds a Unicode
// noncharacter, which the restricted profile excludes (IE1-002), as the reference's canonicalize
// does: content that holds one lies outside the profile.
func checkString(text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("canonical string is not UTF-8")
	}
	for _, code := range text {
		if (code >= 0xFDD0 && code <= 0xFDEF) || code&0xFFFE == 0xFFFE {
			return fmt.Errorf("canonical string holds the Unicode noncharacter U+%04X", code)
		}
	}
	return nil
}

func checkNumbers(value any) error {
	switch current := value.(type) {
	case string:
		return checkString(current)
	case json.Number:
		integer, ok := new(big.Int).SetString(current.String(), 10)
		if !ok {
			return fmt.Errorf("canonical number is not an integer: %q", current.String())
		}
		if new(big.Int).Abs(integer).Cmp(maxExact) > 0 {
			return fmt.Errorf("canonical integer is outside the exact range: %s", current.String())
		}
	case int:
		return checkNumbers(json.Number(fmt.Sprint(current)))
	case int64:
		return checkNumbers(json.Number(fmt.Sprint(current)))
	case uint64:
		return checkNumbers(json.Number(fmt.Sprint(current)))
	case []any:
		for _, item := range current {
			if err := checkNumbers(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for name, item := range current {
			if err := checkString(name); err != nil {
				return err
			}
			if err := checkNumbers(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// Marshal returns the canonical bytes of value. It accepts the values that strict.Parse returns
// and refuses any number that is not an integer within plus or minus 2^53 - 1.
func Marshal(value any) ([]byte, error) {
	if err := checkNumbers(value); err != nil {
		return nil, err
	}
	return canonical.Marshal(value)
}

// Digest returns the lowercase hexadecimal SHA-256 of the canonical bytes of value.
func Digest(value any) (string, error) {
	if err := checkNumbers(value); err != nil {
		return "", err
	}
	return canonical.Digest(value)
}

// Reference returns the digest object that ECL objects use to name value:
// {"algorithm": "ecl.digest.sha-256.v1", "value": <Digest(value)>}.
func Reference(value any) (map[string]any, error) {
	digest, err := Digest(value)
	if err != nil {
		return nil, err
	}
	return map[string]any{"algorithm": DigestAlgorithm, "value": digest}, nil
}
