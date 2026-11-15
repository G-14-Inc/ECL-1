// Package canon serializes JSON values in the canonical form that ECL-1 digests and signatures
// cover (RFC 8785 restricted to integers, with no noncharacter in a string or member name):
// members ordered by UTF-16 code units, no insignificant whitespace, and the shortest string
// escapes.
package canon

import "externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"

// DigestAlgorithm is the registered identifier of the digest that Digest computes.
const DigestAlgorithm = "ecl.digest.sha-256.v1"

// The canonical producer limits (IE1-028): top-level depth zero, all values including
// containers, and the exact encoded output size. Every internal digest uses the same guard.
const (
	MaxDepth = canonical.MaxDepth
	MaxNodes = canonical.MaxNodes
	MaxBytes = canonical.MaxBytes
)

// Marshal returns the canonical bytes of value. It accepts the values that strict.Parse returns
// within the declared producer limits and refuses any number that is not an integer within
// plus or minus 2^53 - 1. Unsupported types, invalid strings and cyclic values are refused.
func Marshal(value any) ([]byte, error) {
	return canonical.Marshal(value)
}

// Digest returns the lowercase hexadecimal SHA-256 of the canonical bytes of value.
func Digest(value any) (string, error) {
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
