package envelope_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func TestDirectTrustNanosecondBoundaries(t *testing.T) {
	const keyID = "urn:example:key:vector-ed"
	const boundary = "2026-11-10T12:00:00.000000500Z"
	for _, kind := range []string{"from", "until", "revocation"} {
		for _, offset := range []int{-1, 0, 1} {
			for _, own := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/%t", kind, offset, own), func(t *testing.T) {
					policy, err := trust.Load(vectors.Read(t, "conformance/suites/envelope/trust-policy.json"))
					if err != nil {
						t.Fatal(err)
					}
					at := fmt.Sprintf("2026-11-10T12:00:00.%09dZ", 500+offset)
					context, err := policy.VerificationContext(at, "ecl.time.issued-at.v1")
					if err != nil {
						t.Fatal(err)
					}
					if own {
						context.EvaluatedAt = "2026-11-10T12:00:01Z"
						context.KeyTimes = map[string]string{keyID: at}
					}
					keys := policy.Keyring()
					key := keys[keyID]
					expected := ""
					switch kind {
					case "from":
						key.ValidFrom = boundary
						if offset < 0 {
							expected = "ecl.error.expired.v1"
						}
					case "until":
						key.ValidUntil = boundary
						if offset >= 0 {
							expected = "ecl.error.expired.v1"
						}
					case "revocation":
						context.Revocations = []envelope.Revocation{{KeyID: keyID, EffectiveAt: boundary, Reason: "synthetic test"}}
						if offset >= 0 {
							expected = "ecl.error.revoked.v1"
						}
					}
					keys[keyID] = key
					_, err = envelope.Verify(parse(t, "conformance/suites/envelope/envelope-valid-ed25519-signed.json"), keys, context)
					if expected == "" {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					var refusal *envelope.Error
					if !errors.As(err, &refusal) || refusal.Code != expected {
						t.Fatalf("got %v, want %s", err, expected)
					}
				})
			}
		}
	}
}

func TestDirectEd25519TrustKeyDomain(t *testing.T) {
	forged := make([]byte, 64)
	forged[0] = 1
	for index := 0; index < 14; index++ {
		document := parse(t, fmt.Sprintf("conformance/suites/trust-policy/trust-policy-invalid-small-order-%02d.json", index))
		for _, value := range document["keys"].([]any) {
			key := value.(map[string]any)
			if key["key_id"] != "urn:example:key:vector-ed" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(key["public_key"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if envelope.VerifyEd25519(raw, []byte{1, 2, 3}, forged) {
				t.Errorf("key %d accepted a keyless signature", index)
			}
		}
	}
}
