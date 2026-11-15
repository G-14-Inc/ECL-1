package envelope_test

import (
	"errors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
	"testing"
)

func TestSignatureIdentityBoundaries(t *testing.T) {
	doc := parse(t, "tests/fixtures/identity-boundaries/cases.json")
	for _, value := range doc["envelopes"].([]any) {
		row := value.(map[string]any)
		t.Run(row["name"].(string), func(t *testing.T) {
			document := parse(t, "conformance/suites/envelope/envelope-valid-ed25519-signed.json")
			entries := document["signatures"].([]any)
			entry := entries[0].(map[string]any)
			switch row["operation"] {
			case "duplicate":
				document["signatures"] = append(entries, entry)
			case "remove":
				delete(entry, row["member"].(string))
			case "replace":
				entry[row["member"].(string)] = row["value"]
			case "object-pair":
				entry["key_id"] = map[string]any{"b": 1, "1": 1}
				other := map[string]any{}
				for k, v := range entry {
					other[k] = v
				}
				other["key_id"] = map[string]any{"1": 1, "b": 1}
				document["signatures"] = append(entries, other)
			}
			policy, err := trust.Load(vectors.Read(t, "conformance/suites/envelope/trust-policy.json"))
			if err != nil {
				t.Fatal(err)
			}
			context, err := policy.VerificationContext("2026-11-10T12:00:00Z", "ecl.time.issued-at.v1")
			if err != nil {
				t.Fatal(err)
			}
			_, err = envelope.Verify(document, policy.Keyring(), context)
			actual := ""
			if err != nil {
				var refusal *envelope.Error
				if !errors.As(err, &refusal) {
					t.Fatal(err)
				}
				actual = refusal.Code
			}
			if actual != row["expected"] {
				t.Fatalf("got %s, want %s", actual, row["expected"])
			}
		})
	}
}
