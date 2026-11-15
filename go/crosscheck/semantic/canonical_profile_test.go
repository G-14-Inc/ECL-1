package semantic_test

import (
	"crypto/sha256"
	"encoding/hex"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"slices"
	"testing"
)

func TestDirectSemanticParametersUseRestrictedCanonicalProfile(t *testing.T) {
	for _, c := range []struct {
		name       string
		parameters any
		text       string
		bad        bool
	}{
		{"safe", map[string]any{"n": int64(9007199254740991)}, `{"n":9007199254740991}`, false},
		{"unsafe", map[string]any{"n": int64(9007199254740992)}, `{"n":9007199254740992}`, true},
		{"noncharacter", map[string]any{"s": "\uFFFE"}, "{\"s\":\"\uFFFE\"}", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			value := reviewRequest(t)
			action := value["action"].(map[string]any)
			digest := sha256.Sum256([]byte(c.text))
			action["parameters"] = c.parameters
			action["parameters_digest"] = map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": hex.EncodeToString(digest[:])}
			found, err := semantic.Validate(value, semantic.Registered())
			if err != nil {
				t.Fatal(err)
			}
			refused := slices.ContainsFunc(found, func(f semantic.Finding) bool { return f.RuleID == "ecl.rule.parameters-digest-matches.v1" })
			if refused != c.bad || (!c.bad && len(found) != 0) {
				t.Fatalf("findings: %v", found)
			}
		})
	}
}
