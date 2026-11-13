package evidence

import (
	"encoding/json"
	"testing"
)

func TestSingleUseLimitRejectsUnsupportedAuthority(t *testing.T) {
	for _, item := range []struct {
		name, policy   string
		maximum        any
		present, valid bool
	}{
		{"single-absent", "single_use", nil, false, true}, {"single-one", "single_use", json.Number("1"), true, true},
		{"bounded-two", "bounded_multi_use", json.Number("2"), true, false}, {"bounded-absent", "bounded_multi_use", nil, false, false},
		{"single-two", "single_use", json.Number("2"), true, false}, {"single-boolean", "single_use", true, true, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			auth := map[string]any{"use_policy": item.policy}
			if item.present {
				auth["max_uses"] = item.maximum
			}
			response := map[string]any{"authorization": auth}
			limit, supported := useLimit(response)
			if supported != item.valid || supported && limit != 1 {
				t.Fatalf("got %d,%v", limit, supported)
			}
			consumed := []authorityUse{{event: &entry{index: 0, payload: map[string]any{"event": map[string]any{"authorization_id": "urn:example:authority", "use_count": json.Number("1")}}}, response: &entry{index: 1, payload: response}}}
			var found []BundleFinding
			checkUseCounts(consumed, &found)
			if item.valid && len(found) != 0 || !item.valid && (len(found) != 1 || found[0].Code != DecisionBindingInvalid) {
				t.Fatalf("findings: %v", found)
			}
		})
	}
}
