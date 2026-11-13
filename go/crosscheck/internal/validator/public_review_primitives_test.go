package validator

import (
	"encoding/json"
	"testing"
)

func TestPublicReviewROOT011AccumulatesExtensionFindings(t *testing.T) {
	extension := func(id string, critical bool) map[string]any {
		return map[string]any{"id": id, "version": json.Number("1"), "critical": critical}
	}
	duplicate := extension("urn:example:tag", false)
	unknown := extension("urn:example:unknown", true)
	for _, entries := range [][]any{{duplicate, duplicate, unknown}, {unknown, duplicate, duplicate}} {
		found := validateExtensions(map[string]any{"extensions": entries}, Options{})
		rules := map[string]bool{}
		for _, item := range found {
			rules[item.RuleID] = true
		}
		if len(found) != 2 || !rules[RuleExtensionUnique] || !rules[RuleUnknownCritical] {
			t.Fatal(found)
		}
	}
}
