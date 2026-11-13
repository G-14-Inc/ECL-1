package validatorx

import (
	"encoding/json"
	"testing"
)

func TestCoreSelfCausationStringIdentityDomain(t *testing.T) {
	for _, protocol := range []string{"DCMP-2", "EBMP-2"} {
		identityMember := "message_id"
		if protocol == "EBMP-2" {
			identityMember = "object_id"
		}
		for _, own := range []any{"urn:example:message:self", json.Number("1e4301")} {
			root := map[string]any{"protocol": protocol, identityMember: own, "workflow": map[string]any{"causal_predecessors": []any{map[string]any{"id": json.Number("1e4301")}}}}
			if found := SelfCausation(root); len(found) != 0 {
				t.Errorf("wrong-typeidentity needs schema, not self finding: %v", found)
			}
		}
	}
}
