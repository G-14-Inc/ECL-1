package evidence_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"strconv"
	"testing"
)

func TestRegisterDeadlineArithmetic(t *testing.T) {
	for _, ms := range []int64{0, 9, 10, 3600000, 9223372036855, 18446744073710, 9007199254740991} {
		t.Run(json.Number(strconv.FormatInt(ms, 10)).String(), func(t *testing.T) {
			const action = "ecl.action.ai-proposed-operation.v1"
			input := map[string]any{"input": "urn:example:input", "class": "verifiable", "source": "urn:example:source", "required": true, "deadline_milliseconds": ms}
			register := map[string]any{"register_id": "urn:example:register", "entries": []any{map[string]any{"action_class_id": action, "decision_inputs": []any{input}}}}
			reference, err := evidence.RegisterReference(register)
			if err != nil {
				t.Fatal(err)
			}
			basis := map[string]any{"register": reference, "received_at": "2026-10-01T00:00:00Z", "inputs": []any{map[string]any{"input": "urn:example:input", "class": "verifiable", "source": "urn:example:source", "required": true, "status": "available", "obtained_at": "2026-10-01T00:00:00.010Z"}}}
			got, err := evidence.RegisterProblems(basis, register, action)
			if err != nil {
				t.Fatal(err)
			}
			late := false
			for _, p := range got {
				if p[0] != "/inputs/0/obtained_at" {
					t.Errorf("unrelated problem %v", p)
				}
				late = late || p[0] == "/inputs/0/obtained_at"
			}
			if late != (ms < 10) {
				t.Errorf("deadline %d ms, got late=%v", ms, late)
			}
		})
	}
}
