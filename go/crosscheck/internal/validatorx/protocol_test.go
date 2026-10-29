package validatorx

import (
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
)

func rules(findings []validator.Finding) []string {
	ids := []string{}
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}

func TestParametersDigest(t *testing.T) {
	parameters := map[string]any{"amount": "1.00"}
	digest, err := canonical.Digest(parameters)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"protocol": "DCMP-2", "message_type": "decision_request", "action": map[string]any{
		"parameters": parameters, "parameters_digest": map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": digest},
	}}
	if f := Protocol(request, validator.Options{}); len(f) != 0 {
		t.Fatalf("matching digest: %v", f)
	}
	request["action"].(map[string]any)["parameters_digest"] = map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": "00"}
	if f := rules(Protocol(request, validator.Options{})); len(f) != 1 || f[0] != RuleParametersDigest {
		t.Fatalf("mismatched digest: %v", f)
	}
}

func TestEmergencyPlaneAndNamespace(t *testing.T) {
	control := map[string]any{"protocol": "DCMP-2", "message_type": "control", "operation": "halt",
		"authority":  map[string]any{"plane": "ordinary"},
		"extensions": []any{map[string]any{"id": "ecl.ext.unallocated.v1"}, map[string]any{"id": "https://example.com/ext/v1"}}}
	got := rules(Protocol(control, validator.Options{}))
	if len(got) != 2 || got[0] != RuleExtensionNamespace || got[1] != RuleEmergencyPlane {
		t.Fatalf("findings: %v", got)
	}
}

func TestEventKindAndState(t *testing.T) {
	record := map[string]any{"protocol": "EBMP-2", "object_type": "event_record", "event_type": "decision_recorded",
		"event": map[string]any{"kind": "execution", "state": "running"}}
	if f := rules(Protocol(record, validator.Options{})); len(f) != 1 || f[0] != RuleEventKind {
		t.Fatalf("kind: %v", f)
	}
	record["event_type"] = "execution_released"
	if f := rules(Protocol(record, validator.Options{})); len(f) != 1 || f[0] != RuleEventKind {
		t.Fatalf("state: %v", f)
	}
	record["event"] = map[string]any{"kind": "execution", "state": "released"}
	if f := Protocol(record, validator.Options{}); len(f) != 0 {
		t.Fatalf("consistent: %v", f)
	}
}
