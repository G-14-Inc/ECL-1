package validator

import (
	"encoding/json"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"
)

var testOptions = Options{KnownExtensions: map[string]map[int]bool{
	"ecl.ext.consequence-coupling.v1": {1: true},
}}

func TestValidateStrictJSONIsExpectationBlind(t *testing.T) {
	findings, err := Validate([]byte(`{"a":1,"a":2}`), testOptions)
	assertOnlyRule(t, findings, err, "ecl.rule.json-no-duplicate-members.v1")
}

func TestValidateDCMPSemantics(t *testing.T) {
	cases := []struct {
		name string
		json string
		rule string
	}{
		{
			name: "admit without authority",
			json: `{"protocol":"DCMP-2","message_id":"m","message_type":"decision_response","outcome":"admit","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:00:01Z","workflow":{"causal_predecessors":[]},"extensions":[]}`,
			rule: RuleAdmitAuthority,
		},
		{
			name: "deny with authority",
			json: `{"protocol":"DCMP-2","message_id":"m","message_type":"decision_response","outcome":"deny","authorization":{"authorization_id":"a"},"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:00:01Z","workflow":{"causal_predecessors":[]},"extensions":[]}`,
			rule: RuleNonAdmitAuthority,
		},
		{
			name: "self causation",
			json: `{"protocol":"DCMP-2","message_id":"m","message_type":"decision_request","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:00:01Z","workflow":{"causal_predecessors":[{"id":"m"}]},"extensions":[]}`,
			rule: RuleNoSelfCausation,
		},
		{
			name: "unknown critical extension",
			json: `{"protocol":"DCMP-2","message_id":"m","message_type":"decision_request","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:00:01Z","workflow":{"causal_predecessors":[]},"extensions":[{"id":"ecl.ext.unknown.v1","version":1,"critical":true}]}`,
			rule: RuleUnknownCritical,
		},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			findings, err := Validate([]byte(current.json), testOptions)
			assertOnlyRule(t, findings, err, current.rule)
		})
	}
}

func TestValidateAdapterBodyDigest(t *testing.T) {
	body := map[string]any{
		"schema_version": "ecl_adapter_binding_v1",
		"source":         map[string]any{"retained": true},
		"ecl_objects": []any{
			map[string]any{"object_id": "https://externalcontrollayer.ai/ns/object/1"},
		},
		"field_accounting": []any{
			map[string]any{
				"source_path":  "/x",
				"disposition":  "mapped",
				"target_paths": []any{"/0/x"},
			},
		},
		"loss_class": "lossless",
		"authority_boundary": map[string]any{
			"native_authoritative_for_effects":     true,
			"ecl_is_portable_evidence_only":        true,
			"inbound_requires_native_reevaluation": true,
			"conflict_disposition":                 "fail_closed_no_release",
		},
		"responsibility_coverage": coverage("https://externalcontrollayer.ai/ns/object/1"),
	}
	digest, err := canonical.Digest(body)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	body["binding_digest"] = map[string]any{
		"algorithm": "ecl.digest.sha-256.v1",
		"value":     digest,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	findings, err := Validate(payload, testOptions)
	if err != nil || len(findings) != 0 {
		t.Fatalf("Validate(valid adapter) = %#v, %v", findings, err)
	}
	body["binding_digest"].(map[string]any)["value"] = "0000000000000000000000000000000000000000000000000000000000000000"
	payload, _ = json.Marshal(body)
	findings, err = Validate(payload, testOptions)
	assertOnlyRule(t, findings, err, RuleAdapterBinding)
}

func TestValidateBundleRules(t *testing.T) {
	released := record("released", "r1", 5, nil)
	releasedDigest, _ := canonical.Digest(released)
	running := record("running", "r2", 6, predecessor("r1", releasedDigest))
	runningDigest, _ := canonical.Digest(running)
	terminal := record("succeeded", "r3", 7, predecessor("r2", runningDigest))

	valid := bundle(released, running, terminal)
	findings, err := Validate(valid, testOptions)
	if err != nil || len(findings) != 0 {
		t.Fatalf("Validate(valid bundle) = %#v, %v", findings, err)
	}

	badDigest := record("succeeded", "r3", 7, predecessor("r2", "0000000000000000000000000000000000000000000000000000000000000000"))
	findings, err = Validate(bundle(released, running, badDigest), testOptions)
	assertOnlyRule(t, findings, err, RulePredecessorDigest)

	badSequence := record("succeeded", "r3", 6, predecessor("r2", runningDigest))
	findings, err = Validate(bundle(released, running, badSequence), testOptions)
	assertOnlyRule(t, findings, err, RuleBundleSequence)

	revived := record("running", "r4", 8, predecessor("r3", mustDigest(t, terminal)))
	findings, err = Validate(bundle(released, running, terminal, revived), testOptions)
	assertOnlyRule(t, findings, err, RuleExecutionTransition)
}

func TestValidateLifecycleAndTerminalRecord(t *testing.T) {
	lifecycle := []byte(`{"protocol":"EBMP-2","object_id":"r","event_type":"lifecycle_transition","event":{"kind":"lifecycle","operation":"redact"},"extensions":[]}`)
	findings, err := Validate(lifecycle, testOptions)
	assertOnlyRule(t, findings, err, RuleLifecycleDerivative)

	terminal := []byte(`{"protocol":"EBMP-2","object_id":"r","event_type":"execution_terminal","event":{"kind":"execution","state":"running"},"extensions":[]}`)
	findings, err = Validate(terminal, testOptions)
	assertOnlyRule(t, findings, err, RuleTerminalState)
}

func coverage(objectID string) map[string]any {
	result := map[string]any{}
	for _, name := range []string{"Decision", "Authority", "Enforcement", "Provenance", "Verification", "Fleet"} {
		result[name] = map[string]any{
			"status":     "not_applicable",
			"object_ids": []any{},
		}
	}
	result["Decision"] = map[string]any{
		"status":     "represented",
		"object_ids": []any{objectID},
	}
	return result
}

func record(state, id string, sequence int, predecessors []any) map[string]any {
	if predecessors == nil {
		predecessors = []any{}
	}
	eventType := "execution_observed"
	if terminalState(state) {
		eventType = "execution_terminal"
	}
	return map[string]any{
		"protocol":   "EBMP-2",
		"object_id":  id,
		"event_type": eventType,
		"event": map[string]any{
			"kind":       "execution",
			"attempt_id": "attempt-1",
			"state":      state,
		},
		"workflow": map[string]any{
			"workflow_id":         "workflow-1",
			"root_trace_id":       "trace-1",
			"sequence":            sequence,
			"causal_predecessors": predecessors,
		},
		"extensions": []any{},
	}
}

func predecessor(id, digest string) []any {
	return []any{map[string]any{
		"id": id,
		"digest": map[string]any{
			"algorithm": "ecl.digest.sha-256.v1",
			"value":     digest,
		},
	}}
}

func bundle(records ...map[string]any) []byte {
	items := make([]any, len(records))
	for index, record := range records {
		items[index] = record
	}
	payload, err := json.Marshal(map[string]any{"records": items})
	if err != nil {
		panic(err)
	}
	return payload
}

func mustDigest(t *testing.T, value any) string {
	t.Helper()
	result, err := canonical.Digest(value)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	return result
}

func assertOnlyRule(t *testing.T, findings []Finding, err error, rule string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != rule {
		t.Fatalf("Validate() findings = %#v; want only %s", findings, rule)
	}
}
