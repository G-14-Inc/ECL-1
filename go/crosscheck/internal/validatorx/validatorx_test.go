package validatorx

import "testing"

func TestRequiredProofOutsideStrictProfile(t *testing.T) {
	doc := map[string]any{"profile_id": "urn:example:ordinary", "dependencies": []any{map[string]any{"supplies_required_proof": true, "loss_disposition": "degraded"}}}
	findings := Validate(doc)
	if len(findings) != 1 || findings[0].RuleID != ProofRule {
		t.Fatalf("required proof: %v", findings)
	}
	doc["dependencies"] = []any{map[string]any{"supplies_required_proof": true, "loss_disposition": "quarantine"}}
	if findings := Validate(doc); len(findings) != 0 {
		t.Fatalf("safe disposition: %v", findings)
	}
}

func strict() []any { return []any{StrictProfile} }

func TestEveryStrictDisposition(t *testing.T) {
	for _, field := range []string{"timeout_disposition", "dependency_disposition", "stale_dependency_disposition", "buffer_exhaustion_disposition"} {
		doc := map[string]any{"claimed_profiles": strict(), "action_classes": []any{map[string]any{field: "fail_open"}}}
		if f := Validate(doc); len(f) != 1 || f[0].RuleID != StrictRule {
			t.Fatalf("%s: %v", field, f)
		}
	}
	doc := map[string]any{"claimed_profiles": strict(), "evidence_buffer": map[string]any{"overflow": "fail_open"}}
	if f := Validate(doc); len(f) != 1 || f[0].RuleID != StrictRule {
		t.Fatal(f)
	}
}

func TestTheClaimNotTheNameMakesAProfileStrict(t *testing.T) {
	open := map[string]any{"overflow": "fail_open"}
	for _, name := range []string{"urn:example:profile:STRICT-FAILURE-1", "urn:example:profile:strict-failure-pilot"} {
		doc := map[string]any{"profile_id": name, "claimed_profiles": []any{}, "evidence_buffer": open}
		if f := Validate(doc); len(f) != 0 {
			t.Fatalf("%s without a claim: %v", name, f)
		}
	}
	doc := map[string]any{"profile_id": "urn:example:profile:not-strict", "claimed_profiles": strict(), "evidence_buffer": open}
	if f := Validate(doc); len(f) != 1 || f[0].RuleID != StrictRule {
		t.Fatalf("claimed profile: %v", f)
	}
}
