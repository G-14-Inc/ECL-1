package corpus

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"testing"
)

var observationNames = []string{"observed_verdict", "observed_scope", "observed_effects", "observed_unresolved_predecessor_ids", "observed_canonical_sha256"}

func observationVector() Vector {
	unresolved := []string{}
	return Vector{ExpectedVerdict: "verified", CanonicalHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedScope: &ExpectedScope{}, ExpectedEffects: []ExpectedEffect{{ActionID: "urn:test:action", Level: "none"}}, ExpectedUnresolved: &unresolved}
}

func encodedObservations(t *testing.T, result Result) map[string]any {
	t.Helper()
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]any
	if err := json.Unmarshal(b, &all); err != nil {
		t.Fatal(err)
	}
	return all
}

func TestObservationUnavailableIsExplicitNull(t *testing.T) {
	result := Result{Status: "not-met"}
	recordObservations(&result, observationVector(), "", nil, "")
	encoded := encodedObservations(t, result)
	for _, name := range observationNames {
		value, exists := encoded[name]
		if !exists || value != nil {
			t.Fatalf("%s: want present null, got %#v (present %v)", name, value, exists)
		}
	}
}

func TestObservationUndeclaredAndUnsupportedAreOmitted(t *testing.T) {
	for _, item := range []struct {
		name   string
		vector Vector
		status string
	}{
		{"undeclared", Vector{}, "met"}, {"unsupported", observationVector(), "unsupported"},
	} {
		t.Run(item.name, func(t *testing.T) {
			result := Result{Status: item.status}
			recordObservations(&result, item.vector, "verified", &evidence.Report{}, "digest")
			encoded := encodedObservations(t, result)
			for _, name := range observationNames {
				if _, exists := encoded[name]; exists {
					t.Fatalf("unexpected %s", name)
				}
			}
		})
	}
}

func TestObservedEmptyCollectionsRemainEmptyCollections(t *testing.T) {
	result := Result{Status: "not-met"}
	recordObservations(&result, observationVector(), "invalid", &evidence.Report{}, "")
	encoded := encodedObservations(t, result)
	if encoded["observed_verdict"] != "invalid" {
		t.Fatal("expected verdict was substituted for observed verdict")
	}
	for _, name := range []string{"observed_effects", "observed_unresolved_predecessor_ids"} {
		value, ok := encoded[name].([]any)
		if !ok || len(value) != 0 {
			t.Fatalf("%s must be an empty array", name)
		}
	}
	scope := encoded["observed_scope"].(map[string]any)
	for _, name := range []string{"established", "not_established"} {
		value, ok := scope[name].([]any)
		if !ok || len(value) != 0 {
			t.Fatalf("scope %s must be an empty array", name)
		}
	}
	reasons, ok := scope["reasons"].(map[string]any)
	if !ok || len(reasons) != 0 {
		t.Fatal("empty reasons must be an object")
	}
}
