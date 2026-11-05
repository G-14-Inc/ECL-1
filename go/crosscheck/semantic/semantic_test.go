package semantic_test

import (
	"fmt"
	"slices"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/corpus"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func ids(findings []semantic.Finding) map[string]bool {
	found := map[string]bool{}
	for _, item := range findings {
		found[item.RuleID] = true
	}
	return found
}

// Every rule vector of the foundation, control-extension and schema-coverage suites yields its
// expected rule, the decision-basis vectors included; every passing vector yields no finding. A
// vector of a corpus capability that this module did not implement would be skipped here, as the
// corpus runner would report it as unsupported.
func TestRuleVectors(t *testing.T) {
	options := semantic.Registered()
	capabilities := vectors.Capabilities(t)
	checked := 0
	for _, name := range []string{"foundation", "control-extensions", "schema-coverage"} {
		for _, vector := range vectors.Suite(t, name).Vectors {
			if vector.Stage != "semantic" && vector.Stage != "protocol" {
				continue
			}
			if !slices.Contains(corpus.Capabilities, capabilities[vector.ID]) {
				continue
			}
			findings, err := semantic.ValidateBytes(vectors.Read(t, vector.Path), options)
			if err != nil {
				t.Fatalf("%s: %v", vector.ID, err)
			}
			found := ids(findings)
			switch {
			case vector.Expected == "pass" && len(findings) > 0:
				t.Errorf("%s: %v", vector.ID, findings)
			case vector.Expected == "fail" && vector.Primary != "ecl.error.schema-invalid.v1" && !found[vector.Primary]:
				t.Errorf("%s: %v lacks %s", vector.ID, findings, vector.Primary)
			}
			checked++
		}
	}
	if checked < 100 {
		t.Fatalf("only %d vectors", checked)
	}
}

// The RC-4 divergence: an EBMP-2 bundle manifest has a records member of references and is
// classified by its protocol, not read as a bare bundle.
func TestBundleManifestIsClassifiedByProtocol(t *testing.T) {
	findings, err := semantic.ValidateBytes(vectors.Read(t, "conformance/suites/schema-coverage/ebmp-valid-bundle-manifest.json"), semantic.Registered())
	if err != nil || len(findings) != 0 {
		t.Fatalf("%v %v", findings, err)
	}
}

func TestSafeStateProfiles(t *testing.T) {
	for _, vector := range vectors.Suite(t, "strict-failure").Vectors {
		if vector.Stage != "safe-state-profile" {
			continue
		}
		value, err := strict.Parse(vectors.Read(t, vector.Path))
		if err != nil {
			t.Fatal(err)
		}
		found := ids(semantic.SafeStateProfile(value))
		if vector.Expected == "pass" && len(found) > 0 || vector.Expected == "fail" && vector.Primary != "ecl.error.schema-invalid.v1" && !found[vector.Primary] {
			t.Errorf("%s: %v", vector.ID, found)
		}
	}
}

func TestMalformedExtensionValuesAreSchemaInvalid(t *testing.T) {
	value, err := strict.Parse([]byte(`{"protocol": "EBMP-2", "event_type": "human_intervention", "event": {"operation": ["approve"], "issued_at": "2026-01-01T00:00:00Z"}, "extensions": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if found := ids(semantic.Extensions(value, semantic.Registered())); !found[semantic.SchemaInvalid] {
		t.Fatalf("%v", found)
	}
}

func ExampleValidateBytes() {
	findings, _ := semantic.ValidateBytes([]byte(`{"records": [{"object_id": "a"}, {"object_id": "a"}]}`), semantic.Registered())
	for _, finding := range findings {
		fmt.Println(finding.RuleID)
	}
	// Output: ecl.rule.bundle-object-identifiers-unique.v1
}
