package schema_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"os"
	"testing"
)

func TestPolicyMetadataContracts(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/policy-metadata-contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID     string `json:"id"`
		Schema string `json:"schema"`
		Value  any    `json:"value"`
		Valid  bool   `json:"valid"`
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile("../../../schemas/ecl-registry-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(metadata, &document); err != nil {
		t.Fatal(err)
	}
	registry, err := schema.NewSet(map[string]any{"https://externalcontrollayer.ai/ns/schema/registry/2": document})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			set := schema.ECL()
			if c.Schema == "https://externalcontrollayer.ai/ns/schema/registry/2" {
				set = registry
			}
			valid, err := set.Valid(c.Schema, c.Value)
			if err != nil || valid != c.Valid {
				t.Errorf("valid=%v want=%v err=%v", valid, c.Valid, err)
			}
		})
	}
}
