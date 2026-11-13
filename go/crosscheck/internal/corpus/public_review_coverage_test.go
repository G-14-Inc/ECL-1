package corpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

func TestPublicReviewCoverageWitnesses(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "conformance/suites/repair-coverage/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []Vector `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, vector := range manifest.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, vector.Path))
			if err != nil {
				t.Fatal(err)
			}
			// Match Run's registered extension context for protocol-stage witnesses.
			found, err := Evaluate(data, vector, context())
			if err != nil {
				t.Fatal(err)
			}
			expected := []string{}
			if vector.Expected == "fail" {
				expected = append(append(expected, vector.Primary), vector.Secondary...)
			}
			slices.Sort(found)
			slices.Sort(expected)
			if !slices.Equal(found, expected) {
				t.Fatalf("got %v want %v", found, expected)
			}
		})
	}
}

func TestProtocolCoverageWitnessUsesRegisteredExtensionSchema(t *testing.T) {
	for _, item := range []struct {
		name string
		want []string
	}{
		{"repair-coverage-acs-modify-digest-control", []string{}},
		{"repair-coverage-acs-modify-without-digest", []string{semantic.RuleExtensionValue}},
	} {
		t.Run(item.name, func(t *testing.T) {
			local := context()
			data, err := os.ReadFile(filepath.Join(local.Root, "conformance/suites/repair-coverage", item.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			vector := Vector{Stage: "protocol", Schema: dcmpSchema}
			value, err := vector.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			// The outer protocol schema permits extension values. The registered
			// value schema, not a core DCMP shape failure, rejects the missing digest.
			outer, err := schema.ECL().Errors(dcmpSchema, value, 1)
			if err != nil || len(outer) != 0 {
				t.Fatalf("outer schema: %v, %v", outer, err)
			}
			direct, err := semantic.ValidateBytes(data, semantic.Registered())
			if err != nil {
				t.Fatal(err)
			}
			ids := ruleIDs(direct, func(item semantic.Finding) string { return item.RuleID })
			found, err := Evaluate(data, vector, local)
			if err != nil || !slices.Equal(ids, item.want) || !slices.Equal(found, item.want) {
				t.Fatalf("direct=%v protocol=%v want=%v err=%v", ids, found, item.want, err)
			}
		})
	}
}
