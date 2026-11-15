package bindings_test

import (
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/bindings"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func TestBindingSchemaBoundaries(t *testing.T) {
	for _, family := range []string{"aarm-binding", "acs-binding", "mcp-gateway", "otel-export", "oauth-authority"} {
		t.Run(family, func(t *testing.T) {
			var selected *vectors.Vector
			for _, row := range vectors.Suite(t, family).Vectors {
				if row.Expected == "pass" && row.Stage == "binding" {
					selected = &row
					break
				}
			}
			if selected == nil {
				t.Fatal("missing valid binding control")
			}
			value, err := strict.Parse(vectors.Read(t, selected.Path))
			if err != nil {
				t.Fatal(err)
			}
			findings, err := bindings.EvaluateRecord(selected.Schema, value)
			if err != nil || len(findings) != 0 {
				t.Fatalf("valid control: %v %v", findings, err)
			}
			empty := map[string]any{"schema_version": value.(map[string]any)["schema_version"]}
			findings, err = bindings.EvaluateRecord(selected.Schema, empty)
			if err != nil || len(findings) == 0 {
				t.Fatalf("incomplete profile record: %v %v", findings, err)
			}
			for _, schemaID := range []string{"https://externalcontrollayer.ai/ns/schema/common/1", "urn:example:unknown"} {
				for _, input := range []any{empty, nil} {
					if findings, err := bindings.EvaluateRecord(schemaID, input); err == nil {
						t.Fatalf("unsupported schema %s returned %v without error", schemaID, findings)
					}
				}
			}
		})
	}
}
