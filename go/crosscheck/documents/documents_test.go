package documents_test

import (
	"encoding/json"
	"slices"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// Every document vector of the shared corpus: strict parsing, the schema that the vector names,
// and the rules whose applies_to names the document's type, with the vector's primary and
// secondary findings exactly.
func TestEveryDocumentVector(t *testing.T) {
	checked := 0
	var suite []vectors.Vector
	for _, name := range []string{"document-coverage", "extension-rules"} {
		suite = append(suite, vectors.Suite(t, name).Vectors...)
	}
	for _, vector := range suite {
		if vector.Stage != "document" {
			continue
		}
		if !slices.Contains(documents.Schemas, vector.Schema) {
			t.Errorf("%s: %s is not a document schema", vector.ID, vector.Schema)
		}
		value, err := strict.Parse(vectors.Read(t, vector.Path))
		if err != nil {
			if vector.Expected != "fail" {
				t.Errorf("%s: %v", vector.ID, err)
			}
			checked++
			continue
		}
		findings, err := documents.Evaluate(vector.Schema, value)
		if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		found := []string{}
		for _, item := range findings {
			if !slices.Contains(found, item.RuleID) {
				found = append(found, item.RuleID)
			}
		}
		slices.Sort(found)
		expected := []string{}
		if vector.Expected == "fail" {
			expected = append(append(expected, vector.Primary), vector.Secondary...)
			slices.Sort(expected)
		}
		if !slices.Equal(found, expected) {
			t.Errorf("%s: %v, want %v", vector.ID, found, expected)
		}
		checked++
	}
	if checked < 50 {
		t.Fatalf("only %d vectors", checked)
	}
}

func TestDocumentsAreObjectsOfAKnownSchema(t *testing.T) {
	findings, err := documents.Evaluate(documents.Schemas[0], []any{})
	if err != nil || len(findings) != 1 || findings[0].RuleID != semantic.SchemaInvalid {
		t.Fatalf("%v %v", findings, err)
	}
	if _, err := documents.Evaluate("https://externalcontrollayer.ai/ns/schema/unknown/1", map[string]any{}); err == nil {
		t.Fatal("an unknown schema is accepted")
	}
	for _, identifier := range documents.Schemas {
		if !slices.Contains(schema.ECL().Identifiers(), identifier) {
			t.Errorf("%s is not embedded", identifier)
		}
	}
}

// The extension rules apply to a work intent (ECL-WI-1) whether or not its schema accepts it, and
// no rule applies to a document without a type.
func TestTheExtensionRulesApplyToAWorkIntent(t *testing.T) {
	intent := map[string]any{
		"protocol": "ECL-WI-1",
		"extensions": []any{
			map[string]any{"id": "com.example.tag.v1", "version": json.Number("1"), "critical": false, "value": map[string]any{}},
			map[string]any{"id": "com.example.tag.v1", "version": json.Number("2"), "critical": false, "value": map[string]any{}},
			map[string]any{"id": "ecl.ext.unknown.v1", "version": json.Number("1"), "critical": true, "value": map[string]any{}},
		},
	}
	findings, err := documents.Evaluate(documents.Schemas[len(documents.Schemas)-1], intent)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, item := range findings {
		got[item.RuleID] = item.Path
	}
	want := map[string]string{
		semantic.SchemaInvalid:                            got[semantic.SchemaInvalid],
		"ecl.rule.extension-single-version.v1":            "/extensions/1",
		"ecl.rule.extension-namespace-allocated.v1":       "/extensions/2/id",
		"ecl.rule.unknown-critical-extension-rejected.v1": "/extensions/2/id",
	}
	if len(got) != len(want) || got[semantic.SchemaInvalid] == "" {
		t.Fatalf("%v", findings)
	}
	for rule, path := range want {
		if got[rule] != path {
			t.Errorf("%s at %q, want %q", rule, got[rule], path)
		}
	}
	delete(intent, "protocol")
	findings, err = documents.RuleFindings(intent, "")
	if err != nil || len(findings) != 0 {
		t.Fatalf("a document without a type: %v %v", findings, err)
	}
}
