package schema_test

import (
	"fmt"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func parse(t *testing.T, text string) any {
	t.Helper()
	value, err := strict.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func set(t *testing.T, documents string) *schema.Set {
	t.Helper()
	built, err := schema.NewSet(parse(t, documents).(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func valid(t *testing.T, s *schema.Set, reference, instance string) bool {
	t.Helper()
	ok, err := s.Valid(reference, parse(t, instance))
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestURIFormat(t *testing.T) {
	for _, value := range []string{"urn:example:key:a", "https://externalcontrollayer.ai/ns/schema/dcmp/2", "https://[::1]/x", "https://[fe80::1%25eth0]:8443/", "https://[v1.x]/", "mailto:a@b", "a:b%20c"} {
		if !schema.IsURI(value) {
			t.Errorf("refused %q", value)
		}
	}
	for _, value := range []any{"", "a:", "https://", "x:?y", "mailto:#x", "1a:b", "https://h/%2", "https://h/%zz", "https://[1.2.3.4]/", "https://us[er]@host/", "https://[::1/x", "has space:x", "café:x", `a\b:c`, 5} {
		if schema.IsURI(value) {
			t.Errorf("accepted %v", value)
		}
	}
}

func TestDateTimeFormat(t *testing.T) {
	for _, value := range []string{"2026-10-01T00:00:00Z", "2024-02-29T23:59:59.123456789Z", "0001-01-01T00:00:00Z"} {
		if !schema.IsDateTime(value) {
			t.Errorf("refused %q", value)
		}
	}
	for _, value := range []any{"2026-02-29T00:00:00Z", "0000-01-01T00:00:00Z", "2026-04-31T00:00:00Z", "2026-10-01T24:00:00Z", "2026-10-01T00:00:60Z", "2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00.1234567890Z", "2026-10-01 00:00:00Z", 1} {
		if schema.IsDateTime(value) {
			t.Errorf("accepted %v", value)
		}
	}
}

func TestPatternsAreECMA262(t *testing.T) {
	s := set(t, `{"urn:test:anchors": {"type": "string", "pattern": "^[a-z]+$"}, "urn:test:dot": {"type": "string", "pattern": "^a.b$"}}`)
	if !valid(t, s, "urn:test:anchors", `"abc"`) || valid(t, s, "urn:test:anchors", `"abc\n"`) {
		t.Error("$ is not the end of the string")
	}
	if valid(t, s, "urn:test:dot", `"a b"`) || valid(t, s, "urn:test:dot", `"a\rb"`) || !valid(t, s, "urn:test:dot", `"a-b"`) {
		t.Error(". matches a line terminator")
	}
}

func TestLengthsEnumsAndUniqueness(t *testing.T) {
	s := set(t, `{"urn:test:length": {"type": "string", "maxLength": 1}, "urn:test:enum": {"enum": [1, "a"]}, "urn:test:unique": {"type": "array", "uniqueItems": true}}`)
	if !valid(t, s, "urn:test:length", `"😀"`) {
		t.Error("a length counts code points")
	}
	if valid(t, s, "urn:test:enum", `true`) || !valid(t, s, "urn:test:enum", `1`) {
		t.Error("enum equates a boolean with a number")
	}
	if !valid(t, s, "urn:test:unique", `[1, true]`) || valid(t, s, "urn:test:unique", `[{"a": 1, "b": 2}, {"b": 2, "a": 1}]`) {
		t.Error("uniqueItems")
	}
}

func TestUnevaluatedPropertiesSeesSatisfiedBranchesOnly(t *testing.T) {
	s := set(t, `{"urn:test:unevaluated": {
		"allOf": [{"properties": {"a": {"type": "string"}}}],
		"if": {"required": ["kind"], "properties": {"kind": {"const": "x"}}},
		"then": {"properties": {"x": true}},
		"else": {"properties": {"y": true}},
		"properties": {"kind": true},
		"unevaluatedProperties": false}}`)
	if !valid(t, s, "urn:test:unevaluated", `{"kind": "x", "a": "s", "x": 1}`) ||
		valid(t, s, "urn:test:unevaluated", `{"kind": "x", "a": "s", "y": 1}`) ||
		!valid(t, s, "urn:test:unevaluated", `{"kind": "z", "y": 1}`) {
		t.Error("unevaluatedProperties")
	}
}

func TestUnsupportedSchemasAreRefused(t *testing.T) {
	for _, document := range []string{
		`{"urn:test:x": {"type": "array", "contains": true, "minContains": 2}}`,
		`{"urn:test:x": {"type": "array", "contains": {"format": "email"}}}`,
		`{"urn:test:x": {"type": "string", "format": "email"}}`,
		`{"urn:test:x": {"type": "string", "pattern": "a(?!b)"}}`,
		`{"urn:test:x": {"type": "string", "pattern": "^a+(?!b)"}}`,
		`{"urn:test:x": {"type": "string", "pattern": "^(?!a(?!b))"}}`,
		`{"urn:test:x": {"type": "string", "pattern": "^(?=a)b"}}`,
		`{"urn:test:x": {"type": "string", "pattern": "^\\s$"}}`,
		`{"urn:test:x": {"$ref": "urn:test:missing"}}`,
	} {
		if _, err := schema.NewSet(parse(t, document).(map[string]any)); err == nil {
			t.Errorf("accepted %s", document)
		}
	}
}

func TestContains(t *testing.T) {
	s := set(t, `{"urn:test:contains": {"contains": {"const": "Decision"}}}`)
	for text, want := range map[string]bool{`["Authority", "Decision"]`: true, `["Authority"]`: false, `[]`: false, `"Decision"`: true} {
		if valid(t, s, "urn:test:contains", text) != want {
			t.Errorf("contains %s: want %v", text, want)
		}
	}
}

func TestAnchoredNegativeLookaheads(t *testing.T) {
	s := set(t, `{"urn:test:path": {"type": "string", "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\).+$"},
		"urn:test:duration": {"type": "string", "pattern": "^P(?!$).+$"}}`)
	for text, want := range map[string]bool{`"a/b"`: true, `"a..b/c"`: true, `"/a"`: false, `"a/../b"`: false, `".."`: false, `"a/.."`: false, `"a\\\\b"`: false, `""`: false, `"a\nb"`: false} {
		if valid(t, s, "urn:test:path", text) != want {
			t.Errorf("path %s: want %v", text, want)
		}
	}
	for text, want := range map[string]bool{`"P1D"`: true, `"P"`: false, `"Q1D"`: false} {
		if valid(t, s, "urn:test:duration", text) != want {
			t.Errorf("duration %s: want %v", text, want)
		}
	}
}

func TestSchemaCoverageSuite(t *testing.T) {
	checked := 0
	for _, vector := range vectors.Suite(t, "schema-coverage").Vectors {
		if vector.Schema == "" {
			continue
		}
		value, err := strict.Parse(vectors.Read(t, vector.Path))
		if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		errorsFound, err := schema.Validate(vector.Schema, value)
		if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		switch {
		case vector.Expected == "pass" && len(errorsFound) > 0:
			t.Errorf("%s: %v", vector.ID, errorsFound)
		case vector.Expected == "fail" && vector.Primary == "ecl.error.schema-invalid.v1" && len(errorsFound) == 0:
			t.Errorf("%s: no schema error", vector.ID)
		}
		checked++
	}
	if checked < 50 {
		t.Fatalf("only %d vectors", checked)
	}
}

func TestEmbeddedSchemas(t *testing.T) {
	identifiers := strings.Join(schema.ECL().Identifiers(), " ")
	for _, name := range []string{"dcmp/2", "ebmp/2", "integrity-envelope/1", "evidence-bundle/1", "trust-policy/1", "common/1",
		"binding/aarm-exchange/1", "binding/oauth-presentation/1", "conformance-claim/1", "offline-verification-package/1"} {
		if !strings.Contains(identifiers, "https://externalcontrollayer.ai/ns/schema/"+name) {
			t.Errorf("missing %s", name)
		}
	}
	if _, err := schema.Validate("urn:test:unknown", nil); err == nil {
		t.Error("an unknown schema was accepted")
	}
}

func ExampleValidate() {
	value, _ := strict.Parse([]byte(`{"schema_version": "ecl_evidence_bundle_v1", "envelopes": []}`))
	errorsFound, _ := schema.Validate("https://externalcontrollayer.ai/ns/schema/evidence-bundle/1", value)
	fmt.Println(len(errorsFound) > 0)
	// Output: true
}
