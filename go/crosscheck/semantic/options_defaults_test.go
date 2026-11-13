package semantic_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

const optionCoupling = "ecl.ext.consequence-coupling.v1"

func optionControl(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "suites", "control-extensions", "coupling-valid-admit-permitting-results.json"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := strict.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func optionEntry(t *testing.T, name string, value map[string]any, options semantic.Options) []semantic.Finding {
	t.Helper()
	var found []semantic.Finding
	var err error
	switch name {
	case "Validate":
		found, err = semantic.Validate(value, options)
	case "ValidateBytes":
		var raw []byte
		raw, err = json.Marshal(value)
		if err == nil {
			found, err = semantic.ValidateBytes(raw, options)
		}
	case "Extensions":
		found = semantic.Extensions(value, options)
	default:
		t.Fatal("unrecognized test entry point")
	}
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestSemanticOptionDefaults(t *testing.T) {
	configurations := []struct {
		name string
		make func() semantic.Options
	}{
		{"zero", func() semantic.Options { return semantic.Options{} }},
		{"known-only", func() semantic.Options {
			return semantic.Options{KnownExtensions: map[string]map[int]bool{optionCoupling: {1: true}}}
		}},
		{"registered", semantic.Registered},
		{"nil-known", func() semantic.Options { v := semantic.Registered(); v.KnownExtensions = nil; return v }},
		{"nil-value-schemas", func() semantic.Options { v := semantic.Registered(); v.ValueSchemas = nil; return v }},
		{"nil-schema-resolver", func() semantic.Options { v := semantic.Registered(); v.Schemas = nil; return v }},
		{"nil-applicability", func() semantic.Options { v := semantic.Registered(); v.Applicability = nil; return v }},
	}
	for _, configuration := range configurations {
		for _, entry := range []string{"Validate", "ValidateBytes", "Extensions"} {
			for _, malformed := range []bool{false, true} {
				name := configuration.name + "/" + entry + "/valid"
				if malformed {
					name = configuration.name + "/" + entry + "/invalid-value"
				}
				t.Run(name, func(t *testing.T) {
					value := optionControl(t)
					if malformed {
						value["extensions"].([]any)[0].(map[string]any)["value"] = "not-an-object"
					}
					before, _ := json.Marshal(value)
					options := configuration.make()
					found := optionEntry(t, entry, value, options)
					if malformed {
						if len(found) != 1 || found[0].RuleID != semantic.RuleExtensionValue {
							t.Fatalf("got %+v, want extension-value-valid", found)
						}
					} else if len(found) != 0 {
						t.Fatalf("valid control: %+v", found)
					}
					after, _ := json.Marshal(value)
					if string(before) != string(after) {
						t.Fatal("validation changed the object")
					}
				})
			}
		}
	}
}

func TestSemanticExplicitEmptyKnownExtensions(t *testing.T) {
	for _, entry := range []string{"Validate", "ValidateBytes", "Extensions"} {
		for _, critical := range []bool{false, true} {
			t.Run(entry+map[bool]string{false: "/noncritical", true: "/critical"}[critical], func(t *testing.T) {
				value := optionControl(t)
				ext := value["extensions"].([]any)[0].(map[string]any)
				ext["critical"] = critical
				ext["value"] = "opaque unsupported value"
				known := map[string]map[int]bool{}
				found := optionEntry(t, entry, value, semantic.Options{KnownExtensions: known})
				// Extensions checks interpreted value/behavior only; the public validators
				// additionally reject unknown critical occurrences.
				if critical && entry != "Extensions" {
					if len(found) != 1 || found[0].RuleID != "ecl.rule.unknown-critical-extension-rejected.v1" {
						t.Fatalf("got %+v", found)
					}
				} else if len(found) != 0 {
					t.Fatalf("unimplemented occurrence was interpreted: %+v", found)
				}
				if len(known) != 0 {
					t.Fatal("explicit empty implementation set was modified")
				}
			})
		}
	}
}

func TestSemanticDefaultFutureVersionRemainsUnknown(t *testing.T) {
	for _, critical := range []bool{false, true} {
		for _, entry := range []string{"Validate", "ValidateBytes", "Extensions"} {
			value := optionControl(t)
			ext := value["extensions"].([]any)[0].(map[string]any)
			ext["version"] = json.Number("2")
			ext["critical"] = critical
			ext["value"] = "future data"
			found := optionEntry(t, entry, value, semantic.Options{})
			if critical && entry != "Extensions" {
				if len(found) != 1 || found[0].RuleID != "ecl.rule.unknown-critical-extension-rejected.v1" {
					t.Fatalf("got %+v", found)
				}
			} else if len(found) != 0 {
				t.Fatalf("future version was interpreted: %+v", found)
			}
		}
	}
}

func TestSemanticCustomRegistryRetainsMapsWithDefaultResolver(t *testing.T) {
	const custom = "com.example.validated.v1"
	valueSchemas := map[string]string{custom: "https://externalcontrollayer.ai/ns/schema/extension/consequence-coupling/1"}
	expected := map[string]string{custom: valueSchemas[custom]}
	options := semantic.Options{
		KnownExtensions: map[string]map[int]bool{custom: {1: true}},
		ValueSchemas:    valueSchemas,
		Applicability:   validatorx.ExtensionApplicability{custom: {1: {"DCMP-2": true, "EBMP-2": true, "ECL-IE-1": true, "ECL-WI-1": true}}},
	}
	for _, kind := range []string{"request", "event", "envelope", "work"} {
		for _, validity := range []string{"valid", "invalid"} {
			t.Run(kind+"/"+validity, func(t *testing.T) {
				path := filepath.Join("..", "..", "..", "tests", "fixtures", "extension-consumer-cases", "custom-"+kind+"-"+validity+".json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				found, err := semantic.ValidateBytes(raw, options)
				if err != nil {
					t.Fatal(err)
				}
				if validity == "invalid" {
					if len(found) != 1 || found[0].RuleID != semantic.RuleExtensionValue {
						t.Fatalf("got %+v", found)
					}
				} else if len(found) != 0 {
					t.Fatalf("got %+v", found)
				}
				if !reflect.DeepEqual(valueSchemas, expected) {
					t.Fatal("explicit value-schema map changed")
				}
			})
		}
	}
}
