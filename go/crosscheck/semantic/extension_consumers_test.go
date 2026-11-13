package semantic_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func TestExtensionConsumers(t *testing.T) {
	root := os.Getenv("ECL_EXTENSION_FIXTURES")
	if root == "" {
		root = filepath.Join("..", "..", "..", "tests", "fixtures", "extension-consumer-cases")
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var manifest struct {
		EvaluatedAt       string `json:"evaluated_at"`
		CustomIdentifier  string `json:"custom_identifier"`
		CustomValueSchema string `json:"custom_value_schema"`
		Cases             []struct {
			ID, File, Kind string
			Expected       json.RawMessage
		}
	}
	if err := json.Unmarshal(read("manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	policy, err := trust.Load(read("envelope-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundlePolicy, err := trust.Load(read("bundle-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	context, err := policy.VerificationContext(manifest.EvaluatedAt, "ecl.time.issued-at.v1")
	if err != nil {
		t.Fatal(err)
	}
	tag := manifest.CustomIdentifier
	custom := semantic.Options{KnownExtensions: map[string]map[int]bool{tag: {1: true}}, ValueSchemas: map[string]string{tag: manifest.CustomValueSchema}, Schemas: schema.ECL(),
		Applicability: validatorx.ExtensionApplicability{tag: {1: {"DCMP-2": true, "EBMP-2": true, "ECL-IE-1": true, "ECL-WI-1": true}}}}
	for _, row := range manifest.Cases {
		t.Run(row.ID, func(t *testing.T) {
			value, err := strict.Parse(read(row.File))
			if err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(value)
			switch row.Kind {
			case "envelope":
				var wanted *string
				if err := json.Unmarshal(row.Expected, &wanted); err != nil {
					t.Fatal(err)
				}
				_, err := envelope.Verify(value, policy.Keyring(), context)
				var actual *string
				if err != nil {
					var refusal *envelope.Error
					if !errors.As(err, &refusal) {
						t.Fatal(err)
					}
					actual = &refusal.Code
				}
				if !reflect.DeepEqual(actual, wanted) {
					t.Fatalf("got %v (%v), want %s", actual, err, row.Expected)
				}
			case "bundle":
				var wanted string
				if err := json.Unmarshal(row.Expected, &wanted); err != nil {
					t.Fatal(err)
				}
				report, err := evidence.Verify(value, bundlePolicy, evidence.Options{Now: "2026-10-01T00:00:00Z"})
				if err != nil {
					t.Fatal(err)
				}
				if report.Verdict != wanted {
					t.Fatalf("got %s, want %s: %+v", report.Verdict, wanted, report.Findings)
				}
			default:
				var wanted []string
				if err := json.Unmarshal(row.Expected, &wanted); err != nil {
					t.Fatal(err)
				}
				options := semantic.Registered()
				if row.Kind == "custom" {
					options = custom
				}
				findings, err := semantic.Validate(value, options)
				if err != nil {
					t.Fatal(err)
				}
				unique := map[string]bool{}
				for _, finding := range findings {
					unique[finding.RuleID] = true
				}
				actual := []string{}
				for id := range unique {
					actual = append(actual, id)
				}
				sort.Strings(actual)
				if !reflect.DeepEqual(actual, wanted) {
					t.Fatalf("got %v, want %v: %+v", actual, wanted, findings)
				}
			}
			after, _ := json.Marshal(value)
			if string(after) != string(before) {
				t.Fatal("consumer modified its input")
			}
		})
	}
}
