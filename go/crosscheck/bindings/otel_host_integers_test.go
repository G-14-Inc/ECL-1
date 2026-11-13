// Native Go workflow integer copies. Robert F. Tilley Jr.; G-14, Inc.
package bindings

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
)

func otelHostClone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, item := range v {
			result[key] = otelHostClone(item)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = otelHostClone(item)
		}
		return result
	default:
		return value
	}
}

func TestOTelWorkflowHostIntegerCopies(t *testing.T) {
	keys, err := LoadExportKeys(vectors.Read(t, vectors.Suite(t, "otel-export").ExportKeysPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, representation := range []string{"json.Number", "int", "int64"} {
		for _, keyed := range []bool{false, true} {
			mode := "unkeyed"
			if keyed {
				mode = "known-key"
			}
			for _, removed := range []string{"none", "attempt", "sequence", "both"} {
				t.Run(representation+"/"+mode+"/"+removed, func(t *testing.T) {
					value := bindingVector(t, "otel-export", "otel-valid-request-exported")
					for _, name := range []string{"object", "evidence_after"} {
						workflow := value[name].(map[string]any)["workflow"].(map[string]any)
						for _, field := range []string{"attempt", "sequence"} {
							switch representation {
							case "json.Number":
								workflow[field] = json.Number("1")
							case "int":
								workflow[field] = int(1)
							case "int64":
								workflow[field] = int64(1)
							}
						}
					}
					log := value["log_record"].(map[string]any)
					kept := []any{}
					for _, entry := range log["attributes"].([]any) {
						key := entry.(map[string]any)["key"].(string)
						if !keyed && (key == OTelKeyID || key == OTelObjectDigest || key == OTelParametersDigest) {
							continue
						}
						if (removed == "attempt" || removed == "both") && key == "ecl.workflow.attempt" {
							continue
						}
						if (removed == "sequence" || removed == "both") && key == "ecl.workflow.sequence" {
							continue
						}
						kept = append(kept, entry)
					}
					log["attributes"] = kept
					valid, err := schema.ECL().Valid(OTelExportSchema, value)
					if err != nil || !valid {
						t.Fatalf("schema control: %v %v", valid, err)
					}
					before := otelHostClone(value)
					object := value["object"].(map[string]any)
					beforeCanonical, err := canon.Marshal(object)
					if err != nil {
						t.Fatal(err)
					}
					var held *ExportKey
					if keyed {
						for _, k := range keys {
							copy := k
							held = &copy
							break
						}
					}
					attrs, err := OTelAttributes(object, value["bundle_id"], held, nil)
					if err != nil {
						t.Fatal(err)
					}
					for _, field := range []string{"attempt", "sequence"} {
						actual, present := attrs["ecl.workflow."+field]
						if !present || !pyjson.Equal(actual, json.Number("1")) {
							t.Errorf("required workflow %s omitted or changed: %#v", field, actual)
						}
					}
					var findings []Finding
					if keyed {
						findings, err = EvaluateRecordWithKeys(OTelExportSchema, value, keys)
					} else {
						findings, err = EvaluateRecord(OTelExportSchema, value)
					}
					if err != nil {
						t.Fatal(err)
					}
					want := map[string]bool{}
					if removed == "attempt" || removed == "both" {
						want["ecl.workflow.attempt is not the object's value"] = true
					}
					if removed == "sequence" || removed == "both" {
						want["ecl.workflow.sequence is not the object's value"] = true
					}
					if len(findings) != len(want) {
						t.Errorf("copy findings: got %v; want %v", findings, want)
					}
					for _, finding := range findings {
						if finding.RuleID != RuleOTelMatch || finding.Path != "/log_record/attributes" || !want[finding.Detail] {
							t.Errorf("unexpected copy finding: %v", finding)
						}
						delete(want, finding.Detail)
					}
					if len(want) != 0 {
						t.Errorf("missing required copy findings: %v", want)
					}
					afterCanonical, err := canon.Marshal(object)
					if err != nil || string(beforeCanonical) != string(afterCanonical) || !reflect.DeepEqual(value, before) {
						t.Fatal("caller input changed", err)
					}
				})
			}
		}
	}
}

func TestOTelAttributeHostIntegerBounds(t *testing.T) {
	values := []any{int(0), int64(0), int64(9007199254740991), json.Number("9007199254740991")}
	if strconv.IntSize == 64 {
		maximum := int64(9007199254740991)
		values = append(values, int(maximum))
	}
	for _, value := range values {
		object := bindingVector(t, "otel-export", "otel-valid-request-exported")["object"].(map[string]any)
		workflow := object["workflow"].(map[string]any)
		workflow["attempt"], workflow["sequence"] = value, value
		attrs, err := OTelAttributes(object, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"attempt", "sequence"} {
			actual, present := attrs["ecl.workflow."+field]
			if !present || !pyjson.Equal(actual, value) {
				t.Errorf("boundary copy %T(%v): %s=%v", value, value, field, actual)
			}
		}
	}
	for _, value := range []any{true, false, float64(1), json.Number("1.0"), json.Number("1e0")} {
		object := bindingVector(t, "otel-export", "otel-valid-request-exported")["object"].(map[string]any)
		object["workflow"].(map[string]any)["attempt"] = value
		_, boolean := value.(bool)
		if _, err := canon.Marshal(object); err == nil && !boolean {
			t.Errorf("unsupported canonical numeric representation accepted: %T(%v)", value, value)
		}
		if got := pick(object, []string{"workflow", "attempt"}); got != nil {
			t.Errorf("unsupported or boolean member copied: %T(%v)", value, got)
		}
	}
	object := bindingVector(t, "otel-export", "otel-valid-request-exported")["object"].(map[string]any)
	workflow := object["workflow"].(map[string]any)
	delete(workflow, "attempt")
	delete(workflow, "sequence")
	attrs, err := OTelAttributes(object, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"attempt", "sequence"} {
		if _, present := attrs["ecl.workflow."+field]; present {
			t.Errorf("absent %s invented", field)
		}
	}
}
