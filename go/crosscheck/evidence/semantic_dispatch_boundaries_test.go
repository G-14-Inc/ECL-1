package evidence_test

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func boundaryValue(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../..", path))
	if err != nil {
		t.Fatal(err)
	}
	v, err := strict.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func boundaryPolicy(t *testing.T) *trust.Policy {
	t.Helper()
	data, err := os.ReadFile("../../../conformance/suites/evidence-bundle/trust-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := trust.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestSemanticDispatchBoundaries(t *testing.T) {
	for _, entry := range boundaryValue(t, "tests/fixtures/semantic-dispatch-boundaries/cases.json").([]any) {
		c := entry.(map[string]any)
		t.Run(c["id"].(string), func(t *testing.T) {
			value := c["value"]
			before, err := canon.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			options := semantic.Registered()
			if mode, ok := c["options"].(string); ok {
				id := "urn:example:review-extension"
				options.KnownExtensions = map[string]map[int]bool{}
				if mode == "custom" {
					options.KnownExtensions[id] = map[int]bool{1: true}
				}
				options.Applicability = map[string]map[int64]map[string]bool{id: {1: {c["kind"].(string): true}}}
				options.ValueSchemas = map[string]string{}
			}
			ids := map[string]bool{}
			locations := map[string]map[string]bool{}
			counts := map[string]int{}
			add := func(id, path string) {
				counts[id]++
				ids[id] = true
				if locations[id] == nil {
					locations[id] = map[string]bool{}
				}
				locations[id][path] = true
			}
			if c["api"] == "bundle" {
				report, err := evidence.Verify(value, boundaryPolicy(t), evidence.Options{Now: "2026-10-01T00:00:00Z"})
				if err != nil {
					t.Fatal(err)
				}
				if report.Verdict != "invalid" {
					t.Fatal(report.Verdict)
				}
				for _, f := range report.Findings {
					add(f.Code, "")
				}
			} else if c["api"] == "object" {
				findings, err := evidence.ObjectFindings(value)
				if err != nil {
					t.Fatal(err)
				}
				seenPairs := map[string]bool{}
				for _, f := range findings {
					key := f.RuleID + "@" + f.Path
					if c["id"] == "adapter-generic-operand-complete-semantic" && seenPairs[key] {
						t.Errorf("duplicate finding %s", key)
					}
					seenPairs[key] = true
					add(f.RuleID, f.Path)
				}
			} else {
				findings, err := semantic.Validate(value, options)
				if err != nil {
					t.Fatal(err)
				}
				seenPairs := map[string]bool{}
				for _, f := range findings {
					key := f.RuleID + "@" + f.Path
					if c["id"] == "adapter-generic-operand-complete-semantic" && seenPairs[key] {
						t.Errorf("duplicate finding %s", key)
					}
					seenPairs[key] = true
					add(f.RuleID, f.Path)
				}
				// ValidateBytes uses the same strict parser and semantic dispatch.
				raw, err := canon.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				bytesFindings, err := semantic.ValidateBytes(raw, options)
				if err != nil || !reflect.DeepEqual(findings, bytesFindings) {
					t.Fatalf("parsed/bytes mismatch: %v %v %v", findings, bytesFindings, err)
				}
			}

			after, err := canon.Marshal(value)
			if err != nil || string(before) != string(after) {
				t.Fatal("input mutated", err)
			}
			if strings.HasPrefix(c["id"].(string), "work-intent-foreign-") {
				root := value.(map[string]any)
				schemaID := "https://externalcontrollayer.ai/ns/schema/work-intent/1"
				ruleFindings, err := documents.RuleFindings(root, schemaID)
				if err != nil {
					t.Fatal(err)
				}
				evaluated, err := documents.Evaluate(schemaID, root)
				if err != nil {
					t.Fatal(err)
				}
				for _, fs := range [][]semantic.Finding{ruleFindings, evaluated} {
					seen := map[string]bool{}
					for _, f := range fs {
						seen[f.RuleID] = true
					}
					for _, required := range []string{"ecl.rule.expiry-after-issue.v1", "ecl.rule.message-cannot-cause-itself.v1", "ecl.rule.work-intent-context-consistent.v1"} {
						if !seen[required] {
							t.Errorf("document API lost %s: %v", required, fs)
						}
					}
					for _, foreign := range []string{"ecl.rule.register-declarations-consistent.v1", "ecl.rule.adapter-source-binding-valid.v1", "ecl.rule.deployment-timing-case-consistent.v1"} {
						if seen[foreign] {
							t.Errorf("document API applied foreign rule %s", foreign)
						}
					}
				}
			}
			for _, rule := range c["required"].([]any) {
				if !ids[rule.(string)] {
					t.Errorf("missing %s: %v", rule, ids)
				}
			}
			for _, rule := range c["absent"].([]any) {
				if ids[rule.(string)] {
					t.Errorf("unexpected %s", rule)
				}
			}
			if maximums, ok := c["max_rule_counts"].(map[string]any); ok {
				for rule, raw := range maximums {
					maximum, ok := pyjson.Int(raw)
					if !ok || int64(counts[rule]) > maximum {
						t.Errorf("too many %s findings: %d", rule, counts[rule])
					}
				}
			}
			if c["clean"] == true && len(ids) != 0 {
				t.Errorf("valid control: %v", ids)
			}
			if required, ok := c["required_paths"].(map[string]any); ok {
				for rule, paths := range required {
					for _, path := range paths.([]any) {
						if !locations[rule][path.(string)] {
							t.Errorf("missing %s at %s: %v", rule, path, locations)
						}
					}
				}
			}
			if c["id"] == "dcmp-adapter-discriminator" || c["id"] == "ebmp-adapter-discriminator" {
				fs, err := evidence.ObjectFindings(value)
				if err != nil {
					t.Fatal(err)
				}
				hasSchema := false
				for _, f := range fs {
					hasSchema = hasSchema || f.RuleID == "ecl.error.schema-invalid.v1"
				}
				if !hasSchema {
					t.Fatal("invalid extra discriminator passed the schema")
				}
			}
		})
	}
}
func TestScopeSignerDependencies(t *testing.T) {
	for _, mode := range []string{"valid", "all-time-authority", "one-time-authority", "none", "signer-and-time-authority"} {
		t.Run(mode, func(t *testing.T) {
			report, err := evidence.Verify(boundaryValue(t, "conformance/suites/evidence-bundle/bundle-valid-observation-corroborates.json"), boundaryPolicy(t), evidence.Options{Now: "2026-10-01T00:00:00Z"})
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != "verified" || report.Effects[0].Level != "corroborated" {
				t.Fatal(report.Verdict, report.Effects)
			}
			if mode == "none" {
				report.TrustDependencies = nil
			} else if mode == "signer-and-time-authority" {
				for _, d := range append([]evidence.TrustDependency{}, report.TrustDependencies...) {
					d.Role = "time-authority"
					report.TrustDependencies = append(report.TrustDependencies, d)
				}
			} else {
				for i := range report.TrustDependencies {
					if mode == "all-time-authority" || (mode == "one-time-authority" && report.TrustDependencies[i].Index == 0) {
						report.TrustDependencies[i].Role = "time-authority"
					}
				}
			}
			evidence.WithScope(report)
			supported := mode == "valid" || mode == "signer-and-time-authority"
			if slices.Contains(report.Scope.Established, "envelope-signatures") != supported {
				t.Fatal(report.Scope)
			}
			want := "issuer-asserted"
			if supported {
				want = "corroborated"
			}
			if report.Effects[0].Level != want {
				t.Fatal(report.Effects)
			}
		})
	}
}

func TestOutcomeReasonProtocolSelection(t *testing.T) {
	for _, envelope := range []string{"absent", "", "ECL-IE-1"} {
		t.Run(envelope, func(t *testing.T) {
			value := boundaryValue(t, "conformance/suites/control-extensions/outcome-reason-valid-expired-before-release.json").(map[string]any)
			if envelope != "absent" {
				value["envelope_version"] = envelope
			}
			before, err := canon.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if !validatorx.InterpretedOccurrence(value, value["extensions"].([]any)[0]) {
				t.Fatal("outcome reason not interpreted")
			}
			after, err := canon.Marshal(value)
			if err != nil || string(before) != string(after) {
				t.Fatal("input mutated", err)
			}
		})
	}
}

func TestAdapterNoncanonicalHostValueStructured(t *testing.T) {
	for _, extra := range []any{1.5, func() {}} {
		value := boundaryValue(t, "conformance/vectors/adapters/valid-native-binding.json").(map[string]any)
		value["noncanonical"] = extra
		findings, err := semantic.Validate(value, semantic.Registered())
		if err != nil {
			t.Fatal("raw canonicalization error", err)
		}
		found := false
		for _, f := range findings {
			if f.RuleID == "ecl.rule.adapter-source-binding-valid.v1" && f.Path == "/binding_digest" {
				found = true
			}
		}
		if !found {
			t.Fatal("missing structured canonicalization finding", findings)
		}
	}
}

func TestCoreSelfCausationProtocolIdentity(t *testing.T) {
	for _, protocol := range []string{"DCMP-2", "EBMP-2"} {
		for _, variant := range []string{"other", "self", "self-foreign-text", "self-foreign-number", "foreign-predecessor"} {
			t.Run(protocol+"/"+variant, func(t *testing.T) {
				fixture := "conformance/vectors/dcmp-2/invalid-self-causation.json"
				ownMember, foreignMember := "message_id", "object_id"
				if protocol == "EBMP-2" {
					fixture = "conformance/vectors/ebmp-2/valid-execution-terminal.json"
					ownMember, foreignMember = "object_id", "message_id"
				}
				value := boundaryValue(t, fixture).(map[string]any)
				workflow := value["workflow"].(map[string]any)
				predecessor := workflow["causal_predecessors"].([]any)[0].(map[string]any)
				predecessor["id"] = "urn:example:predecessor:other"
				wantSelf := strings.HasPrefix(variant, "self")
				if wantSelf {
					predecessor["id"] = value[ownMember]
				}
				foreign := false
				switch variant {
				case "self-foreign-text":
					value[foreignMember], foreign = "urn:example:foreign-identity", true
				case "self-foreign-number":
					value[foreignMember], foreign = int64(1), true
				case "foreign-predecessor":
					value[foreignMember], foreign = predecessor["id"], true
				}
				before, err := canon.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				semanticFindings, err := semantic.Validate(value, semantic.Registered())
				if err != nil {
					t.Fatal(err)
				}
				objectFindings, err := evidence.ObjectFindings(value)
				if err != nil {
					t.Fatal(err)
				}
				findingsByAPI := map[string][]string{"semantic": {}, "object": {}}
				for _, finding := range semanticFindings {
					findingsByAPI["semantic"] = append(findingsByAPI["semantic"], finding.RuleID)
				}
				for _, finding := range objectFindings {
					findingsByAPI["object"] = append(findingsByAPI["object"], finding.RuleID)
				}
				for api, findings := range findingsByAPI {
					selfCount, schemaCount := 0, 0
					for _, finding := range findings {
						if finding == validatorx.RuleSelfCausation {
							selfCount++
						}
						if finding == "ecl.error.schema-invalid.v1" {
							schemaCount++
						}
					}
					wantCount := 0
					if wantSelf {
						wantCount = 1
					}
					if selfCount != wantCount {
						t.Errorf("%s self count=%d, want %d: %v", api, selfCount, wantCount, findings)
					}
					if api == "object" && foreign && schemaCount == 0 {
						t.Errorf("foreign identity lost schema refusal: %v", findings)
					}
				}
				after, err := canon.Marshal(value)
				if err != nil || string(before) != string(after) {
					t.Fatal("input changed", err)
				}
			})
		}
	}
}
