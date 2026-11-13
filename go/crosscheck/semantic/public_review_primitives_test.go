package semantic_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/bindings"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func reviewRequest(t *testing.T) map[string]any {
	t.Helper()
	value, err := strict.Parse(vectors.Read(t, "conformance/vectors/dcmp-2/valid-decision-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func reviewOccurrence(id string, version any, critical any) map[string]any {
	return map[string]any{"id": id, "version": version, "critical": critical, "value": map[string]any{}}
}

func reviewRules(t *testing.T, value any) map[string]bool {
	t.Helper()
	found, err := semantic.Validate(value, semantic.Registered())
	if err != nil {
		t.Fatal(err)
	}
	return ids(found)
}

func TestPublicReviewROOT010SingleParserBudget(t *testing.T) {
	for _, depth := range []int{120, 130, 253} {
		value := reviewRequest(t)
		var parameters any = json.Number("0")
		for range depth {
			parameters = map[string]any{"nested": parameters}
		}
		action := value["action"].(map[string]any)
		action["parameters"] = parameters
		digest, err := canon.Reference(parameters)
		if err != nil {
			t.Fatal(err)
		}
		action["parameters_digest"] = digest
		data, err := canon.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		found, err := semantic.ValidateBytes(data, semantic.Registered())
		if err != nil || len(found) != 0 {
			t.Fatalf("depth %d: %v %v", depth, found, err)
		}
	}
	// A caller may declare a larger depth/node profile, then pass the parsed value through.
	for _, content := range []string{strings.Repeat("[", 300) + "0" + strings.Repeat("]", 300), "[" + strings.Repeat("0,", 100_000) + "0]"} {
		data := []byte(`{"protocol":"DCMP-2","message_type":"decision_request","extensions":[{"id":"urn:example:opaque","version":1,"critical":false,"value":` + content + `}]}`)
		limits := strict.DefaultLimits
		limits.MaxDepth = 400
		value, err := strict.ParseLimited(data, limits)
		if err != nil {
			t.Fatal(err)
		}
		if found := reviewRules(t, value); len(found) != 0 {
			t.Fatal(found)
		}
	}
	// Default depth is checked once and keeps the registered resource-limit diagnostic.
	data := []byte(strings.Repeat("[", strict.MaxDepth+1) + "0" + strings.Repeat("]", strict.MaxDepth+1))
	found, err := semantic.ValidateBytes(data, semantic.Registered())
	if err != nil || len(found) != 1 || found[0].RuleID != strict.ResourceLimitExceeded {
		t.Fatalf("%v %v", found, err)
	}
	for _, nodes := range []int{3, 2} {
		limits := strict.DefaultLimits
		limits.MaxNodes = nodes
		_, err := strict.ParseLimited([]byte(`{"a":[0]}`), limits)
		if (err == nil) != (nodes == 3) {
			t.Fatalf("nodes %d: %v", nodes, err)
		}
	}
}

func TestPublicReviewROOT011027ExtensionAccumulationAndTypes(t *testing.T) {
	tag := "com.example.audit-tag.v1"
	duplicate := reviewOccurrence(tag, json.Number("1"), false)
	unknown := reviewOccurrence("urn:example:unknown", json.Number("1"), true)
	for _, entries := range [][]any{{duplicate, duplicate, unknown}, {unknown, duplicate, duplicate}, {nil, reviewOccurrence(tag, true, false), duplicate, duplicate, unknown}} {
		value := reviewRequest(t)
		value["extensions"] = entries
		found := reviewRules(t, value)
		if len(found) != 2 || !found["ecl.rule.extension-identifiers-unique.v1"] || !found["ecl.rule.unknown-critical-extension-rejected.v1"] {
			t.Fatal(found)
		}
	}
	value := reviewRequest(t)
	value["extensions"] = []any{reviewOccurrence(tag, true, false), duplicate, reviewOccurrence("urn:example:unknown", json.Number("1"), "false")}
	if found := reviewRules(t, value); len(found) != 0 {
		t.Fatal(found)
	}
	for _, policy := range []map[string]any{{"required": true}, {"threshold": json.Number("1")}} {
		value["integrity_policy"] = policy
		if reviewRules(t, value)["ecl.rule.integrity-threshold-consistent.v1"] {
			t.Fatal(policy)
		}
	}
}

func TestPublicReviewROOT016ReservedAuthority(t *testing.T) {
	for _, id := range []string{"https://externalcontrollayer.ai/audit", "HTTPS://EXTERNALCONTROLLAYER.AI/audit", "https://user@externalcontrollayer.ai:443/audit", "https://externalcontrollayer.ai@example.com/audit", "com.example.audit-tag.v1"} {
		value := reviewRequest(t)
		value["extensions"] = []any{reviewOccurrence(id, json.Number("1"), false)}
		want := !strings.Contains(id, "@example.com") && !strings.HasPrefix(id, "com.")
		if got := reviewRules(t, value)["ecl.rule.extension-namespace-allocated.v1"]; got != want {
			t.Fatalf("%s: %v", id, got)
		}
	}
}

func TestPublicReviewROOT056BindingClassesReturnFindings(t *testing.T) {
	for _, path := range []string{"aarm-binding/aarm-valid-allow-released.json", "acs-binding/acs-valid-allow-released.json", "mcp-gateway/mcp-valid-forwarded-release-order.json"} {
		for _, class := range []any{nil, []any{}, map[string]any{}, "review_invalid_class"} {
			parsed, err := strict.Parse(vectors.Read(t, "conformance/suites/"+path))
			if err != nil {
				t.Fatal(err)
			}
			value := parsed.(map[string]any)
			response, _ := value["response"].(map[string]any)
			if strings.HasPrefix(path, "mcp-") {
				response = value["decision"].(map[string]any)["response"].(map[string]any)
				state := map[string]any{"status": "current", "reference": map[string]any{"uri": "urn:example:control-snapshot:mcp-repair", "digest": map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": strings.Repeat("a", 64)}}, "fresh_until": "2026-09-30T09:01:00.000000Z", "halt": false, "quarantine": false, "revoked": false}
				value["release_observations"] = map[string]any{"initial": map[string]any{"observed_at": "2026-09-30T09:00:00.200000Z", "control_state": state}, "final": map[string]any{"observed_at": "2026-09-30T09:00:00.300000Z", "control_state": state}}
			}
			if class != nil {
				for _, raw := range response["extensions"].([]any) {
					ext := raw.(map[string]any)
					if ext["id"] == semantic.DecisionBasisExtension {
						ext["value"].(map[string]any)["inputs"].([]any)[0].(map[string]any)["class"] = class
					}
				}
			}
			profile := bindings.Profiles[value["schema_version"].(string)]
			if valid, err := schema.ECL().Valid(profile.Schema, value); err != nil || !valid {
				t.Fatalf("%s schema: %v %v", path, valid, err)
			}
			found, err := bindings.Findings(value)
			if err != nil {
				t.Fatalf("%s class %v: %v", path, class, err)
			}
			if class == nil && len(found) != 0 {
				t.Fatalf("control %s: %v", path, found)
			}
			if class != nil && !slices.ContainsFunc(found, func(f bindings.Finding) bool {
				return f.RuleID == semantic.RuleExtensionValue || strings.Contains(fmt.Sprint(f), semantic.RuleExtensionValue)
			}) {
				t.Fatalf("%s: %v", path, found)
			}
		}
	}
}

func TestPublicReviewROOT081WorkIntentPolicy(t *testing.T) {
	for _, mode := range []string{"absent", "valid", "zero", "outside", "unknown-critical"} {
		parsed, err := strict.Parse(vectors.Read(t, "conformance/suites/document-coverage/work-intent-valid.json"))
		if err != nil {
			t.Fatal(err)
		}
		value := parsed.(map[string]any)
		policy := map[string]any{"required": true, "threshold": json.Number("1"), "accepted_suites": []any{"ecl.sig.ed25519.v1"}, "eligible_key_ids": []any{}, "required_key_ids": []any{},
			"verification_time_policy": "ecl.time.issued-at.v1", "revocation_policy": "ecl.revocation.offline-bundle.v1", "trust_policy": map[string]any{"id": "urn:example:policy:review", "version": "1", "epoch": json.Number("1"), "digest": map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": strings.Repeat("ab", 32)}}}
		want := ""
		if mode != "absent" && mode != "unknown-critical" {
			value["integrity_policy"] = policy
		}
		if mode == "zero" {
			policy["threshold"] = json.Number("0")
			want = "ecl.rule.integrity-threshold-consistent.v1"
		}
		if mode == "outside" {
			policy["eligible_key_ids"] = []any{"urn:example:key:eligible"}
			policy["required_key_ids"] = []any{"urn:example:key:required"}
			want = "ecl.rule.integrity-threshold-consistent.v1"
		}
		if mode == "unknown-critical" {
			value["extensions"] = []any{reviewOccurrence("urn:example:unknown", json.Number("1"), true)}
			want = "ecl.rule.unknown-critical-extension-rejected.v1"
		}
		found, err := documents.Evaluate("https://externalcontrollayer.ai/ns/schema/work-intent/1", value)
		if err != nil || (want == "" && len(found) != 0) || (want != "" && (len(found) != 1 || found[0].RuleID != want)) {
			t.Fatalf("%s: %v %v", mode, found, err)
		}
	}
}
