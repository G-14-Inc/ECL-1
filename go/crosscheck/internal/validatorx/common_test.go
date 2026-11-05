package validatorx

import (
	"encoding/json"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
)

func extension(id string, version string, critical bool) map[string]any {
	return map[string]any{"id": id, "version": json.Number(version), "critical": critical, "value": map[string]any{}}
}

// XR1-010: two versions of one identifier conflict, whether or not either is known, unless the
// registry declares the identifier composable; the same version twice is XR1-009's to refuse.
func TestExtensionVersions(t *testing.T) {
	object := map[string]any{"extensions": []any{
		extension("com.example.tag.v1", "1", false),
		extension("https://example.com/ext/v1", "1", false),
		extension("com.example.tag.v1", "1", false),
		extension("com.example.tag.v1", "7", false),
		map[string]any{"id": "com.example.tag.v1", "version": true},
		map[string]any{"id": 5, "version": json.Number("2")},
	}}
	found, problem := ExtensionVersions(object, nil)
	if problem != "" || len(found) != 1 || found[0].RuleID != RuleExtensionVersion || found[0].Path != "/extensions/3" {
		t.Fatalf("%v %q", found, problem)
	}
	if found, _ := ExtensionVersions(object, map[string]bool{"com.example.tag.v1": true}); len(found) != 0 {
		t.Fatalf("a composable identifier: %v", found)
	}
	for _, malformed := range []any{"x", []any{"x"}, []any{map[string]any{}, 1}} {
		if _, problem := ExtensionVersions(map[string]any{"extensions": malformed}, nil); problem == "" {
			t.Errorf("%v was read", malformed)
		}
	}
	for _, absent := range []map[string]any{{}, {"extensions": nil}} {
		if found, problem := ExtensionVersions(absent, nil); len(found) != 0 || problem != "" {
			t.Errorf("%v: %v %q", absent, found, problem)
		}
	}
	request := map[string]any{"protocol": "DCMP-2", "message_type": "decision_request", "extensions": object["extensions"]}
	if got := rules(Protocol(request, validator.Options{})); len(got) != 1 || got[0] != RuleExtensionVersion {
		t.Fatalf("protocol rules: %v", got)
	}
}

// The checks of every object, on an object of no protocol, such as a work intent: the rules of
// EXTENSION-REGISTRY-1 section 2 and XR1-017 at the reference's paths, and one schema finding for
// each check that cannot read the extensions member.
func TestCommon(t *testing.T) {
	intent := map[string]any{"protocol": "ECL-WI-1", "extensions": []any{
		extension("com.example.tag.v1", "1", false),
		extension("com.example.tag.v1", "1", false),
		extension("com.example.tag.v1", "2", false),
		extension("ecl.ext.unallocated.v1", "1", false),
		extension("ecl.ext.decision-basis.v1", "9", true),
		extension("ecl.ext.decision-basis.v1", "1", true),
	}}
	got := map[string][]string{}
	for _, item := range Common(intent) {
		got[item.RuleID] = append(got[item.RuleID], item.Path)
	}
	want := map[string][]string{
		RuleExtensionUnique:    {"/extensions/1"},
		RuleExtensionVersion:   {"/extensions/2", "/extensions/5"},
		RuleExtensionNamespace: {"/extensions/3/id"},
		RuleUnknownCritical:    {"/extensions/4/id"},
	}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for rule, paths := range want {
		if strings.Join(got[rule], " ") != strings.Join(paths, " ") {
			t.Errorf("%s: %v, want %v", rule, got[rule], paths)
		}
	}
	malformed := Common(map[string]any{"extensions": "x"})
	if len(malformed) != 4 {
		t.Fatalf("%v", malformed)
	}
	for _, item := range malformed {
		if item.RuleID != schemaInvalid || item.Path != "/" {
			t.Errorf("%+v", item)
		}
	}
	itself := map[string]any{"object_id": "urn:x", "workflow": map[string]any{"causal_predecessors": []any{map[string]any{"id": "urn:x"}}},
		"integrity_policy": map[string]any{"required": true, "threshold": json.Number("0")}}
	if found := rules(Common(itself)); strings.Join(found, " ") != RuleSelfCausation+" "+RuleIntegrityPolicy {
		t.Fatalf("%v", found)
	}
}
