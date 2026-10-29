// Package documents evaluates the claim and assessment documents of ECL-1: the Consequential
// Action Register, the conformance claim, the assessment package, the mapping packet, the
// deployment profile, the lifecycle policy, the offline verification package and the work
// intent. The conformance runner's document stage reads each by strict parsing, validates it
// against the schema that the vector names, and applies the registered semantic rules whose
// applies_to names the document's type: its protocol, or the $id of the schema that the vector
// names. The work intent (ECL-WI-1) carries extensions, and the extension rules apply to it
// (XR1-006, XR1-009, XR1-010 and XR1-017): EXTENSION-REGISTRY-1 section 2; the register
// declarations rule applies to an action register (ECL1N-0178).
//
// A rule registered for a document type later needs no code here: the registry's applies_to
// names the type, and the semantic package holds the rule.
package documents

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

const namespace = "https://externalcontrollayer.ai/ns/schema/"

// Schemas are the $ids of the documents that the document stage evaluates.
var Schemas = []string{
	namespace + "action-register/1",
	namespace + "assessment-package/1",
	namespace + "conformance-claim/1",
	namespace + "deployment-profile/1",
	namespace + "lifecycle-policy/1",
	namespace + "mapping-packet/1",
	namespace + "offline-verification-package/1",
	namespace + "work-intent/1",
}

// RuleFindings returns the findings of the registered rules whose applies_to names the
// document's type, its protocol or schemaID, the $id of its schema: its semantic findings, kept
// only for those rules.
func RuleFindings(document map[string]any, schemaID string) ([]semantic.Finding, error) {
	scoped := registry.RulesApplyingTo(schemaID)
	if kind, isText := document["protocol"].(string); isText {
		for rule := range registry.RulesApplyingTo(kind) {
			scoped[rule] = true
		}
	}
	if len(scoped) == 0 {
		return []semantic.Finding{}, nil
	}
	found, err := semantic.Validate(document, semantic.Registered())
	if err != nil {
		return nil, err
	}
	kept := []semantic.Finding{}
	for _, item := range found {
		if scoped[item.RuleID] {
			kept = append(kept, item)
		}
	}
	return kept, nil
}

// Evaluate is the document stage for a parsed document and the schema that it names: one schema
// finding when the value is not an object; else one schema finding when it fails that schema,
// together with the findings of the rules that apply to its type, which the stage applies
// whether or not the schema accepts the document, as the reference runner does. The findings
// are sorted by rule, path and detail.
func Evaluate(schemaID string, value any) ([]semantic.Finding, error) {
	document, isObject := value.(map[string]any)
	if !isObject {
		return []semantic.Finding{{RuleID: semantic.SchemaInvalid, Path: "/", Detail: "a document is a JSON object"}}, nil
	}
	refusals, err := schema.ECL().Errors(schemaID, document, 1)
	if err != nil {
		return nil, err
	}
	found := []semantic.Finding{}
	if len(refusals) > 0 {
		found = append(found, semantic.Finding{RuleID: semantic.SchemaInvalid, Path: refusals[0].Path, Detail: refusals[0].Keyword + ": " + refusals[0].Message})
	}
	rules, err := RuleFindings(document, schemaID)
	if err != nil {
		return nil, err
	}
	found = append(found, rules...)
	semantic.Sort(found)
	return found, nil
}
