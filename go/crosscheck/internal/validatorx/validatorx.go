// Package validatorx implements the RC-4 safe-state obligations from
// STRICT-FAILURE-1 and the safe-state-profile schema. It is fresh repository
// code, not an independent implementation or a translation of Python code.
package validatorx

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
	"fmt"
	"strings"
)

const ProofRule = "ecl.rule.required-proof-dependency-fails-closed.v1"
const ClassificationRule = "ecl.rule.dependency-classification-consistent.v1"
const StrictRule = "ecl.rule.strict-profile-forbids-fail-open.v1"
const ActionClassRule = "ecl.rule.action-class-policy-unambiguous.v1"

// StrictProfile is claimed by listing it in claimed_profiles (SF1-004); the profile_id decides nothing.
const StrictProfile = "STRICT-FAILURE-1"

func Validate(value any) []validator.Finding {
	findings := []validator.Finding{}
	doc, ok := value.(map[string]any)
	if !ok {
		return findings
	}
	strict := false
	if claimed, ok := doc["claimed_profiles"].([]any); ok {
		for _, item := range claimed {
			if name, ok := item.(string); ok && name == StrictProfile {
				strict = true
			}
		}
	}
	add := func(rule, path, detail string) {
		findings = append(findings, validator.Finding{RuleID: rule, Path: path, Detail: detail})
	}
	declared := map[string]map[string]any{}
	if dependencies, ok := doc["dependencies"].([]any); ok {
		for i, item := range dependencies {
			dependency, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if identifier, ok := dependency["id"].(string); ok {
				if _, exists := declared[identifier]; exists {
					add(ClassificationRule, fmt.Sprintf("/dependencies/%d/id", i), "a dependency identifier is declared more than once")
					declared[identifier] = nil
				} else {
					declared[identifier] = dependency
				}
			}
			disposition, _ := dependency["loss_disposition"].(string)
			path := fmt.Sprintf("/dependencies/%d/loss_disposition", i)
			class, _ := dependency["class"].(string)
			if class == "advisory" && dependency["supplies_required_proof"] == true {
				add(ClassificationRule, fmt.Sprintf("/dependencies/%d/class", i), "an advisory dependency cannot supply required proof")
			}
			if dependency["supplies_required_proof"] == true && disposition != "fail_closed" && disposition != "quarantine" && disposition != "emergency_halt" {
				add(ProofRule, path, "loss of required proof must block the effect")
			}
			if strict && disposition == "fail_open" {
				add(StrictRule, path, "strict failure forbids fail_open")
			}
		}
	}
	if actions, ok := doc["action_classes"].([]any); ok {
		declaredClasses := map[string]bool{}
		for i, item := range actions {
			action, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if identifier, isText := action["action_class"].(string); isText {
				if declaredClasses[identifier] {
					add(ActionClassRule, fmt.Sprintf("/action_classes/%d/action_class", i), "an action class is declared more than once")
				}
				declaredClasses[identifier] = true
			}
			authorization, ok := action["fail_open_authorization"].(map[string]any)
			if !ok {
				continue
			}
			base := fmt.Sprintf("/action_classes/%d/fail_open_authorization/covered_advisory_dependencies", i)
			covered, ok := authorization["covered_advisory_dependencies"].([]any)
			if !ok || len(covered) == 0 {
				add(ClassificationRule, base, "fail-open authorization names its covered advisory dependencies")
				continue
			}
			seen := map[string]bool{}
			for j, value := range covered {
				identifier, isText := value.(string)
				dependency := declared[identifier]
				proof, proofIsBool := dependency["supplies_required_proof"].(bool)
				if !isText || strings.TrimSpace(identifier) == "" || seen[identifier] || dependency == nil || dependency["class"] != "advisory" || !proofIsBool || proof {
					add(ClassificationRule, fmt.Sprintf("%s/%d", base, j), "fail-open coverage must name each declared advisory dependency once and none may supply required proof")
				}
				if isText {
					seen[identifier] = true
				}
			}
		}
	}
	if strict {
		if actions, ok := doc["action_classes"].([]any); ok {
			for i, item := range actions {
				action, ok := item.(map[string]any)
				if !ok {
					continue
				}
				for _, field := range []string{"timeout_disposition", "dependency_disposition", "stale_dependency_disposition", "buffer_exhaustion_disposition"} {
					if action[field] == "fail_open" {
						add(StrictRule, fmt.Sprintf("/action_classes/%d/%s", i, field), "strict failure forbids fail_open")
					}
				}
			}
		}
		if buffer, ok := doc["evidence_buffer"].(map[string]any); ok && buffer["overflow"] == "fail_open" {
			add(StrictRule, "/evidence_buffer/overflow", "strict failure forbids fail_open")
		}
	}
	return findings
}
