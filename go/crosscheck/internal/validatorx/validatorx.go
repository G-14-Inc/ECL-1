// Package validatorx implements the RC-4 safe-state obligations from
// STRICT-FAILURE-1 and the safe-state-profile schema. It is fresh repository
// code, not an independent implementation or a translation of Python code.
package validatorx

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
	"fmt"
)

const ProofRule = "ecl.rule.required-proof-dependency-fails-closed.v1"
const StrictRule = "ecl.rule.strict-profile-forbids-fail-open.v1"

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
	if dependencies, ok := doc["dependencies"].([]any); ok {
		for i, item := range dependencies {
			dependency, ok := item.(map[string]any)
			if !ok {
				continue
			}
			disposition, _ := dependency["loss_disposition"].(string)
			path := fmt.Sprintf("/dependencies/%d/loss_disposition", i)
			if dependency["supplies_required_proof"] == true && disposition != "fail_closed" && disposition != "quarantine" && disposition != "emergency_halt" {
				add(ProofRule, path, "loss of required proof must block the effect")
			}
			if strict && disposition == "fail_open" {
				add(StrictRule, path, "strict failure forbids fail_open")
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
