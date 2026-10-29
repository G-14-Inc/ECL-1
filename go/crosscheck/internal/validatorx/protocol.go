package validatorx

import (
	"fmt"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
)

// The RC-4 DCMP-2 and EBMP-2 rules: XR1-017, DCMP2-007, DCMP2-025 and EBMP2-046, the RC-5 rule of
// XR1-010, and the parts of EBMP2-011 and EBMP2-040 that the imported core does not check: a
// terminal state on an event of another type than execution_terminal, and the redaction manifest
// of a redaction. This is fresh repository code written from those requirements, beside the
// imported foundation core, whose terminal-state rule already enforces the state of an
// execution_terminal event and EBMP2-013, whose lifecycle rule enforces the derived artifact, and
// whose extension check enforces XR1-006 and XR1-009.
const (
	RuleExtensionNamespace = "ecl.rule.extension-namespace-allocated.v1"
	RuleParametersDigest   = "ecl.rule.parameters-digest-matches.v1"
	RuleEmergencyPlane     = "ecl.rule.emergency-control-plane-required.v1"
	RuleEventKind          = "ecl.rule.event-type-kind-consistent.v1"
	// RuleBudgetDebit is the RC-5 rule of DCMP2-055: a declared budget debit has no sign.
	RuleBudgetDebit = "ecl.rule.budget-debit-non-negative.v1"
)

type eventRule struct {
	kind   string
	states []string
}

var eventKinds = map[string]eventRule{
	"request_received":      {"request", nil},
	"decision_recorded":     {"decision", nil},
	"authority_issued":      {"authority", []string{"issued", "active"}},
	"authority_consumed":    {"authority", []string{"consumed", "revoked", "expired", "superseded"}},
	"release_prepared":      {"execution", []string{"prepared"}},
	"execution_released":    {"execution", []string{"released"}},
	"execution_observed":    {"execution", []string{"running"}},
	"execution_terminal":    {"execution", nil},
	"human_intervention":    {"intervention", nil},
	"verification":          {"verification", nil},
	"safe_state_transition": {"state", nil},
	"fleet_transition":      {"state", nil},
	"lifecycle_transition":  {"lifecycle", nil},
}

// terminalStates are the terminal execution outcomes and non-execution terminal dispositions
// (EBMP-2 section 3.2).
var terminalStates = map[string]bool{
	"succeeded": true, "failed": true, "partially_succeeded": true, "cancelled": true,
	"timed_out": true, "rolled_back": true, "compensated": true, "unknown": true,
	"denied": true, "held": true, "challenged": true, "expired_before_release": true,
}

// authorityMembers are the members of an admit's authorization that bind its release authority
// (DCMP2-013).
var authorityMembers = []string{"authorization_id", "audience", "scope_digest", "valid_from", "valid_until", "use_policy"}

// AdmitAuthority returns the finding of ecl.rule.admit-requires-valid-authority.v1 for one DCMP-2
// object (DCMP2-013): a decision response whose outcome is admit and whose authorization is not an
// object or lacks one of the members that bind its release authority. How those members bind the
// request is checked under DCMP2-044 to DCMP2-050. The imported core checks other conditions
// (three of the members, as non-empty strings), so its finding gives way to this one.
func AdmitAuthority(root map[string]any) []validator.Finding {
	if root["message_type"] != "decision_response" || root["outcome"] != "admit" {
		return nil
	}
	if authorization, isObject := root["authorization"].(map[string]any); isObject {
		complete := true
		for _, member := range authorityMembers {
			if _, present := authorization[member]; !present {
				complete = false
				break
			}
		}
		if complete {
			return nil
		}
	}
	return []validator.Finding{{RuleID: validator.RuleAdmitAuthority, Path: "/authorization", Detail: "admit requires an authorization with its identifier, audience, scope digest, validity interval and use policy"}}
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

// Protocol returns the RC-4 rule findings and the XR1-010 findings for one DCMP-2 or EBMP-2
// object. An extensions member that is not an array of objects gets no finding here: the schema
// and the core's extension check refuse it.
func Protocol(value any, options validator.Options) []validator.Finding {
	findings := []validator.Finding{}
	root, ok := value.(map[string]any)
	if !ok {
		return findings
	}
	add := func(rule, path, detail string) {
		findings = append(findings, validator.Finding{RuleID: rule, Path: path, Detail: detail})
	}
	if extensions, ok := root["extensions"].([]any); ok {
		for index, item := range extensions {
			extension, _ := item.(map[string]any)
			id, _ := extension["id"].(string)
			// XR1-017: allocated under any status, a deprecated identifier included; the options
			// name only the active entries, the occurrences a consumer knows (XR1-006).
			if strings.HasPrefix(id, "ecl.") && !Allocated(id) {
				add(RuleExtensionNamespace, fmt.Sprintf("/extensions/%d/id", index), "unallocated ECL extension identifier")
			}
		}
	}
	// XR1-010: one object carries each extension identifier at one version, unless the registry
	// declares the identifier's versions composable.
	versions, _ := ExtensionVersions(root, Composable())
	findings = append(findings, versions...)
	switch root["protocol"] {
	case "DCMP-2":
		switch root["message_type"] {
		case "decision_request":
			action, _ := root["action"].(map[string]any)
			if parameters, present := action["parameters"]; present {
				declared, _ := action["parameters_digest"].(map[string]any)
				computed, err := canonical.Digest(parameters)
				if err != nil || declared["algorithm"] != "ecl.digest.sha-256.v1" || declared["value"] != computed || len(declared) != 2 {
					add(RuleParametersDigest, "/action/parameters_digest", "parameters digest does not match the canonical in-band parameters")
				}
			}
			// DCMP2-055: a declared budget debit is written without a sign, so it never credits a
			// budget.
			debit, _ := action["budget_debit"].(map[string]any)
			if amount, isText := debit["amount"].(string); isText && strings.HasPrefix(amount, "-") {
				add(RuleBudgetDebit, "/action/budget_debit/amount", "a declared budget debit cannot be negative")
			}
		case "control":
			operation, _ := root["operation"].(string)
			authority, _ := root["authority"].(map[string]any)
			if (operation == "halt" || operation == "quarantine") && authority["plane"] != "emergency" {
				add(RuleEmergencyPlane, "/authority/plane", "halt and quarantine require the emergency control plane")
			}
		}
	case "EBMP-2":
		if root["object_type"] != "event_record" {
			return findings
		}
		eventType, _ := root["event_type"].(string)
		event, _ := root["event"].(map[string]any)
		state, _ := event["state"].(string)
		if rule, known := eventKinds[eventType]; known {
			if event["kind"] != rule.kind {
				add(RuleEventKind, "/event/kind", "event kind does not match event_type")
			} else if rule.states != nil && !contains(rule.states, state) {
				add(RuleEventKind, "/event/state", "event state does not match event_type")
			}
		}
		// EBMP2-011: only an execution_terminal event carries a terminal state.
		if eventType != "execution_terminal" && terminalStates[state] {
			add(validator.RuleTerminalState, "/event/state", "terminal execution state requires event_type execution_terminal")
		}
		// EBMP2-040 and EL1-014: a redaction also references its redaction manifest.
		if eventType == "lifecycle_transition" && event["operation"] == "redact" && !pyjson.Truthy(event["redaction_manifest"]) {
			add(validator.RuleLifecycleDerivative, "/event/redaction_manifest", "redact requires a redaction manifest reference")
		}
	}
	return findings
}
