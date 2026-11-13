package bindings

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"strings"
)

// TerminalReasonFindings applies EBMP2-056 to a terminal in a binding record.
// Findings are relative to the terminal. Paired mode is used only after the caller
// establishes the verified response (empty responseOutcome means none). Intrinsic
// mode leaves the response-dependent denied rule to that pairing. Unknown noncritical
// extension versions are not interpreted as version 1. Bundle checks stay at stage 9.
func TerminalReasonFindings(terminal map[string]any, responseOutcome string, paired bool) []Finding {
	if terminal == nil || text(terminal, "event_type") != "execution_terminal" {
		return nil
	}
	state := text(terminal, "event", "state")
	entries := extensionEntries(terminal, "ecl.ext.outcome-reason.v1")
	var found []Finding
	add := func(message string) {
		found = append(found, Finding{RuleID: "ecl.error.semantic-invalid.v1", Path: "/extensions", Detail: message})
	}
	if len(entries) > 1 {
		add("a terminal has multiple outcome reasons")
	}
	errors := registry.ActiveIDs("error-codes", "", "")
	for _, entry := range entries {
		value, ok := entry["value"].(map[string]any)
		code, textCode := value["code"].(string)
		if !ok || len(value) != 1 || !textCode || !strings.HasPrefix(code, "ecl.error.") || !errors[code] {
			add("a terminal has an invalid outcome reason")
		}
	}
	if len(entries) > 0 && state == "succeeded" {
		add("a succeeded terminal has an outcome reason")
	}
	if len(entries) == 0 && (state == "expired_before_release" || (paired && state == "denied" && (responseOutcome == "" || responseOutcome == "admit"))) {
		add("a terminal is missing its required outcome reason")
	}
	return found
}
