package semantic_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

const (
	admitVector   = "conformance/vectors/dcmp-2/valid-decision-response-admit.json"
	valueRule     = "ecl.rule.extension-value-valid.v1"
	payee         = "urn:example:input:payee-allow-list"
	mandate       = "urn:example:input:principal-transfer-mandate"
	anomaly       = "urn:example:input:transfer-anomaly-score"
	justification = "urn:example:input:agent-justification"
)

func basisDigest(fill string) map[string]any {
	return map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": strings.Repeat(fill, 64)}
}

// basisInputs are two verifiable inputs that support the action, and a judgment and the agent's
// own claim that do not.
func basisInputs() []any {
	input := func(identifier, class string, required bool, uri, fill, source string) map[string]any {
		return map[string]any{"input": identifier, "class": class, "required": required, "status": "available", "effect": "none",
			"reference": map[string]any{"uri": uri, "digest": basisDigest(fill)}, "source": source}
	}
	records := []any{
		input(payee, "verifiable", true, "urn:example:record:payee-allow-list-v12", "1", "urn:example:system-of-record:vendor-master"),
		input(mandate, "verifiable", true, "urn:example:mandate:ap-clerk-transfers", "2", "urn:example:identity-provider:corporate"),
		input(anomaly, "judgment", false, "urn:example:score:transfer-anomaly-0001", "3", "urn:example:detector:transfer-anomaly"),
		input(justification, "actor_supplied", false, "urn:example:statement:justification-1", "4", "urn:example:agent:payments-1"),
	}
	records[0].(map[string]any)["effect"] = "supports"
	records[1].(map[string]any)["effect"] = "supports"
	return records
}

// changedInput returns records with the named input's members changed; a nil value removes one.
func changedInput(records []any, identifier string, changes map[string]any) []any {
	out := make([]any, len(records))
	for index, item := range records {
		record := item.(map[string]any)
		if record["input"] != identifier {
			out[index] = record
			continue
		}
		copied := map[string]any{}
		for name, value := range record {
			copied[name] = value
		}
		for name, value := range changes {
			if value == nil {
				delete(copied, name)
			} else {
				copied[name] = value
			}
		}
		out[index] = copied
	}
	return out
}

func parsedVector(t *testing.T, path string) map[string]any {
	t.Helper()
	value, err := strict.Parse(vectors.Read(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

// basisRegister names the register of the test records (ECL1N-0181).
var basisRegister = map[string]any{"uri": "urn:example:register:payments", "digest": basisDigest("9")}

func withBasis(response map[string]any, records any) map[string]any {
	return withBasisRegister(response, records, basisRegister)
}

// withBasisRegister is withBasis with another register member; nil leaves it out.
func withBasisRegister(response map[string]any, records any, register any) map[string]any {
	copied := map[string]any{}
	for name, value := range response {
		copied[name] = value
	}
	extensions := []any{}
	for _, item := range response["extensions"].([]any) {
		if item.(map[string]any)["id"] != semantic.DecisionBasisExtension {
			extensions = append(extensions, item)
		}
	}
	value := map[string]any{"inputs": records}
	if register != nil {
		value["register"] = register
	}
	extensions = append(extensions, map[string]any{"id": semantic.DecisionBasisExtension, "version": 1, "critical": true, "value": value})
	sort.SliceStable(extensions, func(i, j int) bool {
		return extensions[i].(map[string]any)["id"].(string) < extensions[j].(map[string]any)["id"].(string)
	})
	copied["extensions"] = extensions
	return copied
}

func notAdmitted(t *testing.T, outcome string) map[string]any {
	response := parsedVector(t, admitVector)
	response["outcome"] = outcome
	response["obligations"] = []any{}
	response["reasons"] = []any{map[string]any{"code": "ecl.reason.native-policy-disposition.v1"}}
	delete(response, "authorization")
	extensions := []any{}
	for _, item := range response["extensions"].([]any) {
		if item.(map[string]any)["id"] != "ecl.ext.consequence-coupling.v1" {
			extensions = append(extensions, item)
		}
	}
	response["extensions"] = extensions
	return response
}

func validated(t *testing.T, value map[string]any) []semantic.Finding {
	t.Helper()
	findings, err := semantic.Validate(value, semantic.Registered())
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// basisRule returns "path: detail" for each finding of the decision-basis rule.
func basisRule(t *testing.T, value map[string]any) []string {
	t.Helper()
	var out []string
	for _, item := range validated(t, value) {
		if item.RuleID == semantic.RuleDecisionBasis {
			out = append(out, item.Path+": "+item.Detail)
		}
	}
	return out
}

func paths(lines []string) string {
	var out []string
	for _, line := range lines {
		out = append(out, strings.SplitN(line, ": ", 2)[0])
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func TestDecisionBasisAdmitOnVerifiableInputs(t *testing.T) {
	if found := validated(t, withBasis(parsedVector(t, admitVector), basisInputs())); len(found) != 0 {
		t.Fatalf("%v", found)
	}
}

func TestDecisionBasisRestrictingOnlyInputCannotSupport(t *testing.T) {
	for identifier, position := range map[string]string{anomaly: "2", justification: "3"} {
		found := basisRule(t, withBasis(parsedVector(t, admitVector), changedInput(basisInputs(), identifier, map[string]any{"effect": "supports"})))
		if paths(found) != "/extensions/1/value/inputs/"+position+"/effect" || !strings.Contains(found[0], "can only make an outcome stricter") {
			t.Fatalf("%s: %v", identifier, found)
		}
	}
}

func TestDecisionBasisAdmitNeedsSupportingVerifiableInput(t *testing.T) {
	records := changedInput(changedInput(basisInputs(), payee, map[string]any{"effect": "none"}), mandate, map[string]any{"effect": "none"})
	found := basisRule(t, withBasis(parsedVector(t, admitVector), records))
	if strings.Join(found, "|") != "/extensions/1/value/inputs: an admit records no verifiable input that supports it" {
		t.Fatalf("%v", found)
	}
}

func TestDecisionBasisRequiredInputMustBeAvailable(t *testing.T) {
	for _, status := range []string{"unavailable", "late", "malformed"} {
		required := changedInput(basisInputs(), mandate, map[string]any{"status": status, "effect": "none", "reference": nil})
		if found := basisRule(t, withBasis(parsedVector(t, admitVector), required)); paths(found) != "/extensions/1/value/inputs/1/status" {
			t.Fatalf("%s: %v", status, found)
		}
		optional := changedInput(basisInputs(), anomaly, map[string]any{"status": status, "effect": "none", "reference": nil})
		if found := validated(t, withBasis(parsedVector(t, admitVector), optional)); len(found) != 0 {
			t.Fatalf("%s: %v", status, found)
		}
	}
	records := changedInput(basisInputs(), payee, map[string]any{"status": "late", "reference": nil})
	if found := basisRule(t, withBasis(parsedVector(t, admitVector), records)); paths(found) != "/extensions/1/value/inputs/0/effect /extensions/1/value/inputs/0/status" {
		t.Fatalf("%v", found)
	}
}

func TestDecisionBasisJudgmentOnlyRestricts(t *testing.T) {
	for _, outcome := range []string{"hold", "deny"} {
		if found := validated(t, withBasis(notAdmitted(t, outcome), changedInput(basisInputs(), anomaly, map[string]any{"effect": "restricts"}))); len(found) != 0 {
			t.Fatalf("%s: %v", outcome, found)
		}
	}
	unavailable := changedInput(basisInputs(), mandate, map[string]any{"status": "unavailable", "effect": "restricts", "reference": nil})
	if found := validated(t, withBasis(notAdmitted(t, "deny"), unavailable)); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	for _, outcome := range []string{"hold", "deny", "challenge"} {
		response := notAdmitted(t, outcome)
		if outcome == "challenge" {
			response["challenge_id"] = "https://externalcontrollayer.ai/ns/challenge/example-001"
		}
		found := basisRule(t, withBasis(response, changedInput(basisInputs(), anomaly, map[string]any{"effect": "supports"})))
		if paths(found) != "/extensions/0/value/inputs/2/effect" {
			t.Fatalf("%s: %v", outcome, found)
		}
	}
}

func TestDecisionBasisValueSchemaFirstAndMalformedValues(t *testing.T) {
	records := changedInput(basisInputs(), payee, map[string]any{"reference": map[string]any{"uri": "urn:example:record:payee-allow-list"}})
	found := validated(t, withBasis(parsedVector(t, admitVector), records))
	if len(found) != 1 || found[0].RuleID != valueRule {
		t.Fatalf("%v", found)
	}
	for _, value := range []any{
		map[string]any{"inputs": "not a list"},
		map[string]any{"inputs": []any{"not an object", 7, nil}},
		map[string]any{"inputs": []any{map[string]any{"class": "judgment"}}},
		map[string]any{},
	} {
		response := parsedVector(t, admitVector)
		response["extensions"] = append(response["extensions"].([]any), map[string]any{"id": semantic.DecisionBasisExtension, "version": 1, "critical": true, "value": value})
		found := validated(t, response)
		if len(found) == 0 {
			t.Fatalf("%v: no finding", value)
		}
		for _, item := range found {
			if strings.Contains(item.Detail, "rejected malformed input") {
				t.Fatalf("%v: %v", value, found)
			}
		}
	}
	// An unhashable class is malformed input for the whole check, as in the reference.
	unhashable := changedInput(basisInputs(), anomaly, map[string]any{"effect": "supports", "class": []any{"judgment"}})
	var guarded []string
	for _, item := range validated(t, withBasis(parsedVector(t, admitVector), unhashable)) {
		if strings.HasPrefix(item.Detail, "decision basis semantic check") {
			guarded = append(guarded, item.RuleID)
		}
	}
	if strings.Join(guarded, " ") != semantic.SchemaInvalid {
		t.Fatalf("%v", guarded)
	}
}

func TestDecisionBasisOnlyJudgesDecisions(t *testing.T) {
	request := parsedVector(t, "conformance/vectors/dcmp-2/valid-decision-request.json")
	if found := basisRule(t, withBasis(request, changedInput(basisInputs(), anomaly, map[string]any{"effect": "supports"}))); len(found) != 0 {
		t.Fatalf("%v", found)
	}
}

// The anomaly score as judgment with no effect and again as a
// verifiable input that supports the admit.
func TestDecisionBasisInputListedTwice(t *testing.T) {
	second := map[string]any{}
	for name, value := range basisInputs()[2].(map[string]any) {
		second[name] = value
	}
	second["class"], second["effect"] = "verifiable", "supports"
	found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), second)))
	if strings.Join(found, "|") != "/extensions/1/value/inputs/4/input: the record lists this input more than once" {
		t.Fatalf("%v", found)
	}
}

func derivedInput(name, class string, sources ...any) map[string]any {
	return map[string]any{"input": name, "class": class, "required": false, "status": "available", "effect": "none",
		"reference": map[string]any{"uri": name + ":value", "digest": basisDigest("5")}, "source": name + ":source", "derived_from": sources}
}

func TestDecisionBasisDerivedInputs(t *testing.T) {
	tier := derivedInput("urn:example:input:risk-tier", "verifiable", anomaly)
	found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), tier)))
	if paths(found) != "/extensions/1/value/inputs/4/class" || !strings.Contains(found[0], "cannot be verifiable") {
		t.Fatalf("%v", found)
	}
	check := derivedInput("urn:example:input:payee-check", "verifiable", payee, mandate)
	judged := derivedInput("urn:example:input:risk-tier", "judgment", anomaly, justification)
	if found := validated(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), check, judged))); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	unknown := derivedInput("urn:example:input:payee-check", "verifiable", payee, "urn:example:input:x")
	if found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), unknown))); paths(found) != "/extensions/1/value/inputs/4/derived_from/1" {
		t.Fatalf("%v", found)
	}
}

func TestDecisionBasisEmptyRecordAndRegister(t *testing.T) {
	if found := validated(t, withBasis(notAdmitted(t, "deny"), []any{})); len(found) != 0 {
		t.Fatalf("deny: %v", found)
	}
	if found := basisRule(t, withBasis(parsedVector(t, admitVector), []any{})); strings.Join(found, "|") != "/extensions/1/value/inputs: an admit records no verifiable input that supports it" {
		t.Fatalf("admit: %v", found)
	}
	for _, register := range []any{nil, map[string]any{"uri": "urn:example:register:payments"}} {
		found := validated(t, withBasisRegister(parsedVector(t, admitVector), basisInputs(), register))
		if len(found) != 1 || found[0].RuleID != valueRule {
			t.Fatalf("%v: %v", register, found)
		}
	}
}

// Derivations followed through other inputs, cycles, input names compared by key, the
// verifiable-only outcome, the times of an input, and the register rule.

const (
	lateName    = "urn:example:input:sanctions-list"
	challengeID = "https://externalcontrollayer.ai/ns/challenge/example-001"
)

func lateInput() map[string]any {
	return map[string]any{"input": lateName, "class": "verifiable", "required": false, "status": "late", "effect": "none", "source": "urn:example:system-of-record:sanctions"}
}

func with(record map[string]any, name string, value any) map[string]any {
	copied := map[string]any{}
	for key, item := range record {
		copied[key] = item
	}
	copied[name] = value
	return copied
}

func responseFor(t *testing.T, outcome string) map[string]any {
	if outcome == "admit" {
		return parsedVector(t, admitVector)
	}
	response := notAdmitted(t, outcome)
	if outcome == "challenge" {
		response["challenge_id"] = challengeID
	}
	return response
}

func basisIndex(response map[string]any) int {
	for index, item := range response["extensions"].([]any) {
		if item.(map[string]any)["id"] == semantic.DecisionBasisExtension {
			return index
		}
	}
	return -1
}

func basisOf(response map[string]any) map[string]any {
	return response["extensions"].([]any)[basisIndex(response)].(map[string]any)["value"].(map[string]any)
}

func TestInputKey(t *testing.T) {
	for name, key := range map[string]string{
		"URN:Example:input:Payee": "urn:example:input:Payee",
		"urn:example:input:payee": "urn:example:input:payee",
		// The host of an http or https URI is lowercased, its path is not.
		"HTTPS://Example.org/Input":              "https://example.org/Input",
		"https://User@Agents.Example:8443/A?Q#F": "https://User@agents.example:8443/A?Q#F",
		"https://Agents.Example":                 "https://agents.example",
		"ftp://Example.org/Input":                "ftp://Example.org/Input",
		"Urn:EXAMPLE":                            "urn:EXAMPLE",
		// The hexadecimal digits of each percent-encoding are uppercased, everywhere.
		"urn:example:agent:test%2d1":       "urn:example:agent:test%2D1",
		"https://Host.Example/a%2fb%c3%a9": "https://host.example/a%2Fb%C3%A9",
		"no-scheme%7e":                     "no-scheme%7E",
		"urn:example:%zz%4":                "urn:example:%zz%4",
		"no-scheme":                        "no-scheme",
		":leading-colon":                   ":leading-colon",
		// Only ASCII letters are lowercased.
		"URN:\u0130X:a": "urn:\u0130x:a",
	} {
		if got := semantic.InputKey(name); got != key {
			t.Errorf("%q: %q, not %q", name, got, key)
		}
	}
}

func TestDecisionBasisCaseVariantDuplicate(t *testing.T) {
	variant := with(with(basisInputs()[0].(map[string]any), "input", strings.Replace(payee, "urn:example:", "URN:Example:", 1)), "effect", "none")
	found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), variant)))
	if strings.Join(found, "|") != "/extensions/1/value/inputs/4/input: the record lists this input more than once" {
		t.Fatalf("%v", found)
	}
	// The rest of a name is compared as written: this names another input.
	other := with(variant, "input", strings.Replace(payee, "payee", "Payee", 1))
	if found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), other))); len(found) != 0 {
		t.Fatalf("%v", found)
	}
}

func TestDecisionBasisDerivedFromLateInput(t *testing.T) {
	check := with(derivedInput("urn:example:input:payee-check", "verifiable", lateName), "effect", "supports")
	found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), lateInput(), check)))
	if strings.Join(found, "|") != "/extensions/1/value/inputs/5/effect: an input computed from an input that was not available cannot support an outcome" {
		t.Fatalf("direct: %v", found)
	}
	screen := derivedInput("urn:example:input:sanctions-screen", "verifiable", lateName)
	through := with(derivedInput("urn:example:input:payee-check", "verifiable", screen["input"]), "effect", "supports")
	if found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), lateInput(), screen, through))); paths(found) != "/extensions/1/value/inputs/6/effect" {
		t.Fatalf("through another input: %v", found)
	}
	required := with(derivedInput("urn:example:input:payee-check", "verifiable", lateName), "required", true)
	found = basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), lateInput(), required)))
	if strings.Join(found, "|") != "/extensions/1/value/inputs/5/status: an admit cannot proceed while a required input is computed from an input that was not available" {
		t.Fatalf("required: %v", found)
	}
	if found := validated(t, withBasis(notAdmitted(t, "deny"), append(basisInputs(), lateInput(), with(required, "effect", "restricts")))); len(found) != 0 {
		t.Fatalf("deny: %v", found)
	}
}

func TestDecisionBasisInputComputedFromItself(t *testing.T) {
	first := derivedInput("urn:example:input:a", "judgment", "urn:example:input:b")
	second := derivedInput("urn:example:input:b", "judgment", "URN:example:input:a")
	found := basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), first, second)))
	expected := "/extensions/1/value/inputs/4/derived_from: the input is computed from itself through other inputs|" +
		"/extensions/1/value/inputs/5/derived_from: the input is computed from itself through other inputs"
	if strings.Join(found, "|") != expected {
		t.Fatalf("%v", found)
	}
	itself := derivedInput("urn:example:input:a", "judgment", "urn:Example:input:a")
	found = basisRule(t, withBasis(parsedVector(t, admitVector), append(basisInputs(), itself)))
	if strings.Join(found, "|") != "/extensions/1/value/inputs/4/derived_from/0: the record lists no other input with this name" {
		t.Fatalf("%v", found)
	}
}

func TestDecisionBasisVerifiableOnlyOutcome(t *testing.T) {
	for _, item := range []struct {
		recorded, outcome string
		refused           bool
	}{
		{"deny", "challenge", true}, {"deny", "hold", true}, {"hold", "challenge", true}, {"challenge", "admit", true},
		{"deny", "deny", false}, {"hold", "deny", false}, {"admit", "admit", false}, {"admit", "hold", false},
	} {
		// An input supports only a verifiable-only admit (ECL1N-0181, DCMP2-053).
		records := basisInputs()
		if item.recorded != "admit" {
			records = unsupported(records)
		}
		value := withBasis(responseFor(t, item.outcome), records)
		basisOf(value)["verifiable_only_outcome"] = item.recorded
		if item.refused {
			expected := fmt.Sprintf("/extensions/%d/value/verifiable_only_outcome: the outcome '%s' is less strict than the verifiable-only outcome '%s'", basisIndex(value), item.outcome, item.recorded)
			found := basisRule(t, value)
			if !containsLine(found, expected) {
				t.Errorf("%s %s: %v", item.recorded, item.outcome, found)
			}
		} else if found := validated(t, value); len(found) != 0 {
			t.Errorf("%s %s: %v", item.recorded, item.outcome, found)
		}
	}
	// A caller without the response's outcome does not compare outcomes.
	response := withBasis(responseFor(t, "hold"), unsupported(basisInputs()))
	value := basisOf(response)
	value["verifiable_only_outcome"] = "deny"
	if found := semantic.OneWayProblems(value, false); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	found := semantic.OneWayProblemsAt(value, false, response["outcome"], response["evaluated_at"])
	if len(found) != 1 || found[0] != [2]string{"/verifiable_only_outcome", "the outcome 'hold' is less strict than the verifiable-only outcome 'deny'"} {
		t.Fatalf("%v", found)
	}
}

func containsLine(lines []string, line string) bool {
	for _, item := range lines {
		if item == line {
			return true
		}
	}
	return false
}

// unsupported returns records with no input that supports the outcome.
func unsupported(records []any) []any {
	out := make([]any, len(records))
	for index, item := range records {
		out[index] = with(item.(map[string]any), "effect", "none")
	}
	return out
}

// No input supports an outcome whose verifiable-only outcome is not admit.
func TestDecisionBasisNoInputSupportsAVerifiableOnlyRestriction(t *testing.T) {
	for _, recorded := range []string{"challenge", "hold", "deny"} {
		value := withBasis(responseFor(t, "deny"), basisInputs())
		basisOf(value)["verifiable_only_outcome"] = recorded
		index := basisIndex(value)
		expected := fmt.Sprintf("/extensions/%d/value/inputs/0/effect: no input supports an outcome whose verifiable-only outcome is '%s'|"+
			"/extensions/%d/value/inputs/1/effect: no input supports an outcome whose verifiable-only outcome is '%s'", index, recorded, index, recorded)
		if found := basisRule(t, value); strings.Join(found, "|") != expected {
			t.Errorf("%s: %v", recorded, found)
		}
		value = withBasis(responseFor(t, "deny"), unsupported(basisInputs()))
		basisOf(value)["verifiable_only_outcome"] = recorded
		if found := validated(t, value); len(found) != 0 {
			t.Errorf("%s unsupported: %v", recorded, found)
		}
	}
}

// A verifiable-only admit rests on a verifiable input and on every required input.
func TestDecisionBasisVerifiableOnlyAdmit(t *testing.T) {
	records := changedInput(changedInput(basisInputs(), mandate, map[string]any{"status": "unavailable", "reference": nil, "effect": "none"}), payee, map[string]any{"effect": "none"})
	value := withBasis(responseFor(t, "deny"), records)
	basisOf(value)["verifiable_only_outcome"] = "admit"
	index := basisIndex(value)
	expected := fmt.Sprintf("/extensions/%d/value/inputs/1/status: a verifiable-only admit cannot have a required verifiable input that was not available|"+
		"/extensions/%d/value/verifiable_only_outcome: a verifiable-only admit records no verifiable input that supports it", index, index)
	if found := basisRule(t, value); strings.Join(found, "|") != expected {
		t.Fatalf("%v", found)
	}
	value = withBasis(responseFor(t, "deny"), basisInputs())
	basisOf(value)["verifiable_only_outcome"] = "admit"
	if found := validated(t, value); len(found) != 0 {
		t.Fatalf("%v", found)
	}
}

// A required judgment or actor_supplied input does not change the
// verifiable-only outcome; a decision that is not admit while it is unavailable is valid, and an
// admit is not.
func TestDecisionBasisRequiredJudgmentUnderVerifiableOnlyAdmit(t *testing.T) {
	for _, identifier := range []string{anomaly, justification} {
		records := changedInput(basisInputs(), identifier, map[string]any{"required": true, "status": "unavailable", "reference": nil, "effect": "none"})
		for _, outcome := range []string{"deny", "hold", "challenge"} {
			value := withBasis(responseFor(t, outcome), records)
			basisOf(value)["verifiable_only_outcome"] = "admit"
			if found := validated(t, value); len(found) != 0 {
				t.Errorf("%s %s: %v", identifier, outcome, found)
			}
		}
		admitted := withBasis(responseFor(t, "admit"), records)
		basisOf(admitted)["verifiable_only_outcome"] = "admit"
		if found := basisRule(t, admitted); len(found) == 0 {
			t.Errorf("%s: the admit is not refused", identifier)
		}
	}
}

// The admit vector's response was evaluated at 2026-07-27T04:30:00.090000Z.
const (
	received      = "2026-07-27T04:30:00.010000Z"
	obtained      = "2026-07-27T04:30:00.050000Z"
	valued        = "2026-07-27T04:29:00Z"
	afterDecision = "2026-07-27T04:30:00.100000Z"
)

// timed is the admit with records and received_at; each available input that gives neither time
// gets both, since a record that gives received_at times every available input.
func timed(t *testing.T, records []any, receivedAt string) map[string]any {
	value := withBasis(parsedVector(t, admitVector), records)
	if receivedAt != "" {
		basisOf(value)["received_at"] = receivedAt
		for index, item := range basisOf(value)["inputs"].([]any) {
			record := item.(map[string]any)
			if record["status"] != "available" {
				continue
			}
			copied := with(record, "status", "available")
			if _, present := copied["obtained_at"]; !present {
				copied["obtained_at"] = obtained
			}
			if _, present := copied["value_at"]; !present {
				copied["value_at"] = valued
			}
			basisOf(value)["inputs"].([]any)[index] = copied
		}
	}
	return value
}

func TestDecisionBasisTimes(t *testing.T) {
	records := changedInput(changedInput(basisInputs(), payee, map[string]any{"obtained_at": obtained, "value_at": valued}), mandate, map[string]any{"obtained_at": obtained, "value_at": obtained})
	if found := validated(t, timed(t, records, received)); len(found) != 0 {
		t.Fatalf("within: %v", found)
	}
	// A record that gives received_at times every available input.
	untimed := withBasis(parsedVector(t, admitVector), changedInput(changedInput(basisInputs(), payee, map[string]any{"obtained_at": obtained, "value_at": valued}), mandate, map[string]any{"obtained_at": obtained}))
	basisOf(untimed)["received_at"] = received
	var expected []string
	for _, position := range []string{"1", "2", "3"} {
		expected = append(expected, "/extensions/1/value/inputs/"+position+": a record that gives when the request was received gives when each available input was obtained and the time its value describes")
	}
	if found := basisRule(t, untimed); strings.Join(found, "|") != strings.Join(expected, "|") {
		t.Fatalf("untimed: %v", found)
	}
	if found := validated(t, timed(t, changedInput(basisInputs(), anomaly, map[string]any{"status": "unavailable", "reference": nil}), received)); len(found) != 0 {
		t.Fatalf("unavailable untimed: %v", found)
	}
	// A value one hour after the decision and after its own obtained_at.
	later := "2026-07-27T05:30:00.090000Z"
	found := basisRule(t, timed(t, changedInput(basisInputs(), payee, map[string]any{"obtained_at": obtained, "value_at": later}), received))
	if strings.Join(found, "|") != "/extensions/1/value/inputs/0/value_at: the input's value describes a time after it was obtained|"+
		"/extensions/1/value/inputs/0/value_at: the input's value describes a time after the decision" {
		t.Fatalf("value after: %v", found)
	}
	found = basisRule(t, timed(t, changedInput(basisInputs(), payee, map[string]any{"obtained_at": afterDecision}), received))
	if strings.Join(found, "|") != "/extensions/1/value/inputs/0/status: an input obtained after the decision was not available" {
		t.Fatalf("after: %v", found)
	}
	lateAnomaly := changedInput(basisInputs(), anomaly, map[string]any{"status": "late", "reference": nil, "obtained_at": afterDecision})
	if found := validated(t, timed(t, lateAnomaly, received)); len(found) != 0 {
		t.Fatalf("recorded as late: %v", found)
	}
	found = basisRule(t, timed(t, changedInput(basisInputs(), payee, map[string]any{"obtained_at": obtained}), ""))
	if strings.Join(found, "|") != "/extensions/1/value/received_at: a record that gives when an input was obtained gives when the request was received" {
		t.Fatalf("without received_at: %v", found)
	}
	found = basisRule(t, timed(t, basisInputs(), afterDecision))
	if strings.Join(found, "|") != "/extensions/1/value/received_at: the request was received after the decision" {
		t.Fatalf("received after: %v", found)
	}
	other := validated(t, timed(t, changedInput(basisInputs(), payee, map[string]any{"obtained_at": "yesterday"}), received))
	if len(other) != 1 || other[0].RuleID != valueRule {
		t.Fatalf("another form: %v", other)
	}
}

func bundleRegister(t *testing.T) map[string]any {
	return parsedVector(t, "conformance/suites/evidence-bundle/register.json")
}

func declarationsOf(register map[string]any) []any {
	return register["entries"].([]any)[0].(map[string]any)["decision_inputs"].([]any)
}

func problemLines(problems [][2]string) string {
	var out []string
	for _, problem := range problems {
		out = append(out, problem[0]+": "+problem[1])
	}
	return strings.Join(out, "|")
}

func TestRegisterDeclaresEachClassAndInputOnce(t *testing.T) {
	register := bundleRegister(t)
	if found := semantic.RegisterDocumentProblems(register); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	twice := bundleRegister(t)
	twice["entries"] = append(twice["entries"].([]any), bundleRegister(t)["entries"].([]any)[0])
	if found := problemLines(semantic.RegisterDocumentProblems(twice)); found != "/entries/1/action_class_id: the register declares this action class more than once" {
		t.Fatalf("%s", found)
	}
	variant := bundleRegister(t)
	entry := variant["entries"].([]any)[0].(map[string]any)
	first := declarationsOf(variant)[0].(map[string]any)
	entry["decision_inputs"] = append(declarationsOf(variant), with(first, "input", strings.Replace(first["input"].(string), "urn:example:", "URN:EXAMPLE:", 1)))
	expected := fmt.Sprintf("/entries/0/decision_inputs/%d/input: the register declares this input more than once for the action class", len(declarationsOf(variant))-1)
	if found := problemLines(semantic.RegisterDocumentProblems(variant)); found != expected {
		t.Fatalf("%s", found)
	}
}

func TestRegisterDeclaresEachDerivationConsistently(t *testing.T) {
	// The bundle register declares two verifiable inputs (0 and 1) and a judgment (2).
	names := []any{}
	for _, item := range declarationsOf(bundleRegister(t)) {
		names = append(names, item.(map[string]any)["input"])
	}
	for _, item := range []struct {
		derivations map[int][]any
		expected    string
	}{
		{map[int][]any{2: {names[0], names[1]}}, ""},
		{map[int][]any{2: {"urn:example:input:bundle:elsewhere"}}, "/entries/0/decision_inputs/2/derived_from/0: the register declares no other input of the action class with this name"},
		{map[int][]any{0: {names[2]}}, "/entries/0/decision_inputs/0/class: an input computed from an input of class 'judgment' cannot be verifiable"},
		{map[int][]any{0: {names[1]}, 1: {names[0]}}, "/entries/0/decision_inputs/0/derived_from: the input is computed from itself through other inputs|" +
			"/entries/0/decision_inputs/1/derived_from: the input is computed from itself through other inputs"},
	} {
		register := bundleRegister(t)
		for position, sources := range item.derivations {
			declarationsOf(register)[position].(map[string]any)["derived_from"] = sources
		}
		if found := problemLines(semantic.RegisterDocumentProblems(register)); found != item.expected {
			t.Errorf("%v: %s", item.derivations, found)
		}
	}
}

func TestRegisterRuleAppliesToARegisterDocument(t *testing.T) {
	published := parsedVector(t, "profiles/examples/claims/action-register.json")
	derived := false
	for _, entry := range published["entries"].([]any) {
		inputs, _ := entry.(map[string]any)["decision_inputs"].([]any)
		for _, item := range inputs {
			if _, present := item.(map[string]any)["derived_from"]; present {
				derived = true
			}
		}
	}
	if !derived {
		t.Fatal("the published register declares no derived input")
	}
	if found := validated(t, published); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	twice := bundleRegister(t)
	twice["entries"] = append(twice["entries"].([]any), bundleRegister(t)["entries"].([]any)[0])
	found := validated(t, twice)
	if len(found) != 1 || found[0].RuleID != semantic.RuleRegisterDeclarations || found[0].Path != "/entries/1/action_class_id" {
		t.Fatalf("%v", found)
	}
}
