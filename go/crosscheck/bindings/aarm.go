package bindings

import (
	"errors"
	"fmt"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

// AARM-BINDING-1: an AARM control plane as the ECL Decision Layer or as a source of judgment.
const (
	AARMExchangeVersion = "ecl_aarm_exchange_v1"
	AARMExchangeSchema  = "https://externalcontrollayer.ai/ns/schema/binding/aarm-exchange/1"
	aarmReceipt         = "ecl.ext.aarm-receipt.v1"

	RuleAARMModification = "ecl.rule.aarm-modification-new-request.v1"
	RuleAARMDeferral     = "ecl.rule.aarm-deferral-no-release.v1"
	RuleAARMJudgment     = "ecl.rule.aarm-judgment-inputs.v1"
	RuleAARMOutcome      = "ecl.rule.aarm-outcome-no-weaker.v1"
	RuleAARMRelease      = "ecl.rule.aarm-release-requires-admit.v1"
	RuleAARMReceipt      = "ecl.rule.aarm-receipt-bound.v1"
	// RuleAARMBasis is AB1-013: the record's inputs are those that its response's decision basis
	// records, with the same classes and digests, and the decision basis of the modification
	// response records them with their declarations.
	RuleAARMBasis = "ecl.rule.aarm-inputs-match-basis.v1"
)

// aarmDecisionRequirement is the AARM requirement whose output is the AARM decision itself
// (AB1-006). In the judgment-source role the inputs list it exactly once, as a judgment input.
const aarmDecisionRequirement = "R4"

var (
	// AB1-006: the AARM requirements whose outputs are judgment in either role.
	aarmJudgmentRequirements = map[string]bool{"R2": true, "R3": true, "R7": true}
	// AB1-003: the ECL outcomes no weaker than each AARM decision; MODIFY denies the original.
	aarmPermitted = map[string]map[string]bool{
		"ALLOW":   {"admit": true, "deny": true, "hold": true, "challenge": true},
		"DENY":    {"deny": true},
		"MODIFY":  {"deny": true},
		"STEP_UP": {"challenge": true, "hold": true, "deny": true},
		"DEFER":   {"hold": true, "deny": true},
	}
)

type aarmView struct {
	record     map[string]any
	decision   any
	outcome    any
	candidates []exchange
}

func aarmModification(view aarmView) []problem {
	if view.decision != "MODIFY" {
		return newRequestProblems(view.record)
	}
	request, isObject := object(view.record, "request")
	if !isObject {
		return nil
	}
	if _, hasNew := view.record["modification_request"]; !hasNew {
		if _, released := object(view.record, "release"); !released {
			return modificationResponseProblems(view.record)
		}
	}
	problems := prefixed(modificationProblems(request, member(view.record, "modification_request"), member(view.record, "aarm_decision", "modified_parameters")))
	if _, released := object(view.record, "release"); released && text(view.record, "release", "request_id") != text(view.record, "modification_request", "message_id") {
		problems = append(problems, problem{"/release/request_id", "a modification is released only under its new request"})
	}
	return problems
}

func aarmDeferral(view aarmView) []problem {
	if (view.decision == "DEFER" || view.decision == "STEP_UP") && (view.outcome == "hold" || view.outcome == "challenge") {
		return deferralProblems(member(view.record, "response"), nanos(member(view.record, "aarm_decision", "deadline")))
	}
	return nil
}

func aarmJudgment(view aarmView) []problem {
	inputs := array(view.record, "inputs")
	allAARM := text(view.record, "role") == "judgment-source"
	var required []int
	for index, item := range inputs {
		requirement, isText := textOf(item, "aarm_requirement")
		if isText && (aarmJudgmentRequirements[requirement] || allAARM) {
			required = append(required, index)
		}
	}
	problems := inputProblems(inputs, view.outcome, required)
	// AB1-006: these classes hold in every decision basis that the record holds, the modification
	// response's included, whose admit releases the modified action (AB1-004).
	judged := map[string]string{}
	for _, index := range required {
		if name, isText := textOf(inputs[index], "input"); isText {
			judged[semantic.InputKey(name)] = "judgment"
		}
	}
	problems = append(problems, basisClassProblems(view.record, []string{"modification_response"}, judged)...)
	if allAARM {
		// AB1-006: the AARM decision is an input of the decision in this role; an unlabelled one
		// would escape the class check above.
		var decisions []int
		for index, item := range inputs {
			if text(item, "aarm_requirement") == aarmDecisionRequirement {
				decisions = append(decisions, index)
			}
		}
		if len(decisions) == 0 {
			problems = append(problems, problem{"/inputs", "the inputs do not list the AARM decision as an R4 input"})
		}
		for position, index := range decisions {
			if position > 0 {
				problems = append(problems, problem{fmt.Sprintf("/inputs/%d/aarm_requirement", index), "the inputs list the AARM decision more than once"})
			}
		}
	}
	return problems
}

func aarmOutcome(view aarmView) []problem {
	decision, _ := view.decision.(string)
	permitted, known := aarmPermitted[decision]
	if !known {
		return nil
	}
	outcome, isText := view.outcome.(string)
	if !isText || !permitted[outcome] {
		return []problem{{"/response/outcome", decision + " cannot become " + pyjson.Str(view.outcome)}}
	}
	return nil
}

func aarmRelease(view aarmView) []problem {
	return releaseProblems(member(view.record, "release"), view.candidates)
}

func aarmReceiptBound(view aarmView) []problem {
	receipt, retained := object(view.record, "receipt")
	terminal := member(view.record, "terminal")
	values := extensionValues(terminal, aarmReceipt)
	if !retained && len(values) == 0 {
		return nil
	}
	if !retained {
		return []problem{{"/receipt", "the terminal event binds a receipt that the record does not retain"}}
	}
	if len(values) != 1 {
		return []problem{{"/terminal/extensions", "the terminal event binds the receipt exactly once"}}
	}
	value := values[0]
	var problems []problem
	if !pyjson.Equal(value["receipt_id"], receipt["receipt_id"]) {
		problems = append(problems, problem{"/terminal/extensions", "the bound receipt_id is not the receipt's"})
	}
	expected, err := JCSDigest(receipt)
	if err != nil && !errors.Is(err, ErrJCS) {
		raise(err)
	}
	if err != nil || !sameDigest(value["receipt_digest"], expected) {
		problems = append(problems, problem{"/terminal/extensions", "the bound digest is not the receipt's"})
	}
	recorded := member(receipt, "decision", "result")
	if !pyjson.Equal(value["decision"], recorded) || !pyjson.Equal(recorded, text(view.record, "aarm_decision", "decision")) {
		problems = append(problems, problem{"/receipt/decision", "the receipt's decision is not the AARM decision"})
	}
	original := member(view.record, "request")
	if !sameDigest(digestValue(digestOf(member(receipt, "action", "parameters"))), member(original, "action", "parameters_digest")) {
		problems = append(problems, problem{"/receipt/action/parameters", "the receipt's parameters are not the requested ones"})
	}
	bound := false
	action := text(terminal, "event", "action_id")
	for _, candidate := range view.candidates {
		if text(candidate.request, "action", "action_id") == action {
			bound = true
		}
	}
	if !bound {
		problems = append(problems, problem{"/terminal/event/action_id", "the receipt is bound to another action"})
	}
	return problems
}

// aarmRules are the rules of the profile in the order the reference reports them. A rule added
// to the registry for this profile is one function and one row here.
var aarmRules = []struct {
	rule  string
	check func(aarmView) []problem
}{
	{RuleAARMModification, aarmModification},
	{RuleAARMDeferral, aarmDeferral},
	{RuleAARMJudgment, aarmJudgment},
	{RuleAARMOutcome, aarmOutcome},
	{RuleAARMRelease, aarmRelease},
	{RuleAARMReceipt, aarmReceiptBound},
	{RuleAARMBasis, func(view aarmView) []problem {
		return append(basisProblems(view.record, "aarm_requirement"), modificationBasisProblems(view.record)...)
	}},
}

// checkAARM returns the findings of an ecl_aarm_exchange_v1 record that its schema accepted
// (AB1-002 to AB1-009).
func checkAARM(record map[string]any) []Finding {
	view := aarmView{
		record:     record,
		decision:   text(record, "aarm_decision", "decision"),
		outcome:    text(record, "response", "outcome"),
		candidates: exchanges(record, [2]string{"request", "response"}, [2]string{"modification_request", "modification_response"}),
	}
	var out []Finding
	for _, row := range aarmRules {
		out = append(out, findings(row.rule, row.check(view))...)
	}
	// AB1-013: the response, and a modification's response, satisfy DCMP2-053 under the response's
	// own rule, which is not one of the profile's.
	out = append(out, findings(ruleOneWay, oneWayResponseProblems(record, [2][]string{{"request"}, {"response"}}, [2][]string{{"modification_request"}, {"modification_response"}}))...)
	// AB1-013: each DCMP-2 message that the record holds satisfies the semantic rules of DCMP-2.
	return append(out, messageFindings(record, []string{"request"}, []string{"response"}, []string{"modification_request"}, []string{"modification_response"})...)
}
