package bindings

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// ACS-BINDING-1: an OWASP ACS Guardian as a decision source, its hook points as enforcement
// points.
const (
	ACSExchangeVersion = "ecl_acs_exchange_v1"
	ACSExchangeSchema  = "https://externalcontrollayer.ai/ns/schema/binding/acs-exchange/1"
	acsDecision        = "ecl.ext.acs-decision.v1"
	// Redacted replaces a redacted value when the redaction gives no replacement.
	Redacted = "[REDACTED]"

	RuleACSFailure      = "ecl.rule.acs-decision-failure-closed.v1"
	RuleACSExpiry       = "ecl.rule.acs-expiry-no-release.v1"
	RuleACSModification = "ecl.rule.acs-modification-new-request.v1"
	RuleACSJudgment     = "ecl.rule.acs-judgment-guardian.v1"
	RuleACSOutcome      = "ecl.rule.acs-outcome-no-weaker.v1"
	RuleACSRelease      = "ecl.rule.acs-release-requires-admit.v1"
	RuleACSRecorded     = "ecl.rule.acs-decision-recorded.v1"
	// RuleACSBasis is AC1-012: the inputs of a record that holds a response are the entries of the
	// response's decision basis, each equal to its entry apart from the Guardian marker.
	RuleACSBasis = "ecl.rule.acs-inputs-match-basis.v1"
)

// acsDeterministic is the one ACS evaluator whose decision can be anything but a judgment input
// (AC1-004): a decision from an agent or composite evaluator, or from one that is not stated, is
// judgment. A deterministic Guardian's decision takes the least trusted class of the inputs its
// request carried, which the record names in the derived_from of the Guardian's input (Section
// 4.3 of the core standard), and is actor_supplied when it reached the decision point through a
// channel that the governed AI system can write.
const acsDeterministic = "deterministic"

var (
	// ACSChannels are how the decision point obtained the Guardian's decision (guardian.channel,
	// AC1-004): from the Guardian directly, by verifying the Guardian's signature over it under a
	// key that the governed AI system cannot use, or through a hook point, which runs in the
	// Observed Agent and whose ACS-Core HMAC is made under a key that the Observed Agent holds
	// (ECL1N-0178).
	ACSChannels              = []string{"direct", "signed", "hook"}
	acsAuthenticatedChannels = map[string]bool{"direct": true, "signed": true}
	// inputClasses are the decision-input classes from most to least trusted (Section 4.3).
	inputClasses = []string{"verifiable", "judgment", "actor_supplied"}
	acsPermitted = map[string]map[string]bool{
		"allow":  {"admit": true, "deny": true, "hold": true, "challenge": true},
		"deny":   {"deny": true},
		"modify": {"deny": true},
		"ask":    {"challenge": true, "hold": true, "deny": true},
		"defer":  {"hold": true, "deny": true},
	}
	millisecond = big.NewInt(1_000_000)
)

func deepCopy(value any) any {
	switch current := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(current))
		for key, item := range current {
			out[key] = deepCopy(item)
		}
		return out
	case []any:
		out := make([]any, len(current))
		for index, item := range current {
			out[index] = deepCopy(item)
		}
		return out
	default:
		return value
	}
}

func pointer(path string) ([]string, bool) {
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	parts := strings.Split(path, "/")[1:]
	for index, part := range parts {
		parts[index] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
	}
	return parts, true
}

func overlaps(first, second []string) bool {
	shorter := len(first)
	if len(second) < shorter {
		shorter = len(second)
	}
	for index := 0; index < shorter; index++ {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

// EffectiveParameters returns the tool arguments after a modify decision's modifications, or
// false when there are none: a modifications object that the pinned text forbids (a wholesale
// replacement with edits, or edits whose targets overlap), that cannot be applied (a redaction
// path that does not resolve inside the arguments), or that yields arguments outside the
// restricted canonical profile. Each of these ends in a deny of the original with no new request
// (AC1-005).
func EffectiveParameters(arguments map[string]any, modifications any) (map[string]any, bool) {
	changes, isObject := modifications.(map[string]any)
	if !isObject {
		return nil, false
	}
	wholesale := changes["modified_content"]
	var redactions any = []any{}
	if holds(changes, "redactions") {
		redactions = changes["redactions"]
	}
	var overrides any = map[string]any{}
	if holds(changes, "parameter_overrides") {
		overrides = changes["parameter_overrides"]
	}
	if wholesale != nil {
		if holds(changes, "redactions") || holds(changes, "parameter_overrides") {
			return nil, false
		}
		content, isText := wholesale.(string)
		if !isText {
			return nil, false
		}
		replaced, err := strict.Parse([]byte(content))
		if err != nil {
			return nil, false
		}
		result, isObject := replaced.(map[string]any)
		return result, isObject
	}
	edits, isList := redactions.([]any)
	named, isMap := overrides.(map[string]any)
	if !isList || !isMap || (len(edits) == 0 && len(named) == 0) {
		return nil, false
	}
	paths := make([][]string, 0, len(edits))
	for _, item := range edits {
		path, isText := member(item, "path").(string)
		if !isText {
			return nil, false
		}
		parts, ok := pointer(path)
		if !ok || len(parts) == 0 {
			return nil, false
		}
		paths = append(paths, parts)
	}
	for _, parts := range paths {
		for name := range named {
			if overlaps(parts, []string{name}) {
				return nil, false
			}
		}
	}
	result := deepCopy(arguments).(map[string]any)
	for name, value := range named {
		result[name] = deepCopy(value)
	}
	for index, item := range edits {
		parts := paths[index]
		entry := item.(map[string]any)
		var replacement any = Redacted
		if holds(entry, "replacement") {
			replacement = entry["replacement"]
		}
		var container any = result
		for _, step := range parts[:len(parts)-1] {
			if current, isObject := container.(map[string]any); isObject {
				container = current[step]
			} else {
				container = nil
			}
		}
		target, isObject := container.(map[string]any)
		last := parts[len(parts)-1]
		if !isObject || !holds(target, last) {
			return nil, false
		}
		target[last] = replacement
	}
	if digestOf(result) == nil {
		return nil, false
	}
	return result, true
}

// hexBytes is Python's bytes.fromhex: pairs of hexadecimal digits, with ASCII whitespace allowed
// between pairs.
func hexBytes(text string) ([]byte, bool) {
	var out []byte
	for index := 0; index < len(text); {
		if strings.IndexByte(" \t\n\r\v\f", text[index]) >= 0 {
			index++
			continue
		}
		if index+2 > len(text) {
			return nil, false
		}
		pair, err := hex.DecodeString(text[index : index+2])
		if err != nil {
			return nil, false
		}
		out = append(out, pair...)
		index += 2
	}
	return out, true
}

// EntryHash returns the entry_hash of an ACS ContextEntry under the pinned chain-hashing rule
// (section 8.2): SHA-256 of the RFC 8785 form of the entry without entry_hash and previous_hash,
// followed by the 32 bytes of previous_hash, or nothing for the first entry; false when it has
// none.
func EntryHash(entry map[string]any) (string, bool) {
	content := make(map[string]any, len(entry))
	for name, value := range entry {
		if name != "entry_hash" && name != "previous_hash" {
			content[name] = value
		}
	}
	var tail []byte
	if previous, isText := entry["previous_hash"].(string); isText {
		decoded, ok := hexBytes(previous)
		if !ok {
			return "", false
		}
		tail = decoded
	}
	canonical, err := JCS(content)
	if err != nil {
		if errors.Is(err, ErrJCS) {
			return "", false
		}
		raise(err)
	}
	sum := sha256.Sum256(append(canonical, tail...))
	return hex.EncodeToString(sum[:]), true
}

// chainProblems is each chain entry whose hash or link the recomputation does not reproduce.
func chainProblems(entries []any) []problem {
	var problems []problem
	var previous any
	for index, item := range entries {
		entry, isObject := item.(map[string]any)
		if !isObject {
			problems = append(problems, problem{pointerTo("/chain", index), "a ContextEntry is not an object"})
			continue
		}
		if !pyjson.Equal(entry["previous_hash"], previous) {
			problems = append(problems, problem{pointerTo("/chain", index) + "/previous_hash", "the link is not the prior head"})
		}
		var recomputed any
		if hash, ok := EntryHash(entry); ok {
			recomputed = hash
		}
		if !pyjson.Equal(recomputed, entry["entry_hash"]) {
			problems = append(problems, problem{pointerTo("/chain", index) + "/entry_hash", "the hash is not the recomputed one"})
		}
		previous = nil
		if hash, isText := entry["entry_hash"].(string); isText {
			previous = hash
		}
	}
	return problems
}

// acsDeadline is when the Guardian's ask or defer stops waiting, in nanoseconds: the time the
// adapter observed its decision plus ask_details.timeout_seconds or
// defer_details.resolution_timeout_ms; nil when the record lacks either.
func acsDeadline(record map[string]any, disposition string) *big.Int {
	received := nanos(member(record, "guardian", "observed_at"))
	var span *big.Int
	if disposition == "ask" {
		if seconds, ok := integer(record, "guardian", "result", "ask_details", "timeout_seconds"); ok {
			span = new(big.Int).Mul(big.NewInt(seconds), nanosecond)
		}
	} else if milliseconds, ok := integer(record, "guardian", "result", "defer_details", "resolution_timeout_ms"); ok {
		span = new(big.Int).Mul(big.NewInt(milliseconds), millisecond)
	}
	if received == nil || span == nil {
		return nil
	}
	return received.Add(received, span)
}

func modificationsDigest(result map[string]any) any {
	if !holds(result, "modifications") {
		return nil
	}
	digest, err := JCSDigest(result["modifications"])
	if err != nil {
		if errors.Is(err, ErrJCS) {
			return nil
		}
		raise(err)
	}
	return digest
}

type acsView struct {
	record      map[string]any
	disposition any
	outcome     any
	candidates  []exchange
}

func acsFailure(view acsView) []problem {
	var problems []problem
	if text(view.record, "on_decision_failure") != "deny" {
		problems = append(problems, problem{"/on_decision_failure", "a claim of this profile negotiates deny"})
	}
	if text(view.record, "guardian", "status") == "failed" {
		if _, released := object(view.record, "release"); released {
			problems = append(problems, problem{"/release", "a Guardian decision failure released the action"})
		}
		if view.outcome == "admit" {
			problems = append(problems, problem{"/response/outcome", "a Guardian decision failure ended in an admit"})
		}
	}
	return problems
}

func acsExpiry(view acsView) []problem {
	disposition, _ := view.disposition.(string)
	if disposition != "ask" && disposition != "defer" {
		return nil
	}
	var problems []problem
	if view.outcome == "hold" || view.outcome == "challenge" {
		problems = append(problems, deferralProblems(member(view.record, "response"), acsDeadline(view.record, disposition))...)
		expires := nanos(member(view.record, "response", "expires_at"))
		released := nanos(member(view.record, "release", "released_at"))
		if expires != nil && released != nil && released.Cmp(expires) >= 0 {
			problems = append(problems, problem{"/release/released_at", "the action went ahead after the expiry"})
		}
	}
	return problems
}

func acsModification(view acsView) []problem {
	request, isObject := object(view.record, "request")
	if view.disposition != "modify" {
		return newRequestProblems(view.record)
	}
	if !isObject {
		return nil
	}
	if _, hasNew := view.record["modification_request"]; !hasNew {
		if _, released := object(view.record, "release"); !released {
			return modificationResponseProblems(view.record)
		}
	}
	arguments, isObject := member(request, "action", "parameters").(map[string]any)
	if !isObject {
		arguments = map[string]any{}
	}
	effective, usable := EffectiveParameters(arguments, member(view.record, "guardian", "result", "modifications"))
	modified := member(view.record, "modification_request")
	_, released := object(view.record, "release")
	if !usable {
		var problems []problem
		if modified != nil {
			problems = append(problems, problem{"/modification_request", "an unusable modification gets no new request"})
		}
		if released {
			problems = append(problems, problem{"/release", "an unusable modification releases nothing"})
		}
		return problems
	}
	problems := prefixed(modificationProblems(request, modified, effective))
	if released && text(view.record, "release", "request_id") != text(view.record, "modification_request", "message_id") {
		problems = append(problems, problem{"/release/request_id", "a modification is released only under its new request"})
	}
	return problems
}

// LeastTrusted returns the least trusted of classes in the order of Section 4.3, passing over
// values that are not classes; verifiable for none.
func LeastTrusted(classes []any) string {
	rank := 0
	for _, item := range classes {
		for position, class := range inputClasses {
			if item == class && position > rank {
				rank = position
			}
		}
	}
	return inputClasses[rank]
}

// acsAuthenticated is whether the decision point obtained the Guardian's decision directly or by a
// Guardian signature that it verified (AC1-004).
func acsAuthenticated(channel any) bool {
	name, isText := channel.(string)
	return isText && acsAuthenticatedChannels[name]
}

// GuardianClass returns the class of a Guardian decision (AC1-004): judgment unless its evaluator
// is deterministic, so from an agent or composite evaluator or one that states none;
// actor_supplied when the decision point neither obtained it from the Guardian directly nor
// verified the Guardian's signature over it (channel neither direct nor signed), as for a decision
// that a hook point carried; and otherwise the least trusted class of the inputs its request
// carried.
func GuardianClass(evaluator any, carried []any, channel any) string {
	if evaluator != acsDeterministic {
		return "judgment"
	}
	if !acsAuthenticated(channel) {
		return "actor_supplied"
	}
	return LeastTrusted(carried)
}

func acsJudgment(view acsView) []problem {
	inputs := array(view.record, "inputs")
	evaluator := text(view.record, "guardian", "result", "metadata", "evaluator")
	channel := text(view.record, "guardian", "channel")
	// As the reference's dict comprehension: a later input with the same key wins. A name in
	// derived_from is compared as input names are (DCMP2-053).
	classes := map[string]any{}
	for _, item := range inputs {
		if name, isText := textOf(item, "input"); isText {
			classes[semantic.InputKey(name)] = text(item, "class")
		}
	}
	var problems []problem
	var marked []int
	for index, item := range inputs {
		if member(item, "guardian") == true {
			marked = append(marked, index)
		}
	}
	// The class that each marked input must have, by its semantic.InputKey, in every decision basis
	// that the record holds (AC1-004).
	required := map[string]string{}
	for _, index := range marked {
		item := inputs[index]
		path := fmt.Sprintf("/inputs/%d", index)
		derived, isList := member(item, "derived_from").([]any)
		name, hasName := textOf(item, "input")
		var expected string
		switch {
		case evaluator != acsDeterministic || !acsAuthenticated(channel):
			expected = GuardianClass(evaluator, nil, channel)
		case !isList:
			recorded, hasClass := textOf(item, "class")
			if hasClass && recorded == "verifiable" {
				problems = append(problems, problem{path + "/derived_from", "a verifiable Guardian decision names the inputs its request carried"})
			} else if hasName && hasClass {
				required[semantic.InputKey(name)] = recorded
			}
			continue
		default:
			var carried []any
			for offset, candidate := range derived {
				name, isText := candidate.(string)
				key := ""
				if isText {
					key = semantic.InputKey(name)
				}
				if _, known := classes[key]; !isText || !known {
					problems = append(problems, problem{fmt.Sprintf("%s/derived_from/%d", path, offset), "the record lists no such input"})
				}
				if isText {
					carried = append(carried, classes[key])
				}
			}
			expected = GuardianClass(evaluator, carried, channel)
		}
		if text(item, "class") != expected {
			problems = append(problems, problem{path + "/class", "this input must be " + expected})
		}
		if hasName {
			required[semantic.InputKey(name)] = expected
		}
	}
	// AC1-004: a response that records the Guardian decision rests on it as one input, which the
	// record marks; an unmarked one would escape the class check above.
	if len(extensionEntries(member(view.record, "response"), acsDecision)) > 0 {
		if len(marked) == 0 {
			problems = append(problems, problem{"/inputs", "no input is marked as the Guardian's decision"})
		}
		for position, index := range marked {
			if position > 0 {
				problems = append(problems, problem{fmt.Sprintf("/inputs/%d/guardian", index), "another input is marked as the Guardian's decision"})
			}
		}
	}
	problems = append(problems, basisClassProblems(view.record, []string{"modification_response"}, required)...)
	return append(problems, inputProblems(inputs, view.outcome, nil)...)
}

func acsOutcome(view acsView) []problem {
	disposition, _ := view.disposition.(string)
	permitted, known := acsPermitted[disposition]
	if !known {
		return nil
	}
	outcome, isText := view.outcome.(string)
	if !isText || !permitted[outcome] {
		return []problem{{"/response/outcome", disposition + " cannot become " + pyjson.Str(view.outcome)}}
	}
	return nil
}

func acsRelease(view acsView) []problem {
	return releaseProblems(member(view.record, "release"), view.candidates)
}

func acsRecorded(view acsView) []problem {
	result, hasResult := object(view.record, "guardian", "result")
	response, hasResponse := object(view.record, "response")
	if text(view.record, "guardian", "status") != "decided" || !hasResult || !hasResponse {
		return nil
	}
	entries := extensionEntries(response, acsDecision)
	values := extensionValues(response, acsDecision)
	if len(entries) != 1 || len(values) != 1 {
		return []problem{{"/response/extensions", "the response records the Guardian decision once"}}
	}
	value := values[0]
	var problems []problem
	for _, expected := range []struct {
		name  string
		value any
	}{
		{"decision", result["decision"]},
		{"request_id", result["request_id"]},
		{"evaluator", member(result, "metadata", "evaluator")},
		{"chain_hash", result["chain_hash"]},
		{"modifications_digest", modificationsDigest(result)},
	} {
		if !pyjson.Equal(value[expected.name], expected.value) {
			problems = append(problems, problem{"/response/extensions/" + expected.name, "the recorded " + expected.name + " is not the Guardian's"})
		}
	}
	if member(view.record, "audit_profile") == true {
		if _, isText := value["request_hash"].(string); !isText {
			problems = append(problems, problem{"/response/extensions/request_hash", "ACS-Audit records the request hash"})
		}
	}
	chain := array(view.record, "chain")
	if len(chain) == 0 {
		return problems
	}
	problems = append(problems, chainProblems(chain)...)
	var step map[string]any
	for _, item := range chain {
		if entry, isObject := item.(map[string]any); isObject && pyjson.Equal(entry["step_id"], value["request_id"]) {
			step = entry
			break
		}
	}
	switch {
	case step == nil || !pyjson.Equal(step["entry_hash"], value["chain_hash"]):
		problems = append(problems, problem{"/response/extensions/chain_hash", "the recorded head is not the step's chain head"})
	case holds(value, "request_hash") && !pyjson.Equal(step["request_hash"], value["request_hash"]):
		problems = append(problems, problem{"/response/extensions/request_hash", "the recorded request hash is not the step's"})
	}
	return problems
}

// acsRules are the rules of the profile in the order the reference reports them. A rule added to
// the registry for this profile is one function and one row here.
var acsRules = []struct {
	rule  string
	check func(acsView) []problem
}{
	{RuleACSFailure, acsFailure},
	{RuleACSExpiry, acsExpiry},
	{RuleACSModification, acsModification},
	{RuleACSJudgment, acsJudgment},
	{RuleACSOutcome, acsOutcome},
	{RuleACSRelease, acsRelease},
	{RuleACSRecorded, acsRecorded},
	{RuleACSBasis, func(view acsView) []problem {
		return append(basisProblems(view.record, "guardian"), modificationBasisProblems(view.record)...)
	}},
}

// checkACS returns the findings of an ecl_acs_exchange_v1 record that its schema accepted
// (AC1-003 to AC1-010).
func checkACS(record map[string]any) []Finding {
	view := acsView{
		record:     record,
		outcome:    text(record, "response", "outcome"),
		candidates: exchanges(record, [2]string{"request", "response"}, [2]string{"modification_request", "modification_response"}),
	}
	if text(record, "guardian", "status") == "decided" {
		view.disposition = text(record, "guardian", "result", "decision")
	}
	var out []Finding
	for _, row := range acsRules {
		out = append(out, findings(row.rule, row.check(view))...)
	}
	// AC1-012: the response, and a modification's response, satisfy DCMP2-053 under the response's
	// own rule, which is not one of the profile's.
	out = append(out, findings(ruleOneWay, oneWayResponseProblems(record, [2][]string{{"request"}, {"response"}}, [2][]string{{"modification_request"}, {"modification_response"}}))...)
	// AC1-012: each DCMP-2 message that the record holds satisfies the semantic rules of DCMP-2.
	return append(out, messageFindings(record, []string{"request"}, []string{"response"}, []string{"modification_request"}, []string{"modification_response"})...)
}
