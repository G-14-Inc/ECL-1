package bindings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

// Finding is a rule that a record breaks: the registered rule or error identifier, a JSON
// Pointer into the record, and why.
type Finding = semantic.Finding

const (
	digestSuite    = "ecl.digest.sha-256.v1"
	modificationOf = "ecl.relation.modification-of.v1"
	schemaInvalid  = "ecl.error.schema-invalid.v1"
	// decisionBasis is the registered extension in which a decision response records its basis
	// (ECL1N-0181).
	decisionBasis = "ecl.ext.decision-basis.v1"
	// encodedMember is the only member of a record member that holds bound content outside the
	// restricted profile, encoded as the canonical base64 of its RFC 8785 bytes (MG1-012).
	encodedMember = "rfc8785"
	// ruleOneWay is DCMP2-053: the rule under which a binding checker reports a decision basis,
	// recorded by a decision response that a record embeds, that breaks the one-way rule (AB1-013,
	// AC1-012, MG1-007). It is the rule of the response itself, not one of the profile's own rules.
	ruleOneWay = semantic.RuleDecisionBasis
)

var (
	nanosecond = big.NewInt(1_000_000_000)
	outcomes   = []string{"admit", "deny", "hold", "challenge"}
	// noEffectSafeStates are the safe states that permit no new effect of the governed action: the
	// registry marks the first three permits_new_effects false, and the restricted state permits
	// only bounded diagnosis, recovery and safe-shutdown operations, none of which is the action
	// that waits. A fail-open or degraded state can let the action through (DCMP2-041).
	noEffectSafeStates = map[string]bool{"ecl.state.fail-closed.v1": true, "ecl.state.quarantine.v1": true,
		"ecl.state.emergency-halt.v1": true, "ecl.state.restricted.v1": true}
)

// problem is one reason a record breaks a rule: a JSON Pointer into the record, and why.
type problem struct {
	path    string
	message string
}

func findings(rule string, problems []problem) []Finding {
	out := make([]Finding, 0, len(problems))
	for _, item := range problems {
		out = append(out, Finding{RuleID: rule, Path: item.path, Detail: item.message})
	}
	return out
}

// member returns the member at path of nested objects, or nil (Python's None) when a step is not
// there.
func member(value any, path ...string) any {
	found, ok := pyjson.Path(value, path...)
	if !ok {
		return nil
	}
	return found
}

// text returns the string at path, or nil when it is absent or not a string.
func text(value any, path ...string) any {
	if found, ok := member(value, path...).(string); ok {
		return found
	}
	return nil
}

func textOf(value any, path ...string) (string, bool) {
	found, ok := member(value, path...).(string)
	return found, ok
}

// integer returns the integer at path (never a boolean), or false.
func integer(value any, path ...string) (int64, bool) {
	return pyjson.Int(member(value, path...))
}

func object(value any, path ...string) (map[string]any, bool) {
	found, ok := member(value, path...).(map[string]any)
	return found, ok
}

func array(value any, path ...string) []any {
	found, _ := member(value, path...).([]any)
	return found
}

func holds(value any, key string) bool {
	return pyjson.Has(value, key)
}

// nanos returns an ECL instant as nanoseconds since the epoch, or nil when it is not one.
func nanos(value any) *big.Int {
	parsed, err := instant.Parse(value)
	if err != nil {
		return nil
	}
	total := new(big.Int).Mul(big.NewInt(parsed.Seconds), nanosecond)
	return total.Add(total, big.NewInt(parsed.Nanos))
}

// digestOf returns the ecl.digest.sha-256.v1 digest of the restricted canonical JSON of value
// (IE1-001), or nil when value is outside that profile.
func digestOf(value any) map[string]any {
	reference, err := canon.Reference(value)
	if err != nil {
		return nil
	}
	return reference
}

// digestValue returns a digest object as a JSON value: nil stays nil.
func digestValue(digest map[string]any) any {
	if digest == nil {
		return nil
	}
	return digest
}

// contentError is a record member in the encoded form of MG1-012 that does not decode as that
// form requires.
type contentError struct{ message string }

func (e *contentError) Error() string { return e.message }

// isEncoded reports whether value has the shape of the encoded form: an object whose only member
// is rfc8785.
func isEncoded(value any) (map[string]any, bool) {
	encoded, isObject := value.(map[string]any)
	if !isObject || len(encoded) != 1 {
		return nil, false
	}
	_, present := encoded[encodedMember]
	return encoded, present
}

// DecodeContent returns the content that a record member holds: the member itself, or what its
// encoded form decodes to. An encoded member decodes only when its text is canonical base64, its
// bytes are the RFC 8785 canonical form of a JSON object, read as the reference reads I-JSON, and
// that object lies outside the restricted profile, since content within the profile is held as
// itself; otherwise the error says why.
func DecodeContent(value any) (any, error) {
	encoded, isEncodedForm := isEncoded(value)
	if !isEncodedForm {
		return value, nil
	}
	text, isText := encoded[encodedMember].(string)
	if !isText {
		return nil, &contentError{"the encoded content is not a string"}
	}
	data, canonical := envelope.DecodeCanonicalBase64(text)
	if !canonical {
		return nil, &contentError{"the encoded content is not canonical base64"}
	}
	content, err := ParseJWSJSON(data)
	var written []byte
	if err == nil {
		written, err = JCS(content)
	}
	if err != nil {
		return nil, &contentError{"the encoded bytes are not I-JSON with an RFC 8785 form"}
	}
	if !bytes.Equal(written, data) {
		return nil, &contentError{"the encoded bytes are not the RFC 8785 canonical form of the content"}
	}
	if _, isObject := content.(map[string]any); !isObject {
		return nil, &contentError{"the encoded content is not a JSON object"}
	}
	if digestOf(content) != nil {
		return nil, &contentError{"content within the restricted profile is held as itself"}
	}
	return content, nil
}

// decodedRecord returns a copy of record with the member at each of paths replaced by the
// content it holds, and a problem for each member whose encoded form does not decode (MG1-012).
func decodedRecord(record map[string]any, paths [][]string) (map[string]any, []problem) {
	result := make(map[string]any, len(record))
	for key, item := range record {
		result[key] = item
	}
	var problems []problem
	for _, path := range paths {
		parent := result
		for _, step := range path[:len(path)-1] {
			found, isObject := parent[step].(map[string]any)
			if !isObject {
				parent = nil
				break
			}
			copied := make(map[string]any, len(found))
			for key, item := range found {
				copied[key] = item
			}
			parent[step] = copied
			parent = copied
		}
		last := path[len(path)-1]
		value, present := parent[last]
		if parent == nil || !present {
			continue
		}
		decoded, err := DecodeContent(value)
		if err != nil {
			problems = append(problems, problem{"/" + strings.Join(path, "/"), err.Error()})
			continue
		}
		parent[last] = decoded
	}
	return result, problems
}

// sameDigest reports whether two digest objects name the same algorithm and value.
func sameDigest(left, right any) bool {
	leftObject, leftOK := left.(map[string]any)
	_, rightOK := right.(map[string]any)
	if !leftOK || !rightOK {
		return false
	}
	algorithm, hasAlgorithm := leftObject["algorithm"].(string)
	digest, hasValue := leftObject["value"].(string)
	otherAlgorithm, _ := textOf(right, "algorithm")
	otherValue, otherHasValue := textOf(right, "value")
	_, otherHasAlgorithm := textOf(right, "algorithm")
	return hasAlgorithm && hasValue && otherHasAlgorithm && otherHasValue && algorithm == otherAlgorithm && digest == otherValue
}

// binds reports whether response is bound to request under DCMP2-044 to DCMP2-050.
func binds(request, response any) bool {
	_, requestOK := request.(map[string]any)
	_, responseOK := response.(map[string]any)
	if !requestOK || !responseOK {
		return false
	}
	err := evidence.CheckResponseBinding(request, response, 0)
	var refusal *evidence.BindingError
	if errors.As(err, &refusal) {
		return false
	}
	if err != nil {
		raise(err)
	}
	return true
}

// extensionValues returns the values of the extensions with this identifier that value carries.
func extensionValues(value any, identifier string) []map[string]any {
	var found []map[string]any
	for _, item := range array(value, "extensions") {
		entry, isObject := item.(map[string]any)
		if !isObject || !pyjson.Equal(entry["id"], identifier) {
			continue
		}
		if content, isObject := entry["value"].(map[string]any); isObject {
			found = append(found, content)
		}
	}
	return found
}

// extensionEntries returns the whole extension entries with this identifier.
func extensionEntries(value any, identifier string) []map[string]any {
	var found []map[string]any
	for _, item := range array(value, "extensions") {
		if entry, isObject := item.(map[string]any); isObject && pyjson.Equal(entry["id"], identifier) {
			found = append(found, entry)
		}
	}
	return found
}

// exchange is a decision request of a record and the response to it, if the record has one.
type exchange struct {
	request  map[string]any
	response any
}

func (e exchange) requestID() any { return text(e.request, "message_id") }

func (e exchange) outcome() any { return text(e.response, "outcome") }

func exchanges(record map[string]any, pairs ...[2]string) []exchange {
	var found []exchange
	for _, pair := range pairs {
		request, isObject := object(record, pair[0])
		if !isObject {
			continue
		}
		var response any
		if answer, isObject := object(record, pair[1]); isObject {
			response = answer
		}
		found = append(found, exchange{request: request, response: response})
	}
	return found
}

func inWindow(at, start, end *big.Int) bool {
	return at != nil && start != nil && end != nil && start.Cmp(at) <= 0 && at.Cmp(end) < 0
}

// releaseProblems is each reason a recorded release is not one that an admit authorized: the
// request it names must be one the record holds, its response must admit and be bound to it, the
// released digest must be the request's, and the time must lie in the authorization's window.
func releaseProblems(release any, candidates []exchange) []problem {
	if release == nil {
		return nil
	}
	if _, isObject := release.(map[string]any); !isObject {
		return []problem{{"/release", "the release record is not an object"}}
	}
	named := text(release, "request_id")
	var chosen *exchange
	for index := range candidates {
		if candidates[index].requestID() == named {
			chosen = &candidates[index]
			break
		}
	}
	if chosen == nil {
		return []problem{{"/release/request_id", "the release names no decision request of the record"}}
	}
	if chosen.response == nil || chosen.outcome() != "admit" {
		return []problem{{"/release/request_id", "the action was released without an admit"}}
	}
	if !binds(chosen.request, chosen.response) {
		return []problem{{"/release/request_id", "the admit is not bound to the exact request"}}
	}
	var problems []problem
	if !sameDigest(member(release, "parameters_digest"), member(chosen.request, "action", "parameters_digest")) {
		problems = append(problems, problem{"/release/parameters_digest", "the released parameters are not the admitted ones"})
	}
	released := nanos(member(release, "released_at"))
	start := nanos(member(chosen.response, "authorization", "valid_from"))
	end := nanos(member(chosen.response, "authorization", "valid_until"))
	if !inWindow(released, start, end) {
		problems = append(problems, problem{"/release/released_at", "the release lies outside the authorization's window"})
	}
	return problems
}

// unchangedByModification are the members of a decision request that the new request for a
// modification keeps from the original (AB1-004, AC1-005); in its action, only action_id,
// parameters and parameters_digest change. Its message_id, times, workflow and extensions are its
// own.
var unchangedByModification = []string{"issuer", "actor", "subject", "delegation_chain", "authority_request", "constraints", "integrity_policy"}

var changedInModifiedAction = map[string]bool{"action_id": true, "parameters": true, "parameters_digest": true}

// modificationProblems is each way modified is not the new request for a modification (AB1-004,
// AC1-005): its own message_id, the parameters as the same JSON values (sameJSON, so a boolean
// never stands for a number) and their digest, the modification-of link, and
// the original's action, actor and subject. Paths are relative to the
// record, without the leading slash.
func modificationProblems(original map[string]any, modified, parameters any) []problem {
	if _, isObject := modified.(map[string]any); !isObject {
		return []problem{{"modification_request", "the modification has no new decision request"}}
	}
	var problems []problem
	identifier := text(modified, "message_id")
	if identifier == nil || identifier == text(original, "message_id") {
		problems = append(problems, problem{"modification_request/message_id", "the new request reuses the id"})
	}
	actual := member(modified, "action", "parameters")
	if _, isObject := parameters.(map[string]any); !isObject || !sameJSON(actual, parameters) {
		problems = append(problems, problem{"modification_request/action/parameters", "the parameters are not the modified ones"})
	}
	expected := digestOf(actual)
	if expected == nil || !sameDigest(member(modified, "action", "parameters_digest"), expected) {
		problems = append(problems, problem{"modification_request/action/parameters_digest", "the digest is not that of the parameters"})
	}
	originalDigest := digestValue(digestOf(original))
	originalID := text(original, "message_id")
	linked := false
	for _, item := range array(modified, "workflow", "causal_predecessors") {
		entry, isObject := item.(map[string]any)
		if isObject && pyjson.Equal(entry["id"], originalID) && pyjson.Equal(entry["relation"], modificationOf) && sameDigest(entry["digest"], originalDigest) {
			linked = true
			break
		}
	}
	if !linked {
		problems = append(problems, problem{"modification_request/workflow/causal_predecessors", "the new request does not name the original as modification-of"})
	}
	for _, name := range unchangedByModification {
		if !sameJSON(member(original, name), member(modified, name)) {
			problems = append(problems, problem{"modification_request/" + name, "the new request changes the original's " + name})
		}
	}
	before, _ := object(original, "action")
	after, _ := object(modified, "action")
	seen := map[string]bool{}
	var names []string
	for _, side := range []map[string]any{before, after} {
		for name := range side {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	// Byte order of UTF-8 is code-point order, the order of Python's sorted.
	sort.Strings(names)
	for _, name := range names {
		if !changedInModifiedAction[name] && !sameJSON(before[name], after[name]) {
			problems = append(problems, problem{"modification_request/action/" + name, "the new request changes the action's " + name})
		}
	}
	return problems
}

// newRequestProblems returns each member of a new request that a record holds although its
// decision is not a modification (AB1-004, AC1-005), as the reference's new_request_problems:
// only a MODIFY or a modify has a new request, so the record of any other decision, or of a
// decision failure, holds no modification_request and no modification_response.
func newRequestProblems(record map[string]any) []problem {
	var problems []problem
	for _, name := range []string{"modification_request", "modification_response"} {
		if _, present := record[name]; present {
			problems = append(problems, problem{"/" + name, "only a modification has a new decision request"})
		}
	}
	return problems
}

// modificationResponseProblems returns a modification response that a record of a modification
// holds without the new request it answers (AB1-004, AC1-005), as the reference's
// modification_response_problems. A record of a modification that holds neither a new request
// nor a release shows a deny of the original with no new request, which releases nothing.
func modificationResponseProblems(record map[string]any) []problem {
	if _, present := record["modification_response"]; present {
		return []problem{{"/modification_response", "a modification response answers no new request"}}
	}
	return nil
}

// deferralProblems is a hold or challenge whose expiry could release the action: it must carry
// expires_at, no later than the deadline when there is one, and a safe_state that permits no new
// effect (DCMP2-018, DCMP2-041).
func deferralProblems(response any, deadline *big.Int) []problem {
	var problems []problem
	expires := nanos(member(response, "expires_at"))
	if expires == nil || (deadline != nil && expires.Cmp(deadline) > 0) {
		problems = append(problems, problem{"/response/expires_at", "the response outlasts the deadline it maps"})
	}
	if state, isText := textOf(response, "safe_state"); !isText || !noEffectSafeStates[state] {
		problems = append(problems, problem{"/response/safe_state", "the safe state on expiry permits a new effect"})
	}
	return problems
}

// inputProblems is each way the inputs break the one-way rule of the core standard. The inputs
// are entries of the decision basis (ecl.ext.decision-basis.v1), each with the member its profile
// adds. Inputs at the positions in judgmentRequired must be judgment. Only an available
// verifiable input supports an outcome, whatever the outcome (ECL1N-0181), and an admit rests on
// at least one (DCMP2-053).
func inputProblems(inputs []any, outcome any, judgmentRequired []int) []problem {
	var problems []problem
	for _, index := range judgmentRequired {
		if text(inputs[index], "class") != "judgment" {
			problems = append(problems, problem{fmt.Sprintf("/inputs/%d/class", index), "this input must be judgment"})
		}
	}
	supported := false
	for index, item := range inputs {
		if text(item, "effect") != "supports" {
			continue
		}
		if text(item, "class") != "verifiable" || text(item, "status") != "available" {
			problems = append(problems, problem{fmt.Sprintf("/inputs/%d/effect", index), "only a verifiable input can be the basis of admit"})
		}
		if text(item, "class") == "verifiable" {
			supported = true
		}
	}
	if outcome == "admit" && !supported {
		problems = append(problems, problem{"/inputs", "the admit rests on no verifiable input"})
	}
	return problems
}

// oneWayResponseProblems returns each way a decision response of the record breaks DCMP2-053
// (AB1-013, AC1-012, MG1-007), as the reference's one_way_response_problems. Each exchange names
// the path of a decision request in the record and the path of the decision response that answers
// it. Each response carries exactly one value of ecl.ext.decision-basis.v1, since a response
// without one shows no basis that a checker of the record could see. Each response is checked as a
// decision response is checked on its own, with its outcome and evaluated_at:
// semantic.OneWayProblemsAt runs on each value that it carries. With the request that the record
// holds, evidence.RequestProblems refuses an input recorded as verifiable whose source is the
// request's actor, and a request recorded as received before it was issued, as an evidence
// verifier does with the request of a signed bundle under the reference verification profile. A
// response that the record does not hold has nothing to check.
func oneWayResponseProblems(record map[string]any, exchanges ...[2][]string) []problem {
	var problems []problem
	for _, exchange := range exchanges {
		requestPath, responsePath := exchange[0], exchange[1]
		response, isObject := object(record, responsePath...)
		if !isObject || text(response, "message_type") != "decision_response" {
			continue
		}
		request, isRequest := object(record, requestPath...)
		admit := text(response, "outcome") == "admit"
		prefix := "/" + strings.Join(responsePath, "/") + "/extensions"
		type carried struct {
			index int
			entry map[string]any
		}
		var found []carried
		for index, item := range array(response, "extensions") {
			entry, isEntry := item.(map[string]any)
			if isEntry && pyjson.Equal(entry["id"], decisionBasis) {
				found = append(found, carried{index, entry})
			}
		}
		if len(found) != 1 {
			problems = append(problems, problem{prefix, "the decision response does not carry exactly one decision basis"})
		}
		for _, current := range found {
			value, isValue := current.entry["value"].(map[string]any)
			if !isValue {
				continue
			}
			for _, item := range semantic.OneWayProblemsAt(value, admit, response["outcome"], response["evaluated_at"]) {
				problems = append(problems, problem{fmt.Sprintf("%s/%d/value%s", prefix, current.index, item[0]), item[1]})
			}
			if isRequest {
				for _, item := range evidence.RequestProblems(value, request, 0) {
					problems = append(problems, problem{fmt.Sprintf("%s/%d/value%s", prefix, current.index, item[0]), item[1]})
				}
			}
		}
	}
	return problems
}

// basisClassProblems returns each entry of a decision basis that the response at responsePath
// records whose input a profile gives a class (required, keyed by semantic.InputKey) and that
// records another class (AB1-006, AC1-004), as the reference's basis_class_problems. The class
// that a profile gives an input holds in every decision basis that the record holds, the
// modification response's included, whose admit releases the modified action (AB1-004, AC1-005).
func basisClassProblems(record map[string]any, responsePath []string, required map[string]string) []problem {
	response, isObject := object(record, responsePath...)
	if !isObject || len(required) == 0 {
		return nil
	}
	var problems []problem
	prefix := "/" + strings.Join(responsePath, "/") + "/extensions"
	for index, item := range array(response, "extensions") {
		entry, isEntry := item.(map[string]any)
		if !isEntry || !pyjson.Equal(entry["id"], decisionBasis) {
			continue
		}
		for position, input := range array(entry["value"], "inputs") {
			name, isName := pyjson.Text(member(input, "input"))
			if !isName {
				continue
			}
			expected, isRequired := required[semantic.InputKey(name)]
			if isRequired && text(input, "class") != expected {
				problems = append(problems, problem{fmt.Sprintf("%s/%d/value/inputs/%d/class", prefix, index, position), "this input must be " + expected + ", as the record's inputs class it"})
			}
		}
	}
	return problems
}

// singleBasis returns the value of the one ecl.ext.decision-basis.v1 that the response at name
// carries, with its position among the response's extensions; false when it carries none, more
// than one, or a value that is not an object.
func singleBasis(record map[string]any, name string) (int, map[string]any, bool) {
	position, found := -1, 0
	var value any
	for index, item := range array(member(record, name), "extensions") {
		if entry, isEntry := item.(map[string]any); isEntry && pyjson.Equal(entry["id"], decisionBasis) {
			found++
			position, value = index, entry["value"]
		}
	}
	basis, isObject := value.(map[string]any)
	return position, basis, found == 1 && isObject
}

// derivedKeys returns the input keys of the names in an entry's derived_from; an absent
// derived_from names no input.
func derivedKeys(entry any) map[string]bool {
	keys := map[string]bool{}
	for _, name := range array(entry, "derived_from") {
		if text, isText := name.(string); isText {
			keys[semantic.InputKey(text)] = true
		}
	}
	return keys
}

// modificationBasisProblems returns each way the decision basis of the record's
// modification_response disagrees with the record (AB1-013, AC1-012), as the reference's
// modification_basis_problems: it carries the register reference of
// the basis of the response, member for member, and records the record's inputs, each once,
// compared as input names are (semantic.InputKey), each with the class, required, source and
// derived_from that the record's input gives it. The status, effect, reference and times of an
// entry describe the new decision and may differ. A record whose response or
// modification_response does not carry exactly one decision basis is left to
// oneWayResponseProblems, which reports it.
func modificationBasisProblems(record map[string]any) []problem {
	_, first, hasFirst := singleBasis(record, "response")
	index, value, hasSecond := singleBasis(record, "modification_response")
	if !hasFirst || !hasSecond {
		return nil
	}
	prefix := fmt.Sprintf("/modification_response/extensions/%d/value", index)
	var problems []problem
	if !sameJSON(value["register"], first["register"]) {
		problems = append(problems, problem{prefix + "/register", "the modification response carries another register reference"})
	}
	// As the reference's dict comprehension: a later input with the same key wins, in the place
	// of the first.
	declared := map[string]any{}
	var order []string
	for _, item := range array(record, "inputs") {
		name, isText := textOf(item, "input")
		if !isText {
			continue
		}
		key := semantic.InputKey(name)
		if _, seen := declared[key]; !seen {
			order = append(order, key)
		}
		declared[key] = item
	}
	listed := map[string]bool{}
	for position, entry := range array(value, "inputs") {
		name, isText := textOf(entry, "input")
		if !isText {
			continue
		}
		key := semantic.InputKey(name)
		listed[key] = true
		item, known := declared[key]
		path := fmt.Sprintf("%s/inputs/%d", prefix, position)
		if !known {
			problems = append(problems, problem{path + "/input", "the record lists no such input"})
			continue
		}
		for _, field := range []string{"class", "required"} {
			if !sameJSON(member(entry, field), member(item, field)) {
				problems = append(problems, problem{path + "/" + field, "the " + field + " is not the one the record's inputs give"})
			}
		}
		source, hasSource := textOf(entry, "source")
		given, hasGiven := textOf(item, "source")
		if !hasSource || !hasGiven || semantic.InputKey(source) != semantic.InputKey(given) {
			problems = append(problems, problem{path + "/source", "the source is not the one the record's inputs give"})
		}
		derived, expected := derivedKeys(entry), derivedKeys(item)
		same := len(derived) == len(expected)
		for key := range derived {
			if !expected[key] {
				same = false
			}
		}
		if !same {
			problems = append(problems, problem{path + "/derived_from", "derived_from is not the one the record's inputs give"})
		}
	}
	for _, key := range order {
		if !listed[key] {
			name, _ := textOf(declared[key], "input")
			problems = append(problems, problem{prefix + "/inputs", "the modification response does not record the input " + name})
		}
	}
	return problems
}

// messageFindings returns the findings of the semantic rules of DCMP-2 for each DCMP-2 message
// that the record holds at one of paths (AB1-013, AC1-012, MG1-007), at the message's place in the
// record, as the reference's message_findings. The one-way rule of a decision basis is left to
// oneWayResponseProblems, which applies it with the record's requests.
func messageFindings(record map[string]any, paths ...[]string) []Finding {
	var out []Finding
	for _, path := range paths {
		message, isObject := object(record, path...)
		if !isObject || text(message, "protocol") != "DCMP-2" {
			continue
		}
		prefix := "/" + strings.Join(path, "/")
		found, err := evidence.ObjectFindings(message)
		if err != nil {
			out = append(out, Finding{RuleID: schemaInvalid, Path: prefix, Detail: "object validation could not be completed: " + err.Error()})
			continue
		}
		// Each rule that the message fails is reported once, at the message's place in the
		// record, with the first of its findings as the detail, as the reference's
		// message_findings: the paths and the number of findings inside a message are the
		// object stage's, which reports them when the message is validated on its own.
		first := map[string]string{}
		var rules []string
		for _, item := range found {
			if item.RuleID == ruleOneWay {
				continue
			}
			if _, seen := first[item.RuleID]; !seen {
				first[item.RuleID] = item.Detail
				rules = append(rules, item.RuleID)
			}
		}
		sort.Strings(rules)
		for _, rule := range rules {
			out = append(out, Finding{RuleID: rule, Path: prefix, Detail: first[rule]})
		}
	}
	return out
}

// sameJSON is the reference's same_json: two JSON values of the same Python type that are equal,
// so a boolean never equals a number and an integer never equals a float.
func sameJSON(left, right any) bool {
	switch value := left.(type) {
	case map[string]any:
		other, isObject := right.(map[string]any)
		if !isObject || len(value) != len(other) {
			return false
		}
		for key, item := range value {
			second, present := other[key]
			if !present || !sameJSON(item, second) {
				return false
			}
		}
		return true
	case []any:
		other, isList := right.([]any)
		if !isList || len(value) != len(other) {
			return false
		}
		for index := range value {
			if !sameJSON(value[index], other[index]) {
				return false
			}
		}
		return true
	case bool:
		other, isBool := right.(bool)
		return isBool && value == other
	case string:
		other, isText := right.(string)
		return isText && value == other
	case nil:
		return right == nil
	}
	kind := numberKind(left)
	return kind != "" && kind == numberKind(right) && pyjson.Equal(left, right)
}

// numberKind is the Python type of a JSON number: int or float; empty for anything else.
func numberKind(value any) string {
	switch number := value.(type) {
	case json.Number:
		if strings.ContainsAny(number.String(), ".eE") {
			return "float"
		}
		return "int"
	case int, int64:
		return "int"
	case float64:
		return "float"
	}
	return ""
}

// pointerTo is the JSON Pointer of the item at index of the array at prefix.
func pointerTo(prefix string, index int) string { return prefix + "/" + strconv.Itoa(index) }

// jsonInt is an integer as the number text that the strict parser returns for it.
func jsonInt(value int64) string { return strconv.FormatInt(value, 10) }

// prefixed puts a leading slash on the relative paths of modificationProblems.
func prefixed(problems []problem) []problem {
	out := make([]problem, len(problems))
	for index, item := range problems {
		out[index] = problem{"/" + item.path, item.message}
	}
	return out
}

// basisProblems returns each way the record's inputs disagree with the decision basis that its
// response records in ecl.ext.decision-basis.v1 (AB1-013, AC1-012).
//
// Each input of the record, without the member marker that its profile adds, equals the entry of
// the basis whose input is the same, and each entry appears in the record exactly once. A
// response that does not carry the extension records no inputs. One that carries it more than
// once, or whose value has no inputs array, agrees with no record. A record without a response
// has nothing to agree with.
func basisProblems(record map[string]any, marker string) []problem {
	response, hasResponse := object(record, "response")
	if !hasResponse {
		return nil
	}
	extensions := array(response, "extensions")
	var positions []int
	for index, item := range extensions {
		if entry, isObject := item.(map[string]any); isObject {
			if identifier, isText := entry["id"].(string); isText && identifier == decisionBasis {
				positions = append(positions, index)
			}
		}
	}
	if len(positions) > 1 {
		return []problem{{"/response/extensions", "the response records its decision basis more than once"}}
	}
	var entries []any
	prefix := "/response/extensions"
	if len(positions) == 1 {
		prefix = fmt.Sprintf("/response/extensions/%d/value/inputs", positions[0])
		listed, isList := member(extensions[positions[0]], "value", "inputs").([]any)
		if !isList {
			return []problem{{prefix, "the decision basis has no inputs array"}}
		}
		entries = listed
	}
	var problems []problem
	// The positions of the entries under each name they give, the names in order of first use.
	named := map[string][]int{}
	var names []string
	for position, entry := range entries {
		name, isText := textOf(entry, "input")
		if !isText {
			problems = append(problems, problem{fmt.Sprintf("%s/%d", prefix, position), "the decision-basis entry names no input"})
			continue
		}
		if _, seen := named[name]; !seen {
			names = append(names, name)
		}
		named[name] = append(named[name], position)
	}
	listedNames := map[string]bool{}
	for index, item := range array(record, "inputs") {
		path := fmt.Sprintf("/inputs/%d", index)
		name, hasName := textOf(item, "input")
		if hasName && listedNames[name] {
			problems = append(problems, problem{path + "/input", "the record lists this input more than once"})
			continue
		}
		if hasName {
			listedNames[name] = true
		}
		var matches []int
		if hasName {
			matches = named[name]
		}
		if len(matches) != 1 {
			message := "the response's decision basis does not record this input"
			if len(matches) > 1 {
				message = "the response's decision basis records this input more than once"
			}
			problems = append(problems, problem{path + "/input", message})
			continue
		}
		own := map[string]any{}
		if input, isObject := item.(map[string]any); isObject {
			for key, value := range input {
				if key != marker {
					own[key] = value
				}
			}
		}
		recorded, isObject := entries[matches[0]].(map[string]any)
		if !isObject {
			recorded = map[string]any{}
		}
		keys := map[string]bool{}
		for key := range own {
			keys[key] = true
		}
		for key := range recorded {
			keys[key] = true
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		// Byte order of UTF-8 is code-point order, the order of Python's sorted.
		sort.Strings(ordered)
		for _, key := range ordered {
			mine, inOwn := own[key]
			theirs, inRecorded := recorded[key]
			if inOwn != inRecorded || !sameJSON(mine, theirs) {
				problems = append(problems, problem{path + "/" + key, "the " + key + " is not the one the response records"})
			}
		}
	}
	for _, name := range names {
		if !listedNames[name] {
			for _, position := range named[name] {
				problems = append(problems, problem{fmt.Sprintf("%s/%d/input", prefix, position), "the record does not list this input"})
			}
		}
	}
	return problems
}
