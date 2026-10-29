package bindings

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
)

// MCP-GATEWAY-1: an ECL enforcement point between a governed AI system and its MCP servers. The
// pinned MCP revision is 2026-07-28. A record may hold MCP content in the encoded form of
// MG1-012; the checker decodes it first and reports a member that does not decode, or whose
// content does not satisfy the definition that the record schema gives the same content held as
// itself, as a schema failure, with no finding of the profile's rules. MCPRefusalCause
// reads a decoded member without that check, so it reads any JSON value there.
const (
	MCPRevision        = "2026-07-28"
	MCPExchangeVersion = "ecl_mcp_gateway_exchange_v1"
	MCPExchangeSchema  = "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1"
	mcpBinding         = "ecl.ext.mcp-binding.v1"

	RuleMCPFailure    = "ecl.rule.mcp-decision-failure-not-forwarded.v1"
	RuleMCPReview     = "ecl.rule.mcp-tool-mapped-and-reviewed.v1"
	RuleMCPRequest    = "ecl.rule.mcp-request-from-call.v1"
	RuleMCPForward    = "ecl.rule.mcp-forward-requires-admit.v1"
	RuleMCPObligation = "ecl.rule.mcp-obligations-discharged.v1"
	RuleMCPRefusal    = "ecl.rule.mcp-refusal-defined.v1"
	RuleMCPResult     = "ecl.rule.mcp-result-bound.v1"

	// MG1-013: the record of the pre-release obligations that the gateway discharged, the
	// coupling extension whose deferred witness it discharges too, and the type that names that
	// witness.
	mcpDischarge     = "ecl.ext.obligation-discharge.v1"
	mcpCoupling      = "ecl.ext.consequence-coupling.v1"
	mcpVerifyWitness = "ecl.obligation.verify-witness.v1"

	// MCPServerErrorCode replaces a server error's code when that code is one of the error
	// table's (MG1-010).
	MCPServerErrorCode = -32603
)

var (
	// MG1-002: the requests a gateway always sends to the Decision Layer before forwarding.
	mcpSideEffecting = map[string]bool{"tools/call": true, "tasks/update": true}
	// MCPErrors is the error table of MG1-006, outside the range that JSON-RPC 2.0 reserves.
	MCPErrors = map[string]int64{
		"denied": -31001, "held": -31002, "challenged": -31003, "decision-unavailable": -31004,
		"decision-invalid": -31005, "authorization-unusable": -31006, "not-mapped": -31007,
		"unreviewed-change": -31008, "forward-failed": -31009, "obligation-unproven": -31010,
		"evidence-unavailable": -31011,
	}
	mcpRefusalForOutcome = map[string]string{"deny": "denied", "hold": "held", "challenge": "challenged"}
	mcpNonRelease        = map[string]bool{"denied": true, "held": true, "challenged": true, "expired_before_release": true}
	mappingMembers       = []string{"mapping_id", "server_id", "server_name", "server_version", "tool", "tool_definition_digest", "action_class", "operation", "risk_class", "evidence_profile"}
	mcpTableCodes        = func() map[int64]bool {
		codes := map[int64]bool{}
		for _, code := range MCPErrors {
			codes[code] = true
		}
		return codes
	}()
	// mcpContentPaths are the record members that hold MCP content, which may be in the encoded
	// form of MG1-012.
	mcpContentPaths = [][]string{{"call"}, {"tool_definition"}, {"forwarded", "request"}, {"server_response"}, {"returned"}}
	// mcpContentDefinitions name the definition of the record schema that each member's content
	// satisfies when it is held as itself, and so also when it is held in the encoded form of
	// MG1-012, in the order of mcpContentPaths.
	mcpContentDefinitions = []string{"jsonRpcRequest", "toolDefinition", "jsonRpcRequest", "jsonRpcResponse", "jsonRpcResponse"}
	// mcpDigestMembers name the members of ecl.ext.mcp-binding.v1 that hold the digests of a
	// request's input responses and request state.
	mcpDigestMembers = map[string]string{"inputResponses": "input_responses_digest", "requestState": "request_state_digest"}
)

// mcpCallMembers are the members of a request (MG1-004); a request with any other member is
// refused with -31007, because no decision binds it.
var mcpCallMembers = map[string]bool{"jsonrpc": true, "id": true, "method": true, "params": true}

// mcpSafeMagnitude is the largest magnitude of a number that every RFC 8785 implementation keeps
// exactly (RFC 7493 section 2.2); a request whose id or params holds a larger one is refused with
// -31007 (MG1-004).
var mcpSafeMagnitude = big.NewRat(9007199254740991, 1)

// pointerName returns the JSON Pointer form of one member name.
func pointerName(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}

// beyondSafe reports whether a JSON number's magnitude is greater than 2^53 - 1, compared
// exactly as Python compares an int or a float with an int.
func beyondSafe(value any) bool {
	number, ok := pyjson.Number(value)
	return ok && new(big.Rat).Abs(number).Cmp(mcpSafeMagnitude) > 0
}

type numberAt struct {
	path  string
	value any
}

// numbersIn returns each number in value with its JSON Pointer, booleans excluded, in the order of
// the reference's sorted paths.
func numbersIn(value any, path string) []numberAt {
	var found []numberAt
	type pending struct {
		item any
		path string
	}
	stack := []pending{{value, path}}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch item := current.item.(type) {
		case map[string]any:
			for name, child := range item {
				stack = append(stack, pending{child, current.path + "/" + pointerName(name)})
			}
		case []any:
			for index, child := range item {
				stack = append(stack, pending{child, fmt.Sprintf("%s/%d", current.path, index)})
			}
		case float64, int64, int, json.Number:
			found = append(found, numberAt{current.path, item})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].path < found[j].path })
	return found
}

// MCPUnboundProblems returns each reason why MG1-004 has the gateway refuse a request with -31007,
// and not forward it, before any decision, as the reference's unbound_problems: a member other
// than jsonrpc, id, method and params, which no decision binds, and a number in id or params of
// magnitude greater than 2^53 - 1, which RFC 8785 may not represent exactly.
func MCPUnboundProblems(call map[string]any, prefix string) []problem {
	var names []string
	for name := range call {
		if !mcpCallMembers[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var problems []problem
	for _, name := range names {
		problems = append(problems, problem{prefix + "/" + pointerName(name), "no decision binds this member"})
	}
	for _, name := range []string{"id", "params"} {
		item, present := call[name]
		if !present {
			continue
		}
		for _, found := range numbersIn(item, prefix+"/"+name) {
			if beyondSafe(found.value) {
				problems = append(problems, problem{found.path, "the number's magnitude is greater than 2^53 - 1"})
			}
		}
	}
	return problems
}

// mcpSideEffectingMethod reports whether method names a request that MG1-002 sends to the
// Decision Layer.
func mcpSideEffectingMethod(method any) bool {
	name, isText := method.(string)
	return isText && mcpSideEffecting[name]
}

// MCPReturnedFor is the response a gateway returns for a forwarded request whose server answered
// (MG1-010): the server's response unchanged, except that a JSON-RPC error whose code is one of
// the error table's is returned with the code -32603, so that the governed AI system never reads
// a server's error as a refusal by the gateway.
func MCPReturnedFor(serverResponse map[string]any) map[string]any {
	result, _ := deepCopy(serverResponse).(map[string]any)
	if failure, isObject := result["error"].(map[string]any); isObject {
		if code, isInteger := pyjson.Int(failure["code"]); isInteger && mcpTableCodes[code] {
			replaced := make(map[string]any, len(failure))
			for key, item := range failure {
				replaced[key] = item
			}
			replaced["code"] = json.Number(jsonInt(MCPServerErrorCode))
			result["error"] = replaced
		}
	}
	return result
}

const (
	errExpired             = "ecl.error.expired.v1"
	errReplay              = "ecl.error.replay.v1"
	errUnavailable         = "ecl.error.dependency-unavailable.v1"
	errUnsupported         = "ecl.error.binding-unsupported.v1"
	errUnreviewed          = "ecl.error.control-change-unreviewed.v1"
	errObligationUnproven  = "ecl.error.obligation-unproven.v1"
	errEvidenceUnavailable = "ecl.error.evidence-unavailable.v1"
	// MG1-014 step 5: the wall clock regressed or disagreed with the monotonic clock.
	mcpClockRegressed = "ecl.error.clock-regressed.v1"
)

type toolMapping struct {
	values map[string]any
	digest map[string]any
}

func (m *toolMapping) get(name string) any { return m.values[name] }

func readMapping(record map[string]any) *toolMapping {
	value, isObject := object(record, "mapping")
	if !isObject {
		return nil
	}
	for _, name := range mappingMembers {
		if !holds(value, name) {
			return nil
		}
	}
	digest, isObject := value["tool_definition_digest"].(map[string]any)
	if !isObject {
		return nil
	}
	return &toolMapping{values: value, digest: digest}
}

// target is the target URI the mapping derives from the call's arguments, or nil.
func (m *toolMapping) target(arguments map[string]any) any {
	argument, uri := m.values["target_argument"], m.values["target_uri"]
	if (argument == nil) == (uri == nil) {
		return nil
	}
	if uri != nil {
		return uri
	}
	if found, isText := arguments[pyjson.Str(argument)].(string); isText && strings.Contains(found, ":") {
		return found
	}
	return nil
}

// changed reports whether the tool definition or the server identity differs from the reviewed
// mapping (MG1-008).
func (m *toolMapping) changed(definition, server map[string]any) bool {
	if definition == nil || server == nil {
		return true
	}
	current, err := JCSDigest(definition)
	if err != nil {
		if errors.Is(err, ErrJCS) {
			return true
		}
		raise(err)
	}
	return !sameDigest(current, m.digest) || !pyjson.Equal(server["name"], m.get("server_name")) ||
		!pyjson.Equal(server["version"], m.get("server_version")) || !pyjson.Equal(definition["name"], m.get("tool"))
}

// bindingValue is the value of ecl.ext.mcp-binding.v1 on a decision request (MG1-004): the
// server, tool, reviewed tool-definition digest and mapping, the digest of the call's complete
// params, its _meta included, which the gateway forwards exactly (MG1-005), and the digests of any
// input responses and request state.
func (m *toolMapping) bindingValue(params map[string]any, method string) (map[string]any, error) {
	paramsDigest, err := JCSDigest(params)
	if err != nil {
		return nil, err
	}
	value := map[string]any{
		"mcp_revision": MCPRevision, "method": method, "server_id": m.get("server_id"),
		"server_name": m.get("server_name"), "server_version": m.get("server_version"), "tool": m.get("tool"),
		"tool_definition_digest": m.digest, "mapping_id": m.get("mapping_id"), "params_digest": paramsDigest,
	}
	if holds(params, "inputResponses") {
		digest, err := JCSDigest(params["inputResponses"])
		if err != nil {
			return nil, err
		}
		value["input_responses_digest"] = digest
	}
	if holds(params, "requestState") {
		digest, err := JCSDigest(params["requestState"])
		if err != nil {
			return nil, err
		}
		value["request_state_digest"] = digest
	}
	return value, nil
}

type mcpView struct {
	record    map[string]any
	call      map[string]any
	mapping   *toolMapping
	request   any
	response  any
	status    any
	forwarded any
	released  any
	recovery  any
}

func newMCPView(record map[string]any) mcpView {
	view := mcpView{record: record, call: map[string]any{}, mapping: readMapping(record), status: text(record, "decision", "status")}
	if call, isObject := object(record, "call"); isObject {
		view.call = call
	}
	if request, isObject := object(record, "decision_request"); isObject {
		view.request = request
	}
	if response, isObject := object(record, "decision", "response"); isObject {
		view.response = response
	}
	if forwarded, isObject := object(record, "forwarded"); isObject {
		view.forwarded = forwarded
	}
	if released, isObject := object(record, "released"); isObject {
		view.released = released
	}
	if recovery, isObject := object(record, "recovery"); isObject {
		view.recovery = recovery
	}
	return view
}

// guard is the record's release guard in nanoseconds, zero when it gives none (MG1-014).
func (v mcpView) guard() *big.Int {
	milliseconds, ok := integer(v.record, "release_guard_milliseconds")
	if !ok || milliseconds < 0 {
		return big.NewInt(0)
	}
	return new(big.Int).Mul(big.NewInt(milliseconds), big.NewInt(1_000_000))
}

func (v mcpView) admitted() bool {
	return v.status == "answered" && text(v.response, "outcome") == "admit" && binds(v.request, v.response)
}

// unusable is EXPIRED or REPLAY when an admit cannot be used at the given time and until the
// record's release guard after it (MG1-014), else "".
// guardExceeded reports a cancelled terminal observed later than the recorded release plus the
// record's release guard: the write could not begin within the guard (MG1-014), which the
// record shows.
func (v mcpView) guardExceeded() bool {
	if v.released == nil || text(v.record, "terminal", "event", "state") != "cancelled" {
		return false
	}
	releasedAt := nanos(member(v.released, "observed_at"))
	endedAt := nanos(member(v.record, "terminal", "observed_at"))
	if releasedAt == nil || endedAt == nil {
		return false
	}
	return endedAt.Cmp(new(big.Int).Add(releasedAt, v.guard())) > 0
}

func (v mcpView) unusable(at any) string {
	end := nanos(member(v.response, "authorization", "valid_until"))
	if end != nil {
		end = new(big.Int).Sub(end, v.guard())
	}
	if !inWindow(nanos(at), nanos(member(v.response, "authorization", "valid_from")), end) {
		return errExpired
	}
	limit, limited := integer(v.response, "authorization", "max_uses")
	if text(v.response, "authorization", "use_policy") == "single_use" {
		limit, limited = 1, true
	}
	prior, _ := integer(v.record, "prior_uses")
	if limited && prior+1 > limit {
		return errReplay
	}
	return ""
}

// mcpPreReleaseObligations is MG1-013 on an admit: what it leaves to Enforcement before the
// release, by (obligation_id, type), in order and each once: each obligation whose satisfaction is
// before_release, and each witness result of ecl.ext.consequence-coupling.v1 whose outcome is
// required_before_release, named by the uri of its reference and the type
// ecl.obligation.verify-witness.v1 (EBMP-2 EBMP2-070); and the keys of every obligation it
// carries, the deferred witnesses included.
func mcpPreReleaseObligations(response any) ([][2]string, map[[2]string]bool) {
	var required [][2]string
	needed := map[[2]string]bool{}
	carried := map[[2]string]bool{}
	add := func(key [2]string, need bool) {
		carried[key] = true
		if need && !needed[key] {
			needed[key] = true
			required = append(required, key)
		}
	}
	for _, item := range array(response, "obligations") {
		identifier, hasID := textOf(item, "id")
		kind, hasType := textOf(item, "type")
		if !hasID || !hasType {
			continue
		}
		add([2]string{identifier, kind}, pyjson.Equal(member(item, "satisfaction"), "before_release"))
	}
	for _, value := range extensionValues(response, mcpCoupling) {
		witness := member(value, "witness_result")
		uri, hasURI := textOf(witness, "reference", "uri")
		if pyjson.Equal(member(witness, "outcome"), "required_before_release") && hasURI {
			add([2]string{uri, mcpVerifyWitness}, true)
		}
	}
	return required, carried
}

// mcpDischargeProblems returns each way the value of ecl.ext.obligation-discharge.v1 at path
// fails to discharge what response leaves to Enforcement before the release (MG1-013): an entry
// that names an obligation the response does not carry or that another entry names, an entry
// whose result is not satisfied, and each pre-release obligation that no entry names.
// mcpRepeatedObligationIDs lists the ids that the response's obligation list names more than
// once.
func mcpRepeatedObligationIDs(response any) []string {
	seen := map[string]bool{}
	var repeated []string
	for _, item := range array(response, "obligations") {
		identifier, isText := text(item, "id").(string)
		if !isText {
			continue
		}
		if seen[identifier] && !containsText(repeated, identifier) {
			repeated = append(repeated, identifier)
		}
		seen[identifier] = true
	}
	return repeated
}

func containsText(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func mcpDischargeProblems(value, response any, path string) []problem {
	required, carried := mcpPreReleaseObligations(response)
	var problems []problem
	named := map[[2]string]bool{}
	for index, entry := range array(value, "obligations") {
		where := fmt.Sprintf("%s/obligations/%d", path, index)
		identifier, hasID := textOf(entry, "obligation_id")
		kind, hasType := textOf(entry, "type")
		key := [2]string{identifier, kind}
		if !hasID || !hasType || !carried[key] {
			problems = append(problems, problem{where, "names an obligation that the admit does not carry"})
			continue
		}
		if named[key] {
			problems = append(problems, problem{where, "names an obligation that another entry names"})
			continue
		}
		named[key] = true
		if !pyjson.Equal(member(entry, "result"), "satisfied") {
			problems = append(problems, problem{where + "/result", "records an obligation that was not met"})
		}
	}
	for _, key := range required {
		if !named[key] {
			problems = append(problems, problem{path, fmt.Sprintf("no entry discharges the obligation %s (%s)", key[0], key[1])})
		}
	}
	return problems
}

// discharged reports whether the record shows a discharge of every pre-release obligation of its
// admit (MG1-013).
func (v mcpView) discharged() bool {
	required, _ := mcpPreReleaseObligations(v.response)
	if len(required) == 0 {
		return true
	}
	value, isObject := object(v.record, "obligation_discharge")
	return isObject && len(mcpDischargeProblems(value, v.response, "")) == 0
}

// mcpJournalFailed reports whether the gateway returned -31011: its journal could not record an
// entry before the release (MG1-017), which the record itself cannot show.
func mcpJournalFailed(record map[string]any) bool {
	return pyjson.Equal(member(record, "returned", "error", "code"), json.Number(jsonInt(MCPErrors["evidence-unavailable"]))) &&
		pyjson.Equal(member(record, "returned", "error", "data", "ecl", "code"), "evidence-unavailable")
}

// MCPRefusal is the row of the error table for a request that the gateway refused.
type MCPRefusal struct {
	Cause     string
	Reason    any
	RequestID any
}

// MCPRefusalCause returns the cause, reason and request identifier of the error table for a
// request the gateway refused, or false when nothing in the record required a refusal. The causes
// are tried in the order of MG1-006, and the first that holds is the one the gateway returns. A
// record cannot show that the gateway's evidence log failed (-31011, MG1-017): when the gateway
// returned that error, the cause is taken in its place in the order, after every earlier cause was
// found not to hold.
func MCPRefusalCause(original map[string]any) (MCPRefusal, bool) {
	record, _ := decodedRecord(original, mcpContentPaths)
	view := newMCPView(record)
	params := member(view.call, "params")
	arguments := member(params, "arguments")
	if view.mapping == nil || len(MCPUnboundProblems(view.call, "/call")) > 0 || !mcpSideEffectingMethod(view.call["method"]) || !pyjson.Equal(member(params, "name"), view.mapping.get("tool")) {
		return MCPRefusal{"not-mapped", errUnsupported, nil}, true
	}
	// An arguments member that is not an object, null included, is a cause of -31007: a null is
	// not an absent member.
	if holds(params, "arguments") {
		if _, isObject := arguments.(map[string]any); !isObject || digestOf(arguments) == nil {
			return MCPRefusal{"not-mapped", errUnsupported, nil}, true
		}
	}
	argumentObject, _ := arguments.(map[string]any)
	if argumentObject == nil {
		argumentObject = map[string]any{}
	}
	if view.mapping.target(argumentObject) == nil {
		return MCPRefusal{"not-mapped", errUnsupported, nil}, true
	}
	definition, _ := object(record, "tool_definition")
	server, _ := object(record, "server")
	if view.mapping.changed(definition, server) {
		return MCPRefusal{"unreviewed-change", errUnreviewed, nil}, true
	}
	if view.status == "unavailable" || view.status == nil {
		return MCPRefusal{"decision-unavailable", errUnavailable, nil}, true
	}
	if view.status == "invalid" {
		return MCPRefusal{"decision-invalid", text(record, "decision", "error"), nil}, true
	}
	if !binds(view.request, view.response) {
		return MCPRefusal{"decision-invalid", "ecl.error.request-binding-invalid.v1", nil}, true
	}
	requestID := text(view.response, "request_id")
	if outcome, isText := textOf(view.response, "outcome"); isText {
		if refused, known := mcpRefusalForOutcome[outcome]; known {
			var first any
			if reasons := array(view.response, "reasons"); len(reasons) > 0 {
				first = reasons[0]
			}
			return MCPRefusal{refused, text(first, "code"), requestID}, true
		}
	}
	// MG1-017: once the use is consumed, a journal that fails cancels the attempt,
	// and that failure is the refusal's cause, whatever the gateway had still to discharge.
	if mcpJournalFailed(record) && text(record, "terminal", "event", "state") == "cancelled" {
		return MCPRefusal{"evidence-unavailable", errEvidenceUnavailable, requestID}, true
	}
	if !view.discharged() {
		return MCPRefusal{"obligation-unproven", errObligationUnproven, requestID}, true
	}
	if mcpJournalFailed(record) {
		return MCPRefusal{"evidence-unavailable", errEvidenceUnavailable, requestID}, true
	}
	// MG1-014 and MG1-015: the write begins within the declared release guard after
	// the final observation, or not at all; a cancelled terminal observed later than the release
	// event plus the guard shows a write that could not begin in time.
	if view.guardExceeded() {
		return MCPRefusal{"authorization-unusable", errExpired, requestID}, true
	}
	if problem := view.unusable(member(record, "returned_at")); problem != "" {
		return MCPRefusal{"authorization-unusable", problem, requestID}, true
	}
	return MCPRefusal{}, false
}

// MCPTerminalState is the execution_terminal state for what the server returned (MG1-010).
func MCPTerminalState(response any) string {
	serverResponse, isObject := response.(map[string]any)
	if !isObject {
		return "unknown"
	}
	if holds(serverResponse, "error") {
		return "failed"
	}
	result, isObject := serverResponse["result"].(map[string]any)
	if !isObject {
		return "unknown"
	}
	var kind any = "complete"
	if holds(result, "resultType") {
		kind = result["resultType"]
	}
	if !pyjson.Equal(kind, "complete") {
		return "unknown"
	}
	if result["isError"] == true {
		return "failed"
	}
	return "succeeded"
}

// mcpFailure is MG1-007: a decision was sought, and the gateway forwarded although the decision
// service was unavailable, answered with no verified decision, or left no answer on record. A
// forward with no decision request at all is the concern of MG1-002 and MG1-005.
func mcpFailure(view mcpView) []problem {
	asked := view.status == "unavailable" || view.status == "invalid" || (view.status == nil && view.request != nil)
	if view.forwarded != nil && asked {
		return []problem{{"/forwarded", "forwarded without a verified decision"}}
	}
	return nil
}

func mcpReview(view mcpView) []problem {
	if view.forwarded == nil {
		return nil
	}
	if !mcpSideEffectingMethod(view.call["method"]) {
		return []problem{{"/forwarded", "forwarded a request whose method has no mapping"}}
	}
	if view.mapping == nil || !pyjson.Equal(member(view.call, "params", "name"), view.mapping.get("tool")) {
		return []problem{{"/forwarded", "forwarded a call to a tool that has no mapping"}}
	}
	definition, _ := object(view.record, "tool_definition")
	server, _ := object(view.record, "server")
	if view.mapping.changed(definition, server) {
		return []problem{{"/forwarded", "forwarded a call to a tool whose change is not reviewed"}}
	}
	return nil
}

func mcpRequest(view mcpView) []problem {
	mapping := view.mapping
	request, isObject := view.request.(map[string]any)
	if !isObject {
		return nil
	}
	// MG1-004: a call with a member or a number that no decision can bind is refused, not decided.
	problems := MCPUnboundProblems(view.call, "/call")
	if mapping == nil {
		return problems
	}
	action, _ := object(request, "action")
	for _, pair := range [][2]string{{"action_class", "action_class"}, {"operation", "operation"}, {"risk_class", "risk_class"}, {"required_evidence_profile", "evidence_profile"}} {
		if !pyjson.Equal(action[pair[0]], mapping.get(pair[1])) {
			problems = append(problems, problem{"/decision_request/action/" + pair[0], "not the mapping's"})
		}
	}
	params, isObject := object(view.call, "params")
	if !isObject {
		params = map[string]any{}
	}
	var arguments any = map[string]any{}
	if holds(params, "arguments") {
		arguments = params["arguments"]
	}
	argumentObject, argumentsAreObject := arguments.(map[string]any)
	// MG1-004: the parameters are the call's arguments as the same JSON values, so a number never
	// stands for a boolean.
	if !argumentsAreObject || !sameJSON(action["parameters"], arguments) {
		problems = append(problems, problem{"/decision_request/action/parameters", "not the call's arguments"})
	} else if !sameDigest(action["parameters_digest"], digestValue(digestOf(arguments))) {
		problems = append(problems, problem{"/decision_request/action/parameters_digest", "not their digest"})
	}
	if !argumentsAreObject {
		argumentObject = map[string]any{}
	}
	if !pyjson.Equal(text(action, "target", "uri"), mapping.target(argumentObject)) {
		problems = append(problems, problem{"/decision_request/action/target", "not the target the mapping derives"})
	}
	entries := extensionEntries(request, mcpBinding)
	values := extensionValues(request, mcpBinding)
	if len(entries) != 1 || len(values) != 1 || entries[0]["critical"] != true {
		return append(problems, problem{"/decision_request/extensions", "the critical mcp-binding is missing"})
	}
	expected, err := mapping.bindingValue(params, pyjson.Str(view.call["method"]))
	if err != nil && !errors.Is(err, ErrJCS) {
		raise(err)
	}
	var expectedValue any
	if err == nil {
		expectedValue = expected
	}
	if !pyjson.Equal(values[0], expectedValue) {
		problems = append(problems, problem{"/decision_request/extensions", "the mcp-binding does not name the call and mapping"})
	}
	return problems
}

func mcpForward(view mcpView) []problem {
	if view.forwarded == nil {
		return nil
	}
	if !view.admitted() {
		return []problem{{"/forwarded", "forwarded without an admit bound to the decision request"}}
	}
	var problems []problem
	if view.unusable(member(view.forwarded, "forwarded_at")) != "" {
		problems = append(problems, problem{"/forwarded/forwarded_at", "forwarded when the authorization was unusable"})
	}
	// MG1-015: the forward's time is the final observation that the release event records.
	if view.released != nil && !pyjson.Equal(member(view.forwarded, "forwarded_at"), member(view.released, "observed_at")) {
		problems = append(problems, problem{"/forwarded/forwarded_at", "not the observation that the release event records"})
	}
	forwardedAt := nanos(member(view.forwarded, "forwarded_at"))
	completed := nanos(member(view.forwarded, "forward_completed_at"))
	if completed != nil && forwardedAt != nil && completed.Cmp(forwardedAt) < 0 {
		problems = append(problems, problem{"/forwarded/forward_completed_at", "the send completed before the forward"})
	}
	// MG1-015: the gateway's own observation of the write; the answer's arrival
	// after valid_until is not a late release.
	terminal, _ := object(view.record, "terminal")
	for _, value := range extensionValues(terminal, mcpBinding) {
		if value["released_after_valid_until"] == true {
			problems = append(problems, problem{"/terminal/extensions", "the gateway observed the write at or after valid_until"})
			break
		}
	}
	// MG1-014: the release event declares the guard that the record names.
	if declared, ok := integer(view.record, "release_guard_milliseconds"); ok && view.released != nil {
		if held, has := integer(view.released, "event", "release_guard_ms"); !has || held != declared {
			problems = append(problems, problem{"/released/event/release_guard_ms", "not the record's release guard"})
		}
	}
	// MG1-014: an admit that names one obligation twice is refused before any use.
	if len(mcpRepeatedObligationIDs(view.response)) > 0 {
		problems = append(problems, problem{"/forwarded", "forwarded on an admit that names one obligation twice"})
	}
	sent, isObject := object(view.forwarded, "request")
	if !isObject {
		sent = map[string]any{}
	}
	bound := view.bound()
	// MG1-005: the gateway changes no member of the call, so each member is compared as the same
	// JSON value: an id of 1 forwarded as true is a changed member.
	for _, name := range []string{"jsonrpc", "id"} {
		_, inSent := sent[name]
		_, inCall := view.call[name]
		if inSent != inCall || !sameJSON(sent[name], view.call[name]) {
			problems = append(problems, problem{"/forwarded/request/" + name, "not the call's"})
		}
	}
	// MG1-005: exactly the call, so no member is added to it or removed from it.
	compared := map[string]bool{"jsonrpc": true, "id": true, "method": true, "params": true}
	differs := false
	for _, pair := range [][2]map[string]any{{sent, view.call}, {view.call, sent}} {
		for name, value := range pair[0] {
			other, present := pair[1][name]
			if !compared[name] && (!present || !sameJSON(value, other)) {
				differs = true
			}
		}
	}
	if differs {
		problems = append(problems, problem{"/forwarded/request", "adds, removes or changes a member of the call"})
	}
	if !sameJSON(sent["method"], view.call["method"]) || !bound.matches("method", sent["method"], true) {
		problems = append(problems, problem{"/forwarded/request/method", "not the call's or not what the admit binds"})
	}
	params, hasParams := object(sent, "params")
	for _, name := range []string{"name", "arguments", "inputResponses", "requestState"} {
		value := member(params, name)
		present := hasParams && holds(params, name)
		if !sameJSON(value, member(view.call, "params", name)) || !bound.matches(name, value, present) {
			problems = append(problems, problem{"/forwarded/request/params/" + name, "not the call's or not what the admit binds"})
		}
	}
	forwardedParams := member(sent, "params")
	if !sameJSON(forwardedParams, member(view.call, "params")) || !bound.bindsParams(forwardedParams) {
		problems = append(problems, problem{"/forwarded/request/params", "not the call's or not what the admit binds"})
	}
	return problems
}

// mcpBound is what an admitted decision request binds of the request to forward (MG1-005): its
// method and tool from the request's ecl.ext.mcp-binding.v1, its arguments as action.parameters,
// the digest of its complete params, and the digests of any input responses and request state.
type mcpBound struct {
	request   any
	extension map[string]any
}

// bindsParams is whether the admitted request carries, as params_digest, the digest of the RFC
// 8785 form of params (MG1-004, MG1-005).
func (b mcpBound) bindsParams(params any) bool {
	if b.extension == nil {
		// The request names no single binding; MG1-004's rule reports that.
		return true
	}
	object, isObject := params.(map[string]any)
	if !isObject {
		return false
	}
	digest, err := JCSDigest(object)
	if err != nil {
		if !errors.Is(err, ErrJCS) {
			raise(err)
		}
		return false
	}
	return sameDigest(b.extension["params_digest"], digest)
}

func (v mcpView) bound() mcpBound {
	values := extensionValues(v.request, mcpBinding)
	if len(values) == 1 {
		return mcpBound{v.request, values[0]}
	}
	return mcpBound{v.request, nil}
}

// matches reports whether value, the member name of the forwarded request's params (or its
// method), is what the admitted request binds, compared as the same JSON value.
func (b mcpBound) matches(name string, value any, present bool) bool {
	if name == "arguments" {
		if !present {
			value = map[string]any{}
		}
		return sameJSON(value, member(b.request, "action", "parameters"))
	}
	if b.extension == nil {
		// The request names no single binding; MG1-004's rule reports that, and only the
		// arguments can be compared here.
		return true
	}
	switch name {
	case "method":
		return sameJSON(value, b.extension["method"])
	case "name":
		return sameJSON(value, b.extension["tool"])
	}
	digestName := mcpDigestMembers[name]
	if !present {
		return !holds(b.extension, digestName)
	}
	digest, err := JCSDigest(value)
	if err != nil {
		if !errors.Is(err, ErrJCS) {
			raise(err)
		}
		return false
	}
	return sameDigest(b.extension[digestName], digest)
}

// mcpObligations is MG1-013: a forward on an admit that leaves obligations to Enforcement before
// the release rests on a release event that records the discharge of each of them.
func mcpObligations(view mcpView) []problem {
	if view.forwarded == nil || !view.admitted() {
		return nil
	}
	required, _ := mcpPreReleaseObligations(view.response)
	if len(required) == 0 {
		return nil
	}
	if view.released == nil {
		return []problem{{"/released", "no release event records the discharge of the obligations"}}
	}
	var indexes []int
	var entries []map[string]any
	for index, item := range array(view.released, "extensions") {
		if entry, isObject := item.(map[string]any); isObject && pyjson.Equal(entry["id"], mcpDischarge) {
			indexes = append(indexes, index)
			entries = append(entries, entry)
		}
	}
	if len(entries) != 1 {
		return []problem{{"/released/extensions", "the release records no single discharge"}}
	}
	value, isObject := entries[0]["value"].(map[string]any)
	if !isObject {
		return []problem{{"/released/extensions", "the release records no single discharge"}}
	}
	problems := mcpDischargeProblems(value, view.response, fmt.Sprintf("/released/extensions/%d/value", indexes[0]))
	if held, isObject := object(view.record, "obligation_discharge"); isObject && !sameJSON(held, value) {
		problems = append(problems, problem{"/obligation_discharge", "not the discharge that the release records"})
	}
	return problems
}

func mcpRefusal(view mcpView) []problem {
	if view.forwarded != nil || view.recovery != nil {
		// A recovered record holds no response returned to the governed AI system (MG1-016).
		return nil
	}
	returned, isObject := object(view.record, "returned")
	if !isObject {
		returned = map[string]any{}
	}
	if holds(returned, "result") || !holds(returned, "error") {
		return []problem{{"/returned", "a request that was not forwarded got no error"}}
	}
	var problems []problem
	// A JSON-RPC error answers the call that has the same id, as the same JSON value.
	_, returnedID := returned["id"]
	_, callID := view.call["id"]
	if returnedID != callID || !sameJSON(returned["id"], view.call["id"]) || !pyjson.Equal(returned["jsonrpc"], "2.0") {
		problems = append(problems, problem{"/returned/id", "the error does not answer the call"})
	}
	cause, refused := MCPRefusalCause(view.record)
	if !refused {
		return problems
	}
	expected := map[string]any{"code": cause.Cause}
	if cause.Reason != nil {
		expected["reason"] = cause.Reason
	}
	if cause.RequestID != nil {
		expected["request_id"] = cause.RequestID
	}
	code := json.Number(jsonInt(MCPErrors[cause.Cause]))
	// MG1-014 step 5: a gateway refuses an authorization as unusable with
	// ecl.error.clock-regressed.v1 when its clock readings disagreed, which the record cannot show;
	// a checker accepts that reason where the record shows the window as the cause.
	data := member(returned, "error", "data", "ecl")
	accepted := pyjson.Equal(data, expected)
	if !accepted && cause.Cause == "authorization-unusable" {
		regressed := map[string]any{}
		for key, value := range expected {
			regressed[key] = value
		}
		regressed["reason"] = mcpClockRegressed
		accepted = pyjson.Equal(data, regressed)
	}
	if !pyjson.Equal(member(returned, "error", "code"), code) || !accepted {
		problems = append(problems, problem{"/returned/error", "the cause " + cause.Cause + " has another error"})
	}
	return problems
}

// mcpRecovered is MG1-016: a recovered record claims only what its journal showed, and its
// terminal says when it was recovered; a record that is not recovered has no recovered terminal.
func mcpRecovered(view mcpView, terminal map[string]any, hasTerminal bool) []problem {
	var marked []any
	someMarked := false
	for _, value := range extensionValues(terminal, mcpBinding) {
		marked = append(marked, value["recovered_at"])
		if value["recovered_at"] != nil {
			someMarked = true
		}
	}
	if view.recovery == nil {
		if someMarked {
			return []problem{{"/terminal/extensions", "a terminal of recovery in a record that is not one"}}
		}
		return nil
	}
	if !hasTerminal {
		return []problem{{"/terminal", "a recovered record has no terminal event"}}
	}
	classification := text(view.recovery, "classification")
	state, isText := textOf(terminal, "event", "state")
	var problems []problem
	if classification == "outcome-recorded" {
		if someMarked {
			problems = append(problems, problem{"/terminal/extensions", "a recorded outcome is marked as recovered"})
		}
		return problems
	}
	if len(marked) != 1 || !pyjson.Equal(marked[0], member(view.recovery, "recovered_at")) {
		problems = append(problems, problem{"/terminal/extensions", "the recovered terminal does not say when"})
	}
	if classification == "outcome-unknown" && (view.forwarded == nil || state != "unknown" || holds(view.record, "server_response")) {
		problems = append(problems, problem{"/terminal/event/state", "a released request of unknown outcome is not unknown"})
	}
	if classification == "not-released" && (view.forwarded != nil || !isText || (!mcpNonRelease[state] && state != "cancelled")) {
		problems = append(problems, problem{"/terminal/event/state", "a request that was not released is recorded as released"})
	}
	return problems
}

// mcpCompletionProblems is MG1-015: the terminal of a forward records its completion as the record
// does. Whether the release was late is the gateway's own observation (released_after_valid_until),
// which the forward rule reads; it is not derived from the completion.
func mcpCompletionProblems(view mcpView, terminal map[string]any) []problem {
	values := extensionValues(terminal, mcpBinding)
	completed := member(view.forwarded, "forward_completed_at")
	if len(values) != 1 {
		return nil
	}
	if !pyjson.Equal(values[0]["forward_completed_at"], completed) {
		return []problem{{"/terminal/extensions", "the terminal does not record the forward's completion"}}
	}
	return nil
}

func mcpResult(view mcpView) []problem {
	terminal, hasTerminal := object(view.record, "terminal")
	problems := mcpRecovered(view, terminal, hasTerminal)
	if view.forwarded == nil {
		state, isText := textOf(terminal, "event", "state")
		// MG1-014: a refusal after the authorization was consumed is a cancelled attempt, and a
		// cancelled attempt is one whose use the gateway consumed, or that recovery settled. A
		// journal that failed (MG1-017) may have recorded the consumed use and not the prepared
		// release, which the record then cannot show.
		consumed := member(view.record, "prepared") != nil || view.released != nil
		allowed := mcpNonRelease
		if consumed {
			allowed = map[string]bool{"cancelled": true}
		} else if view.recovery != nil || mcpJournalFailed(view.record) {
			allowed = map[string]bool{"cancelled": true}
			for name := range mcpNonRelease {
				allowed[name] = true
			}
		}
		if hasTerminal && (!isText || !allowed[state]) {
			problems = append(problems, problem{"/terminal/event/state", "a refused request is recorded as released"})
		}
		return problems
	}
	if view.recovery != nil {
		// The journal does not show what the governed AI system received (MG1-016).
		if hasTerminal && view.request != nil {
			err := evidence.CheckEventBinding(terminal, view.request, view.response)
			var refusal *evidence.BindingError
			if errors.As(err, &refusal) {
				problems = append(problems, problem{"/terminal", "the terminal event is not bound: " + refusal.Code})
			} else if err != nil {
				raise(err)
			}
		}
		return problems
	}
	serverResponse, answered := object(view.record, "server_response")
	returned := member(view.record, "returned")
	if _, isObject := returned.(map[string]any); !isObject {
		returned = nil
	}
	// MG1-010: the response returned is the one the evidence binds, as the same JSON values, so
	// false returned as 0 is another response.
	if answered && !sameJSON(returned, MCPReturnedFor(serverResponse)) {
		problems = append(problems, problem{"/returned", "not the response the evidence binds, as MG1-010 returns it"})
	}
	if !answered && !pyjson.Equal(member(returned, "error", "code"), json.Number(jsonInt(MCPErrors["forward-failed"]))) {
		problems = append(problems, problem{"/returned", "an unanswered forward is not reported as forward-failed"})
	}
	if !hasTerminal {
		return append(problems, problem{"/terminal", "a forwarded request has no terminal evidence"})
	}
	var response any
	if answered {
		response = serverResponse
	}
	state := MCPTerminalState(response)
	if text(terminal, "event", "state") != state {
		problems = append(problems, problem{"/terminal/event/state", "the server's response reads as " + state})
	}
	problems = append(problems, mcpCompletionProblems(view, terminal)...)
	values := extensionValues(terminal, mcpBinding)
	if answered {
		bound, err := JCSDigest(serverResponse)
		if err != nil && !errors.Is(err, ErrJCS) {
			raise(err)
		}
		if len(values) != 1 || err != nil || !sameDigest(values[0]["response_digest"], bound) {
			problems = append(problems, problem{"/terminal/extensions", "the evidence does not bind the response"})
		}
	}
	if view.request != nil {
		err := evidence.CheckEventBinding(terminal, view.request, view.response)
		var refusal *evidence.BindingError
		if errors.As(err, &refusal) {
			problems = append(problems, problem{"/terminal", "the terminal event is not bound: " + refusal.Code})
		} else if err != nil {
			raise(err)
		}
	}
	return problems
}

// mcpRules are the rules of the profile in the order the reference reports them. A rule added to
// the registry for this profile is one function and one row here.
var mcpRules = []struct {
	rule  string
	check func(mcpView) []problem
}{
	{RuleMCPFailure, mcpFailure},
	{RuleMCPReview, mcpReview},
	{RuleMCPRequest, mcpRequest},
	{RuleMCPForward, mcpForward},
	{RuleMCPObligation, mcpObligations},
	{RuleMCPRefusal, mcpRefusal},
	{RuleMCPResult, mcpResult},
}

// decodedContentProblems returns a problem for each member of original held in the encoded form
// of MG1-012 whose content, as decoded holds it, does not satisfy the definition that the record
// schema gives the same content held as itself: a call or a forwarded request with a null id or a
// jsonrpc of "1.0" fails jsonRpcRequest in either form.
func decodedContentProblems(original, decoded map[string]any) []problem {
	var problems []problem
	for index, path := range mcpContentPaths {
		if _, encoded := isEncoded(member(original, path...)); !encoded {
			continue
		}
		name := mcpContentDefinitions[index]
		valid, err := schema.ECL().Valid(MCPExchangeSchema+"#/$defs/"+name, member(decoded, path...))
		if err != nil {
			raise(err)
		}
		if !valid {
			problems = append(problems, problem{"/" + strings.Join(path, "/"), "the decoded content does not satisfy " + name})
		}
	}
	return problems
}

// checkMCP returns the findings of an ecl_mcp_gateway_exchange_v1 record that its schema accepted
// (MG1-002 to MG1-012). A member in the encoded form of MG1-012 is decoded first; a member that
// does not decode, or whose content does not satisfy the definition that the record schema gives
// the same content held as itself, fails the record's schema, and the profile's rules are then
// not applied.
func checkMCP(original map[string]any) []Finding {
	record, problems := decodedRecord(original, mcpContentPaths)
	if len(problems) == 0 {
		problems = decodedContentProblems(original, record)
	}
	if len(problems) > 0 {
		return findings(schemaInvalid, problems)
	}
	view := newMCPView(record)
	var out []Finding
	for _, row := range mcpRules {
		out = append(out, findings(row.rule, row.check(view))...)
	}
	if view.status == "answered" {
		// MG1-007: a decision held as answered is a verified decision response, which carries
		// exactly one decision basis and satisfies DCMP2-053 as any decision response does.
		out = append(out, findings(ruleOneWay, oneWayResponseProblems(record, [2][]string{{"decision_request"}, {"decision", "response"}}))...)
	}
	// MG1-007: each DCMP-2 message that the record holds satisfies the semantic rules of DCMP-2,
	// other than the response of a decision whose status is invalid: the gateway refused that
	// response, and the record keeps it as evidence of what it refused.
	held := [][]string{{"decision_request"}}
	if view.status != "invalid" {
		held = append(held, []string{"decision", "response"})
	}
	return append(out, messageFindings(record, held...)...)
}
