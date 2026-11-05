package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
)

// The registered errors of the binding checks.
const (
	RequestBindingInvalid  = "ecl.error.request-binding-invalid.v1"
	DecisionBindingInvalid = "ecl.error.decision-binding-invalid.v1"
	DigestMismatch         = "ecl.error.digest-mismatch.v1"
	AudienceMismatch       = "ecl.error.audience-mismatch.v1"
	ScopeMismatch          = "ecl.error.scope-mismatch.v1"
)

const respondsTo = "ecl.relation.responds-to.v1"

var (
	outcomes        = map[string]bool{"admit": true, "deny": true, "hold": true, "challenge": true}
	executionEvents = map[string]bool{"execution_released": true, "execution_terminal": true}
	authorityEvents = map[string]bool{"authority_issued": true, "authority_consumed": true}
	looseInstant    = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$`)
	noResponse      = "<none>"
)

// TerminalStateOutcomes lists the response outcomes each terminal state may have (EBMP2-051), with
// "<none>" standing for no response. Only denied may have none (a dependency failure), and it may
// also follow an admit.
var TerminalStateOutcomes = map[string]map[string]bool{
	"succeeded":              {"admit": true},
	"failed":                 {"admit": true},
	"partially_succeeded":    {"admit": true},
	"timed_out":              {"admit": true},
	"cancelled":              {"admit": true},
	"unknown":                {"admit": true},
	"rolled_back":            {"admit": true},
	"compensated":            {"admit": true},
	"expired_before_release": {"admit": true},
	"held":                   {"hold": true},
	"challenged":             {"challenge": true},
	"denied":                 {"deny": true, "admit": true, noResponse: true},
}

// BindingError is objects that do not belong together, or an object that cannot be checked.
type BindingError struct {
	Code    string
	Message string
}

func (e *BindingError) Error() string { return e.Code + ": " + e.Message }

// bound is a decoded object with its name for messages and the code a malformed read raises. Its
// reads panic with a *BindingError, which the exported checks recover and return.
type bound struct {
	value map[string]any
	name  string
	code  string
}

func (b *bound) fail(message string, code ...string) {
	selected := b.code
	if len(code) > 0 {
		selected = code[0]
	}
	panic(&BindingError{Code: selected, Message: b.name + ": " + message})
}

func (b *bound) get(path ...string) any {
	var found any = b.value
	for _, step := range path {
		object, ok := found.(map[string]any)
		if !ok {
			b.fail(strings.Join(path, ".") + " is missing")
		}
		found, ok = object[step]
		if !ok {
			b.fail(strings.Join(path, ".") + " is missing")
		}
	}
	return found
}

func (b *bound) has(path ...string) bool {
	var found any = b.value
	for _, step := range path {
		object, ok := found.(map[string]any)
		if !ok {
			return false
		}
		if found, ok = object[step]; !ok {
			return false
		}
	}
	return true
}

func (b *bound) text(path ...string) string {
	found, ok := b.get(path...).(string)
	if !ok || found == "" {
		b.fail(strings.Join(path, ".") + " is not a non-empty string")
	}
	return found
}

func (b *bound) integer(path ...string) int64 {
	found, ok := pyjson.Int(b.get(path...))
	if !ok {
		b.fail(strings.Join(path, ".") + " is not an integer")
	}
	return found
}

func (b *bound) array(path ...string) []any {
	found, ok := b.get(path...).([]any)
	if !ok {
		b.fail(strings.Join(path, ".") + " is not an array")
	}
	return found
}

func (b *bound) member(path ...string) *bound {
	return read(b.get(path...), b.name+"."+strings.Join(path, "."), b.code)
}

// digest returns a digest member, whole.
func (b *bound) digest(path ...string) map[string]any {
	found := b.member(path...)
	found.text("algorithm")
	found.text("value")
	return found.value
}

// digestPair returns the algorithm and value of a digest member, and nothing else of it.
func (b *bound) digestPair(path ...string) [2]string {
	found := b.member(path...)
	return [2]string{found.text("algorithm"), found.text("value")}
}

func (b *bound) instant(path ...string) instant.Instant {
	text := b.text(path...)
	member := strings.Join(path, ".")
	if !looseInstant.MatchString(text) {
		b.fail(member + " is not an RFC 3339 UTC time")
	}
	parsed, err := instant.Parse(text)
	if err != nil {
		b.fail(member + " is not a time that exists")
	}
	return parsed
}

func read(value any, name, code string) *bound {
	object, ok := value.(map[string]any)
	if !ok {
		panic(&BindingError{Code: code, Message: name + " is not a JSON object"})
	}
	return &bound{value: object, name: name, code: code}
}

func fingerprint(value any, owner *bound) map[string]any {
	reference, err := canon.Reference(value)
	if err != nil {
		owner.fail("cannot be canonicalized, so it has no digest")
	}
	return reference
}

func scopeDigest(request *bound) map[string]any {
	scope := map[string]any{"request_id": request.text("message_id"), "action": request.member("action").value}
	return fingerprint(scope, request)
}

func requireMessage(message *bound, messageType string) {
	if message.text("message_type") != messageType {
		message.fail("is not a " + messageType)
	}
}

func requireEvent(event *bound, eventTypes map[string]bool, kind string) {
	if event.text("object_type") != "event_record" {
		event.fail("is not an event record")
	}
	if !eventTypes[event.text("event_type")] {
		names := make([]string, 0, len(eventTypes))
		for name := range eventTypes {
			names = append(names, name)
		}
		sort.Strings(names)
		event.fail("is not one of " + strings.Join(names, ", "))
	}
	if event.text("event", "kind") != kind {
		event.fail("event.kind is not " + kind)
	}
}

func sameText(left, right *bound, path ...string) {
	if left.text(path...) != right.text(path...) {
		left.fail(strings.Join(path, ".") + " is not the " + right.name + "'s")
	}
}

func sameAttempt(left, right *bound) {
	if left.integer("workflow", "attempt") != right.integer("workflow", "attempt") {
		left.fail("workflow.attempt is not the " + right.name + "'s")
	}
}

func predecessors(owner *bound) []*bound {
	var found []*bound
	for index, entry := range owner.array("workflow", "causal_predecessors") {
		found = append(found, read(entry, fmt.Sprintf("%s.workflow.causal_predecessors[%d]", owner.name, index), owner.code))
	}
	for _, entry := range found {
		entry.text("id")
		entry.digest("digest")
	}
	return found
}

func relation(predecessor *bound) string {
	if predecessor.has("relation") {
		return predecessor.text("relation")
	}
	return ""
}

func answersTheRequest(request, response *bound) {
	if response.text("request_id") != request.text("message_id") {
		response.fail("request_id is not the request's message_id")
	}
}

func admits(response *bound) bool {
	return response != nil && response.text("outcome") == "admit"
}

// catch turns a *BindingError panic into the returned error.
func catch(err *error) {
	if recovered := recover(); recovered != nil {
		problem, ok := recovered.(*BindingError)
		if !ok {
			panic(recovered)
		}
		*err = problem
	}
}

// ErrNegativeSkew is a response clock-skew allowance below zero.
var ErrNegativeSkew = errors.New("the response clock-skew allowance is a non-negative integer of seconds")

// CheckResponseBinding returns a *BindingError unless response is the answer to request
// (DCMP2-044 to DCMP2-050). skewSeconds is the verification profile's allowance (DCMP2-047); the
// reference profile's is 0.
func CheckResponseBinding(request, response any, skewSeconds int64) (err error) {
	if skewSeconds < 0 {
		return ErrNegativeSkew
	}
	defer catch(&err)
	asked := read(request, "request", RequestBindingInvalid)
	answer := read(response, "response", RequestBindingInvalid)
	requireMessage(asked, "decision_request")
	requireMessage(answer, "decision_response")
	answersTheRequest(asked, answer)
	sameText(answer, asked, "workflow", "workflow_id")
	sameText(answer, asked, "workflow", "root_trace_id")
	sameAttempt(answer, asked)
	// 4: exactly one responds-to predecessor, the request, with the request's digest.
	var responding []*bound
	for _, entry := range predecessors(answer) {
		if relation(entry) == respondsTo {
			responding = append(responding, entry)
		}
	}
	if len(responding) != 1 {
		answer.fail("does not have exactly one responds-to predecessor", DigestMismatch)
	}
	only := responding[0]
	if only.text("id") != asked.text("message_id") {
		answer.fail("the responds-to predecessor is not the request", DigestMismatch)
	}
	if !pyjson.Equal(only.digest("digest"), fingerprint(asked.value, asked)) {
		answer.fail("the responds-to predecessor's digest is not the request's", DigestMismatch)
	}
	// 5: not issued before the request, less the allowance.
	if instant.Compare(answer.instant("issued_at"), asked.instant("issued_at").AddSeconds(-skewSeconds)) < 0 {
		answer.fail("issued_at is before the request's")
	}
	outcome := answer.text("outcome")
	if !outcomes[outcome] {
		answer.fail("outcome is not admit, deny, hold or challenge")
	}
	if outcome != "admit" {
		return nil
	}
	// 6a: the audience requested.
	if answer.text("authorization", "audience") != asked.text("authority_request", "audience") {
		answer.fail("authorization.audience is not the audience requested", AudienceMismatch)
	}
	// 6b: the scope digest of {"request_id", "action"}.
	if !pyjson.Equal(answer.digest("authorization", "scope_digest"), scopeDigest(asked)) {
		answer.fail("authorization.scope_digest is not the digest of the request's action", ScopeMismatch)
	}
	// 6c: the use policy requested.
	if answer.text("authorization", "use_policy") != asked.text("authority_request", "use_policy") {
		answer.fail("authorization.use_policy is not the use policy requested")
	}
	// 6d: lasts longer than nothing and no longer than requested.
	start := answer.instant("authorization", "valid_from")
	end := answer.instant("authorization", "valid_until")
	allowed := asked.integer("authority_request", "requested_validity_seconds")
	if !(instant.Compare(end, start) > 0 && instant.Compare(end, start.AddSeconds(allowed)) <= 0) {
		answer.fail("authorization window is empty, or longer than requested")
	}
	// 6d1: single use is one use; no more uses than requested.
	grantedUses := func() (int64, bool) {
		if answer.has("authorization", "max_uses") {
			return answer.integer("authorization", "max_uses"), true
		}
		return 0, false
	}
	if answer.text("authorization", "use_policy") == "single_use" {
		if granted, present := grantedUses(); present && granted != 1 {
			answer.fail("a single_use authorization has a max_uses other than 1")
		}
	}
	if asked.has("authority_request", "max_uses") {
		granted, present := grantedUses()
		if !present || granted > asked.integer("authority_request", "max_uses") {
			answer.fail("authorization.max_uses is missing, or more than the request's")
		}
	}
	// 6d2: contained in the decision.
	if instant.Compare(answer.instant("authorization", "valid_from"), answer.instant("issued_at")) < 0 {
		answer.fail("authorization.valid_from is before issued_at")
	}
	if answer.has("expires_at") && instant.Compare(answer.instant("authorization", "valid_until"), answer.instant("expires_at")) > 0 {
		answer.fail("authorization.valid_until is after expires_at")
	}
	seconds := asked.integer("authority_request", "requested_validity_seconds")
	if instant.Compare(answer.instant("authorization", "valid_until"), answer.instant("issued_at").AddSeconds(seconds)) > 0 {
		answer.fail("authorization.valid_until is after issued_at plus the seconds requested")
	}
	return nil
}

// CheckEventBinding returns a *BindingError unless the execution event (execution_released or
// execution_terminal) records request and response (EBMP2-047 to EBMP2-051). response is nil
// when the decision point gave none.
func CheckEventBinding(event, request, response any) (err error) {
	defer catch(&err)
	recorded := read(event, "event", DecisionBindingInvalid)
	asked := read(request, "request", DecisionBindingInvalid)
	var answer *bound
	if response != nil {
		answer = read(response, "response", DecisionBindingInvalid)
	}
	requireEvent(recorded, executionEvents, "execution")
	requireMessage(asked, "decision_request")
	if answer != nil {
		requireMessage(answer, "decision_response")
	}
	if recorded.text("event", "action_id") != asked.text("action", "action_id") {
		recorded.fail("event.action_id is not the request's action")
	}
	if recorded.has("event", "operation") && recorded.text("event", "operation") != asked.text("action", "operation") {
		recorded.fail("event.operation is not the request's")
	}
	if recorded.has("event", "parameters_digest") {
		if recorded.digestPair("event", "parameters_digest") != asked.digestPair("action", "parameters_digest") {
			recorded.fail("event.parameters_digest is not the request's")
		}
	}
	if recorded.has("event", "target") && recorded.text("event", "target", "uri") != asked.text("action", "target", "uri") {
		recorded.fail("event.target.uri is not the request's")
	}
	if answer != nil {
		answersTheRequest(asked, answer)
	}
	sameText(recorded, asked, "workflow", "workflow_id")
	sameText(recorded, asked, "workflow", "root_trace_id")
	if answer != nil {
		sameText(recorded, answer, "workflow", "workflow_id")
		sameText(recorded, answer, "workflow", "root_trace_id")
	}
	sameAttempt(recorded, asked)
	if answer != nil {
		sameAttempt(recorded, answer)
	}
	if answer == nil {
		if recorded.has("event", "decision") {
			recorded.fail("names a decision, and there is no response")
		}
	} else if recorded.text("event", "decision", "uri") != answer.text("message_id") {
		recorded.fail("event.decision is not the response")
	}
	if answer != nil && !pyjson.Equal(recorded.digest("event", "decision", "digest"), fingerprint(answer.value, answer)) {
		recorded.fail("event.decision.digest is not the response's", DigestMismatch)
	}
	if recorded.has("event", "authority") {
		if !admits(answer) {
			recorded.fail("carries authority, and there is no response that admits")
		}
		if recorded.text("event", "authority", "uri") != answer.text("authorization", "authorization_id") {
			recorded.fail("event.authority is not the response's authorization")
		}
	}
	if recorded.text("event_type") == "execution_released" {
		if !admits(answer) {
			recorded.fail("releases, and there is no response that admits")
		}
	} else {
		state := recorded.text("event", "state")
		wanted, known := TerminalStateOutcomes[state]
		if !known {
			recorded.fail("event.state is not a state that a terminal event may be in")
		}
		outcome := noResponse
		if answer != nil {
			outcome = answer.text("outcome")
		}
		if !wanted[outcome] {
			recorded.fail("event.state does not agree with the outcome of the response")
		}
	}
	return nil
}

// CheckAuthorityEventBinding returns a *BindingError unless the authority event
// (authority_issued or authority_consumed) records the authorization of response (EBMP2-052).
func CheckAuthorityEventBinding(event, response any) (err error) {
	defer catch(&err)
	recorded := read(event, "event", DecisionBindingInvalid)
	answer := read(response, "response", DecisionBindingInvalid)
	requireEvent(recorded, authorityEvents, "authority")
	requireMessage(answer, "decision_response")
	if !admits(answer) {
		recorded.fail("records an authorization, and the response does not admit")
	}
	granted := answer.text("authorization", "authorization_id")
	if recorded.text("event", "authorization_id") != granted {
		recorded.fail("event.authorization_id is not the response's")
	}
	var named []*bound
	for _, entry := range predecessors(recorded) {
		if entry.text("id") == answer.text("message_id") {
			named = append(named, entry)
		}
	}
	if len(named) != 1 {
		recorded.fail("does not follow the response exactly once", DigestMismatch)
	}
	if !pyjson.Equal(named[0].digest("digest"), fingerprint(answer.value, answer)) {
		recorded.fail("the digest of the response it follows is not the response's", DigestMismatch)
	}
	sameText(recorded, answer, "workflow", "workflow_id")
	sameText(recorded, answer, "workflow", "root_trace_id")
	sameAttempt(recorded, answer)
	return nil
}
