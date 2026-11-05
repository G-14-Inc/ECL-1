package bindings

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// OTEL-EVIDENCE-EXPORT-1: copies of ECL decisions and evidence as OpenTelemetry log records. No
// record carries a digest that can be computed without a secret (OE1-004): with the deployment's
// export key, the digests of the object and of its parameters are HMAC-SHA-256 under that key and
// the record names the key (OE1-010); without one, the record carries no digest. The identifiers
// of people and records (ecl.actor.id, ecl.subject.id, ecl.action.target) belong to a record only
// when the export policy declares them (OE1-005), and each row of the attribute table applies only
// to the objects it names. An intValue and a time are read as the exact integer that their
// decimal text of at most 20 digits names; other text is not an integer.
const (
	OTelProfile       = "OTEL-EVIDENCE-EXPORT-1/1.0"
	OTelExportVersion = "ecl_otel_export_record_v1"
	OTelExportSchema  = "https://externalcontrollayer.ai/ns/schema/binding/otel-export/1"
	outcomeReason     = "ecl.ext.outcome-reason.v1"

	// ExportKeysVersion is the schema_version of an export key file (OE1-010).
	ExportKeysVersion = "ecl_otel_export_keys_v1"
	// MinExportKeyBytes is the least size of an export key.
	MinExportKeyBytes = 32
	// The attributes that a record carries only with an export key (OE1-010).
	OTelObjectDigest     = "ecl.object.digest"
	OTelParametersDigest = "ecl.action.parameters_digest"
	OTelKeyID            = "ecl.export.key_id"

	SeverityInfo  = 9
	SeverityWarn  = 13
	SeverityError = 17

	// The EBMP-2 event kinds that the attribute table's rows name.
	executionKind = "execution"
	decisionKind  = "decision"
	authorityKind = "authority"
	requestKind   = "request"
	terminalEvent = "execution_terminal"

	// The DCMP-2 message types that the attribute table's rows name. Each row applies only to the
	// objects it names, also when another message type holds the same member, such as the
	// safe_state of a control message.
	decisionRequest  = "decision_request"
	decisionResponse = "decision_response"
	// OTelRequestID carries the identifier of the request (OE1-004).
	OTelRequestID = "ecl.request.id"

	RuleOTelExport    = "ecl.rule.otel-export-after-evidence.v1"
	RuleOTelMatch     = "ecl.rule.otel-record-matches-object.v1"
	RuleOTelMinimized = "ecl.rule.otel-record-minimized.v1"
	RuleOTelSeverity  = "ecl.rule.otel-severity-mapped.v1"
)

type attributeSource struct {
	name string
	path []string
}

var (
	warnStates   = map[string]bool{"denied": true, "held": true, "challenged": true, "expired_before_release": true, "rolled_back": true, "compensated": true}
	errorStates  = map[string]bool{"failed": true, "partially_succeeded": true, "timed_out": true, "cancelled": true, "unknown": true}
	emergencyOps = map[string]bool{"halt": true, "quarantine": true}
	// otlpDecimal is a decimal integer of the OTLP JSON encoding: a 64-bit field never needs more
	// than 20 digits.
	otlpDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,19})$`)
	// otlpFixed64 is the range of an OTLP fixed64, such as a timestamp in nanoseconds (OE1-007).
	otlpFixed64 = new(big.Int).Lsh(big.NewInt(1), 64)
	// requestIDTypes are the messages that identify their request by request_id (OE1-004,
	// DCMP2-019, DCMP2-020).
	requestIDTypes = map[string]bool{decisionResponse: true, "challenge": true, "challenge_response": true}
	// otelKeyedHex is an HMAC-SHA-256 in lowercase hexadecimal (OE1-010).
	otelKeyedHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// severityText is the SeverityText of each SeverityNumber of the severity table (OE1-008).
	severityText = map[int64]string{SeverityInfo: "INFO", SeverityWarn: "WARN", SeverityError: "ERROR"}
	// OTelDeclaredOnly are the attributes that identify people and records, exported only when
	// declared (OE1-005).
	OTelDeclaredOnly = map[string]bool{"ecl.actor.id": true, "ecl.subject.id": true, "ecl.action.target": true}
	dcmpAll          = []attributeSource{{"ecl.issuer.id", []string{"issuer", "id"}}}
	dcmpRequest      = []attributeSource{
		{"ecl.action.class", []string{"action", "action_class"}},
		{"ecl.actor.id", []string{"actor", "id"}}, {"ecl.subject.id", []string{"subject", "id"}},
	}
	dcmpRequestID = []attributeSource{{OTelRequestID, []string{"request_id"}}}
	dcmpResponse  = []attributeSource{
		{"ecl.decision.id", []string{"decision_id"}},
		{"ecl.decision.outcome", []string{"outcome"}}, {"ecl.decision.safe_state", []string{"safe_state"}},
		{"ecl.policy.id", []string{"policy", "id"}}, {"ecl.policy.version", []string{"policy", "version"}},
		{"ecl.policy.digest", []string{"policy", "digest", "value"}},
	}
	ebmpOnly = []attributeSource{
		{"ecl.producer.id", []string{"producer", "id"}}, {"ecl.event.kind", []string{"event", "kind"}},
		{"ecl.event.state", []string{"event", "state"}},
	}
	// ebmpRequest: a request event identifies its request by the reference it holds (OE1-004).
	ebmpRequest = []attributeSource{{OTelRequestID, []string{"event", "request", "uri"}}}
	dcmpAction  = []attributeSource{
		{"ecl.action.id", []string{"action", "action_id"}}, {"ecl.action.operation", []string{"action", "operation"}},
		{"ecl.action.target", []string{"action", "target", "uri"}},
	}
	ebmpAction = []attributeSource{
		{"ecl.action.id", []string{"event", "action_id"}}, {"ecl.action.operation", []string{"event", "operation"}},
		{"ecl.action.target", []string{"event", "target", "uri"}},
	}
	// otelKeyed are the attributes that a record carries only with an export key (OE1-010).
	otelKeyed = map[string]bool{OTelObjectDigest: true, OTelParametersDigest: true, OTelKeyID: true}
	// OTelTable is the attribute table of OE1-003, OE1-004 and OE1-010.
	OTelTable = func() map[string]bool {
		table := map[string]bool{}
		for _, name := range []string{"ecl.export.profile", "ecl.protocol", "ecl.object.id", "ecl.object.type",
			OTelObjectDigest, OTelParametersDigest, OTelKeyID,
			"ecl.workflow.id", "ecl.workflow.root_trace_id", "ecl.workflow.attempt", "ecl.workflow.sequence", "ecl.evidence.bundle",
			"ecl.decision.reason_code", "ecl.authorization.id", "ecl.event.decision_id", "ecl.event.reason_code"} {
			table[name] = true
		}
		for _, sources := range [][]attributeSource{dcmpAll, dcmpRequest, dcmpRequestID, dcmpResponse, ebmpOnly, dcmpAction} {
			for _, source := range sources {
				table[source.name] = true
			}
		}
		return table
	}()
)

// ExportKey is a deployment's export key (OE1-010): a secret of at least 32 bytes that keys the
// digests of exported records and nothing else, and an identifier that is not derived from it.
type ExportKey struct {
	KeyID string
	Key   []byte
}

// ErrExportKeys is the error of an export key file that is not exactly an ecl_otel_export_keys_v1
// document; its messages never hold key material.
var ErrExportKeys = errors.New("export keys")

// NewExportKey returns an export key with an identifier of 1 to 256 characters and at least 32
// bytes of key.
func NewExportKey(keyID any, key []byte) (ExportKey, error) {
	identifier, isText := keyID.(string)
	if !isText || utf8.RuneCountInString(identifier) < 1 || utf8.RuneCountInString(identifier) > 256 {
		return ExportKey{}, fmt.Errorf("%w: an export key identifier is a string of 1 to 256 characters", ErrExportKeys)
	}
	if len(key) < MinExportKeyBytes {
		return ExportKey{}, fmt.Errorf("%w: an export key has at least %d bytes", ErrExportKeys, MinExportKeyBytes)
	}
	return ExportKey{KeyID: identifier, Key: key}, nil
}

// Digest returns the HMAC-SHA-256 under the key of the restricted canonical JSON of value, in
// lowercase hexadecimal, or an error when value is outside that profile.
func (k ExportKey) Digest(value any) (string, error) {
	data, err := canon.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, k.Key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// LoadExportKeys returns the export keys of a key file by identifier. The file is strict JSON:
// {"schema_version": "ecl_otel_export_keys_v1", "keys": [...]}, each key {"key_id", "key"} with
// the key in canonical base64, at least 32 bytes, and every identifier once.
func LoadExportKeys(data []byte) (map[string]ExportKey, error) {
	value, err := strict.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: an export key file is strict JSON: %v", ErrExportKeys, err)
	}
	document, isObject := value.(map[string]any)
	version, _ := document["schema_version"].(string)
	keys, isList := document["keys"].([]any)
	if !isObject || len(document) != 2 || version != ExportKeysVersion || !isList || len(keys) == 0 {
		return nil, fmt.Errorf("%w: not an %s document with at least one key", ErrExportKeys, ExportKeysVersion)
	}
	found := map[string]ExportKey{}
	for _, item := range keys {
		entry, isEntry := item.(map[string]any)
		_, hasID := entry["key_id"]
		material, isText := entry["key"].(string)
		if !isEntry || len(entry) != 2 || !hasID || !isText {
			return nil, fmt.Errorf("%w: an export key entry has exactly a key_id and a key", ErrExportKeys)
		}
		raw, canonical := envelope.DecodeCanonicalBase64(material)
		if !canonical {
			return nil, fmt.Errorf("%w: an export key is canonical base64", ErrExportKeys)
		}
		key, err := NewExportKey(entry["key_id"], raw)
		if err != nil {
			return nil, err
		}
		if _, repeated := found[key.KeyID]; repeated {
			return nil, fmt.Errorf("%w: an export key identifier appears more than once", ErrExportKeys)
		}
		found[key.KeyID] = key
	}
	return found, nil
}

// pick returns a string or an integer member (never a boolean), or nil.
func pick(value any, path []string) any {
	switch found := member(value, path...).(type) {
	case string:
		return found
	case json.Number:
		if _, isInteger := pyjson.Int(found); isInteger {
			return found
		}
	}
	return nil
}

func otelObjectTime(value map[string]any) any {
	name := "observed_at"
	if pyjson.Equal(value["protocol"], "DCMP-2") {
		name = "issued_at"
	}
	return text(value, name)
}

// OTelEventName is the EventName of the record that copies an object (OE1-003).
func OTelEventName(value map[string]any) string {
	if pyjson.Equal(value["protocol"], "DCMP-2") {
		return "ecl.dcmp." + pyjson.Str(value["message_type"])
	}
	return "ecl.ebmp." + pyjson.Str(value["event_type"])
}

// otelEventKind returns the kind of an EBMP-2 event, or nil for any other object.
func otelEventKind(value map[string]any) any {
	if pyjson.Equal(value["protocol"], "DCMP-2") {
		return nil
	}
	return text(value, "event", "kind")
}

// otelParametersDigest returns the parameters digest member of a decision request or an
// execution event, or nil.
func otelParametersDigest(value map[string]any) any {
	if pyjson.Equal(value["protocol"], "DCMP-2") {
		if !pyjson.Equal(value["message_type"], decisionRequest) {
			return nil
		}
		return member(value, "action", "parameters_digest")
	}
	if otelEventKind(value) != executionKind {
		return nil
	}
	return member(value, "event", "parameters_digest")
}

// OTelUnkeyedDigests returns the digests that anyone can compute from the object, by the attribute
// that would carry them: the SHA-256 of the object and the value of its parameters digest
// (OE1-004). A record carries neither. The error is that of an object outside the restricted
// canonical profile.
func OTelUnkeyedDigests(value map[string]any) (map[string]any, error) {
	digest, err := canon.Digest(value)
	if err != nil {
		return nil, err
	}
	found := map[string]any{OTelObjectDigest: digest}
	if parameters, isText := member(otelParametersDigest(value), "value").(string); isText {
		found[OTelParametersDigest] = parameters
	}
	return found, nil
}

// OTelAttributes returns the attribute table for one object, each the object's own value
// (OE1-003, OE1-004). With key, the object's digest and its parameters digest are keyed with it
// and the key is named (OE1-010); with a nil key, no digest is exported. The identifiers of people
// and records are exported only when declared names them (OE1-005). A row applies only to the
// objects it names: the action rows to a decision request and to execution events, the rows of a
// decision to a decision response, the request's identifier to a decision response, a challenge,
// a challenge response and a request event, the event's decision to decision and execution
// events, the authorization to an admit and to authority events, and the reason code to a
// terminal event. The error is that of a keyed digest of an object outside the restricted
// canonical profile.
func OTelAttributes(value map[string]any, bundleID any, key *ExportKey, declared map[string]bool) (map[string]any, error) {
	dcmp := pyjson.Equal(value["protocol"], "DCMP-2")
	identifier, kind := value["object_id"], value["event_type"]
	if dcmp {
		identifier, kind = value["message_id"], value["message_type"]
	}
	result := map[string]any{
		"ecl.export.profile": OTelProfile,
		"ecl.protocol":       pyjson.Str(value["protocol"]),
		"ecl.object.id":      pyjson.Str(identifier),
		"ecl.object.type":    pyjson.Str(kind),
	}
	if key != nil {
		digest, err := key.Digest(value)
		if err != nil {
			return nil, err
		}
		result[OTelObjectDigest] = digest
		result[OTelKeyID] = key.KeyID
		if parameters, isObject := otelParametersDigest(value).(map[string]any); isObject {
			keyed, err := key.Digest(parameters)
			if err != nil {
				return nil, err
			}
			result[OTelParametersDigest] = keyed
		}
	}
	for _, pair := range [][2]string{{"ecl.workflow.id", "workflow_id"}, {"ecl.workflow.root_trace_id", "root_trace_id"}, {"ecl.workflow.attempt", "attempt"}, {"ecl.workflow.sequence", "sequence"}} {
		if found := pick(value, []string{"workflow", pair[1]}); found != nil {
			result[pair[0]] = found
		}
	}
	if bundleID != nil {
		result["ecl.evidence.bundle"] = bundleID
	}
	eventKind := otelEventKind(value)
	messageType, _ := value["message_type"].(string)
	var tables [][]attributeSource
	if dcmp {
		tables = append(tables, dcmpAll)
		if messageType == decisionRequest {
			tables = append(tables, dcmpRequest, dcmpAction)
		}
		if messageType == decisionResponse {
			tables = append(tables, dcmpResponse)
		}
		if requestIDTypes[messageType] {
			tables = append(tables, dcmpRequestID)
		}
	} else {
		tables = append(tables, ebmpOnly)
		if eventKind == executionKind {
			tables = append(tables, ebmpAction)
		}
		if eventKind == requestKind {
			tables = append(tables, ebmpRequest)
		}
	}
	for _, sources := range tables {
		for _, source := range sources {
			if found := pick(value, source.path); found != nil && (!OTelDeclaredOnly[source.name] || declared[source.name]) {
				result[source.name] = found
			}
		}
	}
	var authorization any
	if dcmp {
		if messageType == decisionResponse {
			var first any
			if reasons, isList := value["reasons"].([]any); isList && len(reasons) > 0 {
				first = reasons[0]
			}
			if code := text(first, "code"); code != nil {
				result["ecl.decision.reason_code"] = code
			}
			authorization = text(value, "authorization", "authorization_id")
		}
	} else {
		if eventKind == authorityKind {
			authorization = text(value, "event", "authorization_id")
		}
		if eventKind == decisionKind || eventKind == executionKind {
			if decision := text(value, "event", "decision", "uri"); decision != nil {
				result["ecl.event.decision_id"] = decision
			}
		}
		if pyjson.Equal(value["event_type"], terminalEvent) {
			for _, item := range array(value, "extensions") {
				if entry, isObject := item.(map[string]any); isObject && pyjson.Equal(entry["id"], outcomeReason) {
					if code := text(entry, "value", "code"); code != nil {
						result["ecl.event.reason_code"] = code
					}
				}
			}
		}
	}
	if authorization != nil {
		result["ecl.authorization.id"] = authorization
	}
	return result, nil
}

// OTelSeverity is the SeverityNumber of the severity table (OE1-008).
func OTelSeverity(value map[string]any) int64 {
	if pyjson.Equal(value["protocol"], "DCMP-2") {
		outcome := value["outcome"]
		if pyjson.Equal(outcome, "deny") || pyjson.Equal(outcome, "hold") || pyjson.Equal(outcome, "challenge") {
			return SeverityWarn
		}
		if operation, isText := textOf(value, "operation"); pyjson.Equal(value["message_type"], "control") && isText && emergencyOps[operation] {
			return SeverityError
		}
		return SeverityInfo
	}
	if pyjson.Equal(value["event_type"], "execution_terminal") {
		state, isText := textOf(value, "event", "state")
		if isText && warnStates[state] {
			return SeverityWarn
		}
		if isText && errorStates[state] {
			return SeverityError
		}
	}
	return SeverityInfo
}

// otlpInteger returns a decimal integer string of the OTLP JSON encoding as an integer, or nil
// when it is not one: at most 20 digits, and no whitespace, sign other than a leading minus, digit
// separator or leading zero.
func otlpInteger(raw any) *big.Int {
	text, isText := raw.(string)
	if !isText || !otlpDecimal.MatchString(text) {
		return nil
	}
	integer, _ := new(big.Int).SetString(text, 10)
	return integer
}

// otlpFixed64Value returns a fixed64 of the OTLP JSON encoding, such as a timestamp, as an integer,
// or nil when it is not decimal text of an integer from 0 to 2^64 - 1 (OE1-007).
func otlpFixed64Value(raw any) *big.Int {
	integer := otlpInteger(raw)
	if integer == nil || integer.Sign() < 0 || integer.Cmp(otlpFixed64) >= 0 {
		return nil
	}
	return integer
}

// attributeMap reads a record's attributes by key as the reference reads them: a value of one
// member, a stringValue as its string and an intValue that is decimal text as the exact integer it
// names, and any other AnyValue as the AnyValue object itself; a later key replaces an earlier one,
// and otelMatch reports the repetition.
func attributeMap(log any) map[string]any {
	result := map[string]any{}
	for _, item := range array(log, "attributes") {
		entry, isObject := item.(map[string]any)
		value, valueIsObject := member(item, "value").(map[string]any)
		if !isObject || !valueIsObject || len(value) != 1 {
			continue
		}
		for kind, raw := range value {
			key := pyjson.Str(entry["key"])
			// Only a stringValue holds a string and an intValue an integer: any other
			// AnyValue is kept as the AnyValue object, which equals no value that the table copies.
			if integer := otlpInteger(raw); kind == "intValue" && integer != nil {
				result[key] = json.Number(integer.String())
			} else if kind == "stringValue" {
				result[key] = raw
			} else {
				result[key] = map[string]any{kind: raw}
			}
		}
	}
	return result
}

// otelDeclared returns the attribute names that the record's export policy declares.
func otelDeclared(record map[string]any) map[string]bool {
	declared := map[string]bool{}
	for _, item := range array(record, "declared_attributes") {
		if name, isText := textOf(item, "name"); isText {
			declared[name] = true
		}
	}
	return declared
}

func otelExport(record, value map[string]any, _ map[string]ExportKey) []problem {
	var problems []problem
	attempted := nanos(member(record, "export", "attempted_at"))
	recorded := nanos(otelObjectTime(value))
	if attempted == nil || recorded == nil || attempted.Cmp(recorded) < 0 {
		problems = append(problems, problem{"/export/attempted_at", "the exporter read the object before its time"})
	}
	if after, isObject := object(record, "evidence_after"); isObject {
		left, leftErr := canon.Marshal(after)
		right, rightErr := canon.Marshal(value)
		if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
			problems = append(problems, problem{"/evidence_after", "the evidence differs after the export"})
		}
	}
	return problems
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func otelMatch(record, value map[string]any, keys map[string]ExportKey) []problem {
	log, _ := object(record, "log_record")
	var problems []problem
	if !pyjson.Equal(log["eventName"], OTelEventName(value)) {
		problems = append(problems, problem{"/log_record/eventName", "not the object's event name"})
	}
	time := nanos(otelObjectTime(value))
	if recorded := otlpFixed64Value(log["timeUnixNano"]); time == nil || recorded == nil || recorded.Cmp(time) != 0 {
		problems = append(problems, problem{"/log_record/timeUnixNano", "not the object's time"})
	}
	// OE1-003, OE1-007: the observed time is a fixed64 of nanoseconds, so a decimal text of up to 20
	// digits beyond 2^64 - 1 is no time at all.
	if observed := otlpFixed64Value(log["observedTimeUnixNano"]); time != nil && observed == nil {
		problems = append(problems, problem{"/log_record/observedTimeUnixNano", "not a fixed64 time"})
	} else if time != nil && observed.Cmp(time) < 0 {
		problems = append(problems, problem{"/log_record/observedTimeUnixNano", "earlier than the object's time"})
	}
	actual := attributeMap(log)
	declared := otelDeclared(record)
	named := actual[OTelKeyID]
	if _, isText := named.(string); named != nil && !isText {
		// OE1-010: the record carries the key's identifier, a string.
		problems = append(problems, problem{"/log_record/attributes", OTelKeyID + " is not the identifier of a key"})
	}
	var key *ExportKey
	if identifier, isText := named.(string); isText {
		if held, known := keys[identifier]; known {
			key = &held
		}
	}
	// A record that names a key the caller does not hold: its keyed digests cannot be computed. The
	// parameters digest is among them only for an object that has one (OE1-010); on any other
	// object it copies nothing, as it does under a key the caller holds.
	unverifiable := named != nil && key == nil
	_, hasParameters := otelParametersDigest(value).(map[string]any)
	exempt := func(name string) bool {
		return unverifiable && otelKeyed[name] && (name != OTelParametersDigest || hasParameters)
	}
	expected, err := OTelAttributes(value, text(record, "bundle_id"), key, declared)
	var unkeyed map[string]any
	if err == nil {
		unkeyed, err = OTelUnkeyedDigests(value)
	}
	if err != nil {
		return append(problems, problem{"/object", "the object is outside the restricted canonical profile"})
	}
	for _, name := range sortedKeys(expected) {
		if _, present := actual[name]; name == "ecl.evidence.bundle" && !present {
			continue
		}
		// An attribute holds the value it copies as the same JSON value, so a boolValue of true is
		// not an attempt of 1.
		if !sameJSON(actual[name], expected[name]) {
			problems = append(problems, problem{"/log_record/attributes", name + " is not the object's value"})
		}
	}
	for _, name := range sortedKeys(actual) {
		// An identifier of a person or record exported without its declaration is the concern of
		// OE1-005 (the minimization rule), not of this one.
		undeclared := OTelDeclaredOnly[name] && !declared[name]
		if _, present := expected[name]; OTelTable[name] && !present && !exempt(name) && !undeclared {
			problems = append(problems, problem{"/log_record/attributes", name + " copies nothing in the object"})
		}
	}
	// OE1-010: with an export key, every record carries the keyed digest of the object and, where
	// the object has a parameters digest, the keyed parameters digest, under a key the caller does
	// not hold as under one it holds.
	for _, name := range []string{OTelObjectDigest, OTelParametersDigest} {
		if _, present := actual[name]; exempt(name) && !present {
			problems = append(problems, problem{"/log_record/attributes", OTelKeyID + " is named without the keyed " + name})
		}
	}
	// OE1-003, OE1-010: a keyed digest that the caller cannot compute is still held as the
	// stringValue that the table gives, an HMAC in lowercase hexadecimal, so that no other kind or
	// form, such as the object's SHA-256 as a bytesValue of its bytes, carries past OE1-004 a digest
	// that needs no key.
	for _, name := range []string{OTelParametersDigest, OTelObjectDigest} {
		held, present := actual[name]
		if digest, isText := held.(string); exempt(name) && present && !(isText && otelKeyedHex.MatchString(digest)) {
			problems = append(problems, problem{"/log_record/attributes", name + " is not an HMAC in lowercase hexadecimal"})
		}
	}
	// OTLP: the attribute keys of a record are unique; the map above keeps only the last of a
	// repeated key, which would hide an earlier one from every comparison.
	seenKeys := map[string]bool{}
	for _, item := range array(log, "attributes") {
		if entry, isObject := item.(map[string]any); isObject {
			name := pyjson.Str(entry["key"])
			if seenKeys[name] {
				problems = append(problems, problem{"/log_record/attributes", "an attribute key is repeated"})
				break
			}
			seenKeys[name] = true
		}
	}
	// OE1-004: a digest that needs no key, held as the stringValue that the table gives. In any
	// other kind it is refused above: under a key the caller holds as not the object's value,
	// without a key as copying nothing, and under a key the caller does not hold as not an HMAC in
	// lowercase hexadecimal.
	for _, name := range sortedKeys(unkeyed) {
		if found, isText := actual[name].(string); isText && found == unkeyed[name] {
			problems = append(problems, problem{"/log_record/attributes", name + " is a digest that needs no export key"})
		}
	}
	return problems
}

func otelMinimized(record, _ map[string]any, _ map[string]ExportKey) []problem {
	log, _ := object(record, "log_record")
	declared := otelDeclared(record)
	var problems []problem
	names := sortedKeys(attributeMap(log))
	for _, name := range names {
		if !OTelTable[name] && !declared[name] {
			problems = append(problems, problem{"/log_record/attributes", name + " is neither in the table nor declared"})
		}
	}
	for _, name := range names {
		if OTelDeclaredOnly[name] && !declared[name] {
			problems = append(problems, problem{"/log_record/attributes", name + " identifies a person or record and is not declared"})
		}
	}
	if holds(log, "body") && !declared["body"] {
		problems = append(problems, problem{"/log_record/body", "a body is exported without a declaration"})
	}
	return problems
}

func otelSeverityMapped(record, value map[string]any, _ map[string]ExportKey) []problem {
	number := OTelSeverity(value)
	var problems []problem
	if !pyjson.Equal(member(record, "log_record", "severityNumber"), json.Number(jsonInt(number))) {
		problems = append(problems, problem{"/log_record/severityNumber", "not the severity table's"})
	}
	if !pyjson.Equal(member(record, "log_record", "severityText"), severityText[number]) {
		problems = append(problems, problem{"/log_record/severityText", "not the severity table's name"})
	}
	return problems
}

// otelRules are the rules of the profile in the order the reference reports them, each given the
// record, the object it copies and the export keys the caller holds. A rule added to the registry
// for this profile is one function and one row here.
var otelRules = []struct {
	rule  string
	check func(record, value map[string]any, keys map[string]ExportKey) []problem
}{
	{RuleOTelExport, otelExport},
	{RuleOTelMatch, otelMatch},
	{RuleOTelMinimized, otelMinimized},
	{RuleOTelSeverity, otelSeverityMapped},
}

// checkOTel returns the findings of an ecl_otel_export_record_v1 record that its schema accepted
// (OE1-001 to OE1-010), comparing a keyed digest only under a key of keys that the record names.
func checkOTel(record map[string]any, keys map[string]ExportKey) []Finding {
	value, isObject := object(record, "object")
	if !isObject {
		return nil
	}
	var out []Finding
	for _, row := range otelRules {
		out = append(out, findings(row.rule, row.check(record, value, keys))...)
	}
	return out
}
