package evidence

// The decision basis in signed evidence (DCMP2-053, ECL1N-0178, ECL1N-0181), as the reference's
// ecl_reference.decision_basis checks it. Every signed decision response is checked under the
// one-way rule as an object (semantic.OneWayProblems). Besides that:
//
//   - ecl.rule.decision-basis-required.v1: every decision response carries its decision basis in
//     ecl.ext.decision-basis.v1; a response without that record is refused.
//   - ecl.rule.decision-basis-matches-register.v1: checked against a Consequential Action
//     Register that the caller supplies, a decision basis names that register version and lists
//     exactly the inputs that it declares for the request's action class, each once, with the
//     declared class, required flag, derived_from and source, the source compared as input names
//     are; and no input recorded as available was obtained after its declared deadline, counted
//     from the value's received_at, or has a value older than its declared maximum age at the
//     response's evaluated_at (ECL1N-0182).
//   - ecl.rule.decision-basis-one-way.v1 with the request in hand (RequestProblems): no input
//     whose source is the request's actor is recorded as verifiable (ActorSourceProblems), and
//     the request was not received before it was issued, less the response clock-skew allowance
//     (DCMP2-047).
//   - ecl.rule.register-declarations-consistent.v1: a register that breaks it, or its schema, is
//     refused before any decision basis is checked against it (DCMP2-053).
//
// Input names compare by semantic.InputKey (DCMP2-053).

import (
	"errors"
	"fmt"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// The decision-basis extension, its rules and the register schema.
const (
	DecisionBasisExtension       = "ecl.ext.decision-basis.v1"
	DecisionBasisRequired        = "ecl.rule.decision-basis-required.v1"
	DecisionBasisMatchesRegister = "ecl.rule.decision-basis-matches-register.v1"
	RegisterSchema               = "https://externalcontrollayer.ai/ns/schema/action-register/1"
	// MaxRegisterBytes is the size limit of a register file, enforced before parsing.
	MaxRegisterBytes = 1024 * 1024
)

// ActorSourceProblems returns (path below the value, message) for each entry that a decision-basis
// value records as verifiable while its source is the request's actor, the governed AI system
// that requested the action (DCMP2-053): an input that the governed AI system produces is
// actor_supplied (ECL-1 Section 4.3, ECL1N-0178). Names compare by semantic.InputKey. A verifier
// that holds the request applies it under ecl.rule.decision-basis-one-way.v1, as the reference's
// actor_source_problems.
func ActorSourceProblems(value, request map[string]any) [][2]string {
	actor, isActor := pyjson.Object(request["actor"])
	if !isActor {
		return nil
	}
	actorID, isText := pyjson.Text(actor["id"])
	inputs, isList := value["inputs"].([]any)
	if !isText || !isList {
		return nil
	}
	key := semantic.InputKey(actorID)
	var problems [][2]string
	for position, raw := range inputs {
		item, isItem := pyjson.Object(raw)
		if !isItem {
			continue
		}
		class, _ := pyjson.Text(item["class"])
		source, isSource := pyjson.Text(item["source"])
		if class == "verifiable" && isSource && semantic.InputKey(source) == key {
			problems = append(problems, [2]string{fmt.Sprintf("/inputs/%d/class", position), "an input whose source is the requesting actor cannot be verifiable"})
		}
	}
	return problems
}

// RequestProblems returns (path below the value, message) for each way a decision-basis value
// breaks DCMP2-053 with the request it answers, as the reference's request_problems: an input
// recorded as verifiable whose source is the request's actor (ActorSourceProblems), and a
// received_at earlier than the request's issued_at by more than skewSeconds, the response
// clock-skew allowance of the verification profile (DCMP2-047), zero in the reference profile.
func RequestProblems(value, request map[string]any, skewSeconds int) [][2]string {
	problems := ActorSourceProblems(value, request)
	if skewSeconds < 0 {
		skewSeconds = 0
	}
	received, receivedErr := instant.Parse(value["received_at"])
	issued, issuedErr := instant.Parse(request["issued_at"])
	if receivedErr == nil && issuedErr == nil && instant.Compare(received, issued.AddSeconds(-int64(skewSeconds))) < 0 {
		problems = append(problems, [2]string{"/received_at", "the request was received before it was issued"})
	}
	return problems
}

// ErrInvalidRegister is a register option that does not satisfy the register schema or
// ecl.rule.register-declarations-consistent.v1.
var ErrInvalidRegister = errors.New("the register does not satisfy its schema or ecl.rule.register-declarations-consistent.v1")

// RegisterUsageProblems returns why a verifier refuses a register as a usage error (DCMP2-053):
// its schema errors, or else the findings of the register declarations rule; none for a register
// that a decision basis can be checked against.
func RegisterUsageProblems(register any) ([]string, error) {
	problems, err := RegisterSchemaProblems(register)
	if err != nil || len(problems) > 0 {
		return problems, err
	}
	document, _ := pyjson.Object(register)
	for _, problem := range semantic.RegisterDocumentProblems(document) {
		problems = append(problems, problem[0]+": "+problem[1])
	}
	return problems, nil
}

// RegisterSchemaProblems returns the schema errors of a register document as messages; none when
// it satisfies its schema.
func RegisterSchemaProblems(register any) ([]string, error) {
	if _, isObject := pyjson.Object(register); !isObject {
		return []string{"the register is not a JSON object"}, nil
	}
	found, err := schema.ECL().Errors(RegisterSchema, register, 16)
	if err != nil {
		return nil, err
	}
	problems := make([]string, 0, len(found))
	for _, item := range found {
		message := []rune(item.Path + ": " + item.Message)
		if len(message) > 200 {
			message = message[:200]
		}
		problems = append(problems, string(message))
	}
	return problems, nil
}

// LoadRegister reads a register document from its bytes: strict JSON of at most 1 MiB that
// satisfies the register schema and ecl.rule.register-declarations-consistent.v1, so that no
// action class and no input of a class is declared twice (DCMP2-053, ECL1N-0178). Anything else is
// an *InputError.
func LoadRegister(data []byte) (map[string]any, error) {
	if len(data) > MaxRegisterBytes {
		return nil, &InputError{Message: "register file exceeds the 1 MiB limit", Code: ResourceLimitExceeded}
	}
	value, err := strict.Parse(data)
	if err != nil {
		var refusal *strict.Error
		if errors.As(err, &refusal) {
			return nil, &InputError{Message: "malformed register: the register is not strict JSON", Code: refusal.RuleID}
		}
		return nil, err
	}
	problems, err := RegisterSchemaProblems(value)
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, &InputError{Message: "malformed register: the register does not satisfy its schema: " + problems[0], Code: SchemaInvalid}
	}
	register, _ := pyjson.Object(value)
	if inconsistent := semantic.RegisterDocumentProblems(register); len(inconsistent) > 0 {
		return nil, &InputError{Message: "malformed register: the register breaks " + semantic.RuleRegisterDeclarations + ": " + inconsistent[0][0] + ": " + inconsistent[0][1], Code: semantic.RuleRegisterDeclarations}
	}
	return register, nil
}

// RegisterDigest returns the ecl.digest.sha-256.v1 digest of a register document's restricted
// canonical JSON.
func RegisterDigest(register map[string]any) (map[string]any, error) {
	return canon.Reference(register)
}

// RegisterReference returns the register member that names a register document (ECL1N-0181):
// its register_id as uri, its register_version as version when it has one, and its digest.
func RegisterReference(register map[string]any) (map[string]any, error) {
	digest, err := RegisterDigest(register)
	if err != nil {
		return nil, err
	}
	reference := map[string]any{"uri": pyjson.Str(register["register_id"]), "digest": digest}
	if version, isText := pyjson.Text(register["register_version"]); isText {
		reference["version"] = version
	}
	return reference, nil
}

// DeclaredInputs returns the decision inputs that the register declares for actionClass; none
// when it has no entry for the class.
func DeclaredInputs(register map[string]any, actionClass string) []map[string]any {
	entries, isList := pyjson.Array(register["entries"])
	if !isList {
		return nil
	}
	for _, candidate := range entries {
		item, isObject := pyjson.Object(candidate)
		if !isObject || !pyjson.Equal(item["action_class_id"], actionClass) {
			continue
		}
		declared, isDeclared := pyjson.Array(item["decision_inputs"])
		if !isDeclared {
			return nil
		}
		var result []map[string]any
		for _, value := range declared {
			if declaration, ok := pyjson.Object(value); ok {
				result = append(result, declaration)
			}
		}
		return result
	}
	return nil
}

type basisValue struct {
	index int
	value any
}

// basisValues returns the index and value of each occurrence of the extension on a message.
func basisValues(message map[string]any) []basisValue {
	extensions, isList := pyjson.Array(message["extensions"])
	if !isList {
		return nil
	}
	var found []basisValue
	for index, candidate := range extensions {
		if item, isObject := pyjson.Object(candidate); isObject && pyjson.Equal(item["id"], DecisionBasisExtension) {
			found = append(found, basisValue{index, item["value"]})
		}
	}
	return found
}

// RegisterProblems returns (path below the value, message) for each way a decision basis
// disagrees with the register that a verifier holds, without the response's evaluation time:
// RegisterProblemsAt with no evaluated_at.
func RegisterProblems(value, register map[string]any, actionClass any) ([][2]string, error) {
	return RegisterProblemsAt(value, register, actionClass, nil)
}

// derivedKeys returns the keys of the string names in an entry's derived_from.
func derivedKeys(item map[string]any) map[string]bool {
	keys := map[string]bool{}
	if derived, isList := pyjson.Array(item["derived_from"]); isList {
		for _, candidate := range derived {
			if name, isText := pyjson.Text(candidate); isText {
				keys[semantic.InputKey(name)] = true
			}
		}
	}
	return keys
}

func sameKeys(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if !right[key] {
			return false
		}
	}
	return true
}

func instantOf(value any) (instant.Instant, bool) {
	parsed, err := instant.Parse(value)
	return parsed, err == nil
}

// RegisterProblemsAt returns (path below the value, message) for each way a decision basis
// disagrees with the register that a verifier holds, as the reference's register_problems reports
// them. A register without an entry for the class declares no input for it; an input that it
// declares twice for the class matches no record. evaluatedAt is the response's, which the
// maximum-age check needs.
func RegisterProblemsAt(value, register map[string]any, actionClass, evaluatedAt any) ([][2]string, error) {
	digest, err := RegisterDigest(register)
	if err != nil {
		return nil, err
	}
	var problems [][2]string
	named, isObject := pyjson.Object(value["register"])
	if !isObject || !pyjson.Equal(named["uri"], register["register_id"]) {
		problems = append(problems, [2]string{"/register/uri", "the record names another register"})
	} else if !pyjson.Equal(named["digest"], digest) {
		problems = append(problems, [2]string{"/register/digest", "the record names another version of the register"})
	}
	if pyjson.Has(register, "register_version") && isObject && pyjson.Has(named, "version") && !pyjson.Equal(named["version"], register["register_version"]) {
		problems = append(problems, [2]string{"/register/version", "the record names another register version"})
	}
	inputs, isList := pyjson.Array(value["inputs"])
	if !isList {
		return problems, nil
	}
	declared := map[string]map[string]any{}
	var order []string
	repeated := map[string]bool{}
	if class, isText := pyjson.Text(actionClass); isText {
		for _, item := range DeclaredInputs(register, class) {
			name, isName := pyjson.Text(item["input"])
			if !isName {
				continue
			}
			key := semantic.InputKey(name)
			if _, seen := declared[key]; seen {
				repeated[key] = true
			} else {
				order = append(order, key)
				declared[key] = item
			}
		}
	}
	decided, hasDecided := instantOf(evaluatedAt)
	received, hasReceived := instantOf(value["received_at"])
	listed := map[string]bool{}
	for position, candidate := range inputs {
		path := fmt.Sprintf("/inputs/%d", position)
		item, isEntry := pyjson.Object(candidate)
		if !isEntry {
			continue
		}
		name, isName := pyjson.Text(item["input"])
		if !isName {
			continue
		}
		key := semantic.InputKey(name)
		listed[key] = true
		declaration, isDeclared := declared[key]
		if !isDeclared {
			problems = append(problems, [2]string{path + "/input", "the register does not declare this input for the action class"})
			continue
		}
		if repeated[key] {
			problems = append(problems, [2]string{path + "/input", "the register declares this input more than once"})
			continue
		}
		if !pyjson.Equal(item["class"], declaration["class"]) {
			problems = append(problems, [2]string{path + "/class", "the class is not the one the register declares"})
		}
		if !sameBoolean(item["required"], declaration["required"]) {
			problems = append(problems, [2]string{path + "/required", "the required flag is not the one the register declares"})
		}
		recordedSource, recordedIsText := pyjson.Text(item["source"])
		declaredSource, declaredIsText := pyjson.Text(declaration["source"])
		if !(recordedIsText && declaredIsText && semantic.InputKey(recordedSource) == semantic.InputKey(declaredSource)) {
			problems = append(problems, [2]string{path + "/source", "the source is not the one the register declares"})
		}
		if !sameKeys(derivedKeys(item), derivedKeys(declaration)) {
			problems = append(problems, [2]string{path + "/derived_from", "the inputs it is computed from are not the ones the register declares"})
		}
		if !pyjson.Equal(item["status"], "available") {
			continue
		}
		obtained, hasObtained := instantOf(item["obtained_at"])
		if deadline, isInt := pyjson.Int(declaration["deadline_milliseconds"]); isInt && deadline >= 0 && hasObtained && hasReceived && instant.Compare(obtained, received.AddNanoseconds(deadline*1_000_000)) > 0 {
			problems = append(problems, [2]string{path + "/obtained_at", "the input was obtained after its declared deadline"})
		}
		valueAt, hasValueAt := instantOf(item["value_at"])
		if age, isInt := pyjson.Int(declaration["maximum_age_seconds"]); isInt && hasValueAt && hasDecided && instant.Compare(decided, valueAt.AddSeconds(age)) > 0 {
			problems = append(problems, [2]string{path + "/value_at", "the input's value is older than its declared maximum age"})
		}
	}
	for _, key := range order {
		if !listed[key] {
			problems = append(problems, [2]string{"/inputs", "the record does not list the declared input " + pyjson.Str(declared[key]["input"])})
		}
	}
	return problems, nil
}

// sameBoolean is Python's left is right for the values a required flag can take: true and false
// are each only themselves, and None is itself.
func sameBoolean(left, right any) bool {
	switch value := left.(type) {
	case bool:
		other, isBool := right.(bool)
		return isBool && value == other
	case nil:
		return right == nil
	default:
		return false
	}
}

// checkDecisionBases is DCMP2-053 in the evidence: each decision response carries its decision
// basis; no input whose source is the request's actor is recorded as verifiable, and the request
// was not received before it was issued, less the response clock-skew allowance (DCMP2-047); and
// a basis agrees with the register when the caller supplies one.
func checkDecisionBases(entries []*entry, findings *[]BundleFinding, register map[string]any, skew int64) error {
	requests := map[string]map[string]any{}
	for _, item := range entries {
		protocol, _ := pyjson.Text(item.payload["protocol"])
		messageType, _ := pyjson.Text(item.payload["message_type"])
		identifier, isText := pyjson.Text(item.payload["message_id"])
		// As the reference's dict comprehension: a later request with the same identifier wins.
		if !item.observation && protocol == "DCMP-2" && messageType == "decision_request" && isText {
			requests[identifier] = item.payload
		}
	}
	for _, item := range entries {
		protocol, _ := pyjson.Text(item.payload["protocol"])
		messageType, _ := pyjson.Text(item.payload["message_type"])
		if item.observation || protocol != "DCMP-2" || messageType != "decision_response" {
			continue
		}
		found := basisValues(item.payload)
		if len(found) == 0 {
			*findings = append(*findings, issue(DecisionBasisRequired, fmt.Sprintf("object %d: /extensions: the decision response records no decision basis", item.index)))
			continue
		}
		var request map[string]any
		if requestID, isText := pyjson.Text(item.payload["request_id"]); isText {
			request = requests[requestID]
		}
		if len(found) != 1 || request == nil {
			continue
		}
		value, isObject := pyjson.Object(found[0].value)
		if !isObject {
			continue
		}
		for _, problem := range RequestProblems(value, request, int(skew)) {
			*findings = append(*findings, issue(semantic.RuleDecisionBasis, fmt.Sprintf("object %d: /extensions/%d/value%s: %s", item.index, found[0].index, problem[0], problem[1])))
		}
		if register == nil {
			continue
		}
		var actionClass any
		if action, isAction := pyjson.Object(request["action"]); isAction {
			actionClass = action["action_class"]
		}
		problems, err := RegisterProblemsAt(value, register, actionClass, item.payload["evaluated_at"])
		if err != nil {
			return err
		}
		for _, problem := range problems {
			*findings = append(*findings, issue(DecisionBasisMatchesRegister, fmt.Sprintf("object %d: /extensions/%d/value%s: %s", item.index, found[0].index, problem[0], problem[1])))
		}
	}
	return nil
}
