// Package semantic checks the cross-member rules of ECL-1 objects that JSON Schema cannot
// express: DCMP-2 messages, EBMP-2 objects, bare bundles of EBMP-2 records, adapter bindings and
// safe-state profiles.
//
// The foundation rules come from the imported, separately maintained Go core
// (internal/validator, see provenance/go/GO-IMPORT.json); the RC-4 protocol rules, the safe-state
// rules and the registered control-extension rules are fresh code in this repository. Both are
// maintained by the maintainers of the Python reference, so agreement with it is implementation
// diversity, not independent assessment. The core reports the first failure of a bare bundle,
// which the corpus runner therefore analyzes with evidence.Analyze. Where the core checks other
// conditions of a rule than the requirement states (the threshold rule, the admit authority rule
// and the adapter-binding rule), its findings give way to repository checks of the stated
// conditions.
package semantic

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// SchemaInvalid is the registered error for a value whose shape a check cannot read.
const SchemaInvalid = "ecl.error.schema-invalid.v1"

// The registered control-extension rules (XR1-023, DCMP2-052, DCMP2-053, EBMP2-063 and
// EBMP2-064), and the register declarations rule (ECL1N-0178).
const (
	RuleExtensionValue = "ecl.rule.extension-value-valid.v1"
	RuleCoupling       = "ecl.rule.coupling-results-permit-admit.v1"
	RuleDecisionBasis  = "ecl.rule.decision-basis-one-way.v1"
	RuleReviewTime     = "ecl.rule.approval-review-time-respected.v1"
	RuleControlChange  = "ecl.rule.control-change-approved-and-bounded.v1"
	// RuleRegisterDeclarations is the rule a Consequential Action Register satisfies beyond its
	// schema (ECL1N-0178); a verifier refuses a register that breaks it (DCMP2-053).
	RuleRegisterDeclarations = "ecl.rule.register-declarations-consistent.v1"
	// RegisterSchemaVersion is the schema_version of a Consequential Action Register document.
	RegisterSchemaVersion = "ecl_action_register_v1"
)

// outcomes are the decision outcomes in the strictness order of ECL-1 Section 4.3, least strict
// first.
var outcomes = []string{"admit", "challenge", "hold", "deny"}

const (
	couplingExtension = "ecl.ext.consequence-coupling.v1"
	// DecisionBasisExtension records the inputs of a decision (ECL1N-0181, DCMP2-053).
	DecisionBasisExtension = "ecl.ext.decision-basis.v1"
	approvalExtension      = "ecl.ext.approval-record.v1"
	changeExtension        = "ecl.ext.control-change.v1"
)

// Finding is a rule that a value breaks: the registered rule or error identifier, a JSON Pointer
// to where, and why.
type Finding struct {
	RuleID string
	Path   string
	Detail string
}

// Options is the registry state the rules read.
type Options struct {
	// KnownExtensions maps each active registered extension to its active versions.
	KnownExtensions map[string]map[int]bool
	// ValueSchemas maps a registered extension to the $id of the schema of its value.
	ValueSchemas map[string]string
	// Schemas resolves the value schemas.
	Schemas *schema.Set
}

// Registered returns the options of the registries embedded in this module.
func Registered() Options {
	options := Options{KnownExtensions: map[string]map[int]bool{}, ValueSchemas: map[string]string{}, Schemas: schema.ECL()}
	for _, entry := range registry.Entries("extensions") {
		if entry.Status == "active" {
			if options.KnownExtensions[entry.ID] == nil {
				options.KnownExtensions[entry.ID] = map[int]bool{}
			}
			options.KnownExtensions[entry.ID][int(entry.Version)] = true
		}
		if entry.ValueSchema != "" {
			options.ValueSchemas[entry.ID] = entry.ValueSchema
		}
	}
	return options
}

func convert(findings []validator.Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, item := range findings {
		out = append(out, Finding{RuleID: item.RuleID, Path: item.Path, Detail: item.Detail})
	}
	return out
}

// Sort orders findings by rule, path and detail.
func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Detail < b.Detail
	})
}

// ValidateBytes checks the strict JSON in data. A strict-JSON refusal is one finding naming the
// broken rule; the error is for input that cannot be checked at all.
func ValidateBytes(data []byte, options Options) ([]Finding, error) {
	value, err := strict.Parse(data)
	if err != nil {
		var refusal *strict.Error
		if errors.As(err, &refusal) {
			return []Finding{{RuleID: refusal.RuleID, Path: refusal.Path, Detail: refusal.Reason}}, nil
		}
		return nil, err
	}
	return check(data, value, options)
}

// Validate checks a parsed value: a DCMP-2 message, an EBMP-2 object, a bare bundle
// ({"records": [...]}), an adapter binding, or another object, such as an ECL-IE-1 envelope or an
// ECL-WI-1 work intent, which gets the checks of every object (validatorx.Common).
func Validate(value any, options Options) ([]Finding, error) {
	if root, isObject := value.(map[string]any); isObject && !coreClassifies(root) {
		return common(root), nil
	}
	data, err := canon.Marshal(value)
	if err != nil {
		return nil, err
	}
	return check(data, value, options)
}

// coreClassifies reports whether the imported core checks this object itself: an adapter
// binding, a DCMP-2 or EBMP-2 object, or a bare bundle. It reports every other object as an
// unrecognized artifact, a finding that no registry holds, where the reference applies the
// checks of every object.
func coreClassifies(root map[string]any) bool {
	version, _ := root["schema_version"].(string)
	protocol, _ := root["protocol"].(string)
	return version == "ecl_adapter_binding_v1" || protocol == "DCMP-2" || protocol == "EBMP-2" || root["records"] != nil
}

// common returns the findings of the checks of every object, sorted, and for a Consequential
// Action Register those of the register declarations rule (ECL1N-0178).
func common(root map[string]any) []Finding {
	findings := convert(validatorx.Common(root))
	if pyjson.Equal(root["schema_version"], RegisterSchemaVersion) {
		for _, problem := range RegisterDocumentProblems(root) {
			findings = append(findings, Finding{RuleID: RuleRegisterDeclarations, Path: problem[0], Detail: problem[1]})
		}
	}
	Sort(findings)
	return findings
}

func check(data []byte, value any, options Options) ([]Finding, error) {
	if root, isObject := value.(map[string]any); isObject && !coreClassifies(root) {
		return common(root), nil
	}
	found, err := validator.Validate(data, validator.Options{KnownExtensions: options.KnownExtensions})
	if err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(found))
	for _, item := range convert(found) {
		if item.RuleID != validator.RuleIntegrityThreshold && item.RuleID != validator.RuleAdmitAuthority && item.RuleID != validator.RuleAdapterBinding {
			findings = append(findings, item)
		}
	}
	// IE1-013 lists the only conditions of the threshold rule, DCMP2-013 those of the admit
	// authority rule and EBMP2-069 those of the adapter-binding rule. The imported core checks
	// other conditions for all three (accepted suites and mandatory signers among eligible keys
	// that the policy does not list; three of the authorization's six members; mapped and unmapped
	// targets, the source's retention and a lossless class only, stopping at the first failure), so
	// its findings give way to repository checks of exactly the stated conditions. Unreadable key
	// lists fail the schema, which reports them.
	if root, isObject := value.(map[string]any); isObject {
		integrity, _ := validatorx.IntegrityPolicy(root)
		findings = append(findings, convert(integrity)...)
		protocol, _ := root["protocol"].(string)
		version, _ := root["schema_version"].(string)
		switch {
		case protocol == "DCMP-2":
			findings = append(findings, convert(validatorx.AdmitAuthority(root))...)
		case protocol != "EBMP-2" && version == "ecl_adapter_binding_v1":
			findings = append(findings, convert(validatorx.AdapterBinding(root))...)
		}
	}
	findings = append(findings, convert(validatorx.Protocol(value, validator.Options{KnownExtensions: options.KnownExtensions}))...)
	if protocol, _ := pyjson.Text(pyjson.Get(value, "protocol")); protocol == "DCMP-2" || protocol == "EBMP-2" {
		findings = append(findings, Extensions(value, options)...)
	}
	Sort(findings)
	return findings, nil
}

// SafeStateProfile checks the STRICT-FAILURE-1 obligations of a safe-state profile.
func SafeStateProfile(value any) []Finding {
	findings := convert(validatorx.Validate(value))
	Sort(findings)
	return findings
}

// malformed is the panic value of a check that cannot read the value it needs; guard turns it
// into one schema-invalid finding, as the reference does.
type malformed struct{ message string }

func guard(name string, check func() []Finding) (findings []Finding) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var message string
			switch problem := recovered.(type) {
			case *pyjson.TypeError:
				message = problem.Message
			case malformed:
				message = problem.message
			default:
				panic(recovered)
			}
			findings = []Finding{{RuleID: SchemaInvalid, Path: "/", Detail: name + " semantic check rejected malformed input: " + message}}
		}
	}()
	return check()
}

func timeOf(value any) instant.Instant {
	parsed, err := instant.Parse(value)
	if err != nil {
		panic(malformed{err.Error()})
	}
	return parsed
}

// extensionValues returns (index, value) of each well-formed occurrence of one extension.
func extensionValues(value any, identifier string) ([]int, []map[string]any) {
	list, _ := pyjson.Array(pyjson.Get(value, "extensions"))
	var indexes []int
	var values []map[string]any
	for index, item := range list {
		extension, isObject := pyjson.Object(item)
		content, valueIsObject := pyjson.Object(pyjson.Get(item, "value"))
		if isObject && pyjson.Equal(extension["id"], identifier) && valueIsObject {
			indexes = append(indexes, index)
			values = append(values, content)
		}
	}
	return indexes, values
}

var (
	permitting = []struct {
		member  string
		results map[string]bool
	}{
		{"budget_result", map[string]bool{"authorized": true}},
		{"witness_result", map[string]bool{"satisfied": true, "required_before_release": true}},
		{"quorum_result", map[string]bool{"met": true}},
	}
	approvalOperations = map[string]bool{"approve": true, "reject": true}
	disablingChanges   = map[string]bool{"disable": true, "bypass": true, "auto_approve": true}
	// DCMP2-053, ECL1N-0179 and ECL1N-0182: an input that the governed AI system produces or can
	// write, or a judgment about meaning or risk, only ever makes an outcome stricter.
	restrictingOnlyClasses = map[string]bool{"actor_supplied": true, "judgment": true}
)

// extensionChecks lists, for each protocol, the registered extension rules after the value
// schemas, in the reference's order. A rule added to the registry is one function and one row.
var extensionChecks = map[string][]struct {
	name  string
	check func(any) []Finding
}{
	"DCMP-2": {{"consequence coupling", couplingResults}, {"decision basis", decisionBasis}},
	"EBMP-2": {{"approval record", approvalRecords}, {"control change", controlChanges}},
}

// Extensions checks the registered extensions of a DCMP-2 or EBMP-2 object: each value against
// its registered schema (XR1-023), consequence-coupling results on an admit (DCMP2-052), the
// decision basis of a decision response (DCMP2-053), the minimum review time of an approval
// record (EBMP2-063) and the approvers and expiry of a control change (EBMP2-064).
func Extensions(value any, options Options) []Finding {
	findings := guard("extension value", func() []Finding { return valueSchemas(value, options) })
	protocol, _ := pyjson.Text(pyjson.Get(value, "protocol"))
	for _, row := range extensionChecks[protocol] {
		check := row.check
		findings = append(findings, guard(row.name, func() []Finding { return check(value) })...)
	}
	return findings
}

func valueSchemas(value any, options Options) []Finding {
	var findings []Finding
	list, _ := pyjson.Array(pyjson.Get(value, "extensions"))
	for index, item := range list {
		extension, isObject := pyjson.Object(item)
		if !isObject {
			continue
		}
		identifier, _ := pyjson.Text(extension["id"])
		reference, registered := options.ValueSchemas[identifier]
		content, present := extension["value"]
		if !registered || !present || options.Schemas == nil {
			continue
		}
		if valid, err := options.Schemas.Valid(reference, content); err != nil || !valid {
			findings = append(findings, Finding{RuleID: RuleExtensionValue, Path: fmt.Sprintf("/extensions/%d/value", index), Detail: "value of " + identifier + " does not match its registered schema"})
		}
	}
	return findings
}

func couplingResults(value any) []Finding {
	if !pyjson.Equal(pyjson.Get(value, "message_type"), "decision_response") || !pyjson.Equal(pyjson.Get(value, "outcome"), "admit") {
		return nil
	}
	var findings []Finding
	deferred := false
	if obligations, isList := pyjson.Array(pyjson.Get(value, "obligations")); isList {
		for _, entry := range obligations {
			if _, isObject := pyjson.Object(entry); isObject && pyjson.Equal(pyjson.Get(entry, "satisfaction"), "before_release") {
				deferred = true
			}
		}
	}
	indexes, values := extensionValues(value, couplingExtension)
	for position, coupling := range values {
		index := indexes[position]
		for _, rule := range permitting {
			result, isObject := pyjson.Object(coupling[rule.member])
			if !isObject {
				continue
			}
			outcome := result["outcome"]
			path := fmt.Sprintf("/extensions/%d/value/%s/outcome", index, rule.member)
			if !pyjson.InSet(outcome, rule.results) {
				findings = append(findings, Finding{RuleID: RuleCoupling, Path: path, Detail: "an admit cannot carry " + rule.member + " outcome " + pyjson.Str(outcome)})
			} else if pyjson.Equal(outcome, "required_before_release") && !deferred {
				findings = append(findings, Finding{RuleID: RuleCoupling, Path: path, Detail: "a deferred witness check needs a before_release obligation"})
			}
		}
		if _, present := coupling["blocker_reason"]; present {
			findings = append(findings, Finding{RuleID: RuleCoupling, Path: fmt.Sprintf("/extensions/%d/value/blocker_reason", index), Detail: "an admit cannot carry a blocker reason"})
		}
	}
	return findings
}

// decisionBasis is DCMP2-053 on each decision-basis value of a decision response
// (OneWayProblemsAt), with the response's outcome and evaluated_at. The value schema is checked
// first, by the extension-value rule (XR1-023); this rule reads only the members it needs.
func decisionBasis(value any) []Finding {
	if !pyjson.Equal(pyjson.Get(value, "message_type"), "decision_response") {
		return nil
	}
	outcome := pyjson.Get(value, "outcome")
	admit := pyjson.Equal(outcome, "admit")
	var findings []Finding
	indexes, values := extensionValues(value, DecisionBasisExtension)
	for position, basis := range values {
		prefix := fmt.Sprintf("/extensions/%d/value", indexes[position])
		for _, problem := range OneWayProblemsAt(basis, admit, outcome, pyjson.Get(value, "evaluated_at")) {
			findings = append(findings, Finding{RuleID: RuleDecisionBasis, Path: prefix + problem[0], Detail: problem[1]})
		}
	}
	return findings
}

// asciiLower lowercases the ASCII letters of text and leaves every other character as it is.
func asciiLower(text string) string {
	out := []byte(text)
	for index, character := range out {
		if character >= 'A' && character <= 'Z' {
			out[index] = character + ('a' - 'A')
		}
	}
	return string(out)
}

// isHexDigit reports whether a byte is an ASCII hexadecimal digit.
func isHexDigit(character byte) bool {
	return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')
}

// percentUpper returns name with the two hexadecimal digits of every percent-encoding in upper case.
func percentUpper(name string) string {
	out := []byte(name)
	for index := 0; index < len(out); {
		if out[index] == '%' && index+2 < len(out) && isHexDigit(out[index+1]) && isHexDigit(out[index+2]) {
			for _, at := range []int{index + 1, index + 2} {
				if out[at] >= 'a' && out[at] <= 'f' {
					out[at] -= 'a' - 'A'
				}
			}
			index += 3
		} else {
			index++
		}
	}
	return string(out)
}

// InputKey is the form in which DCMP2-053 compares an input name, an entry's source with its
// declared source and with the request's actor, as the reference's input_key gives it: the case
// normalization of RFC 3986 section 6.2.2.1 and RFC 8141 section 3.1, in ASCII only. The URI
// scheme is lowercased; so are, for a URN, its namespace identifier and, for an http or https URI,
// its host (the authority after any user information, port included); then the two hexadecimal
// digits of every percent-encoding are uppercased. No other normalization is applied.
func InputKey(name string) string {
	colon := strings.Index(name, ":")
	if colon <= 0 {
		return percentUpper(name)
	}
	scheme := asciiLower(name[:colon])
	rest := name[colon:]
	if scheme == "urn" {
		if end := strings.Index(name[colon+1:], ":"); end != -1 {
			end += colon + 1
			rest = ":" + asciiLower(name[colon+1:end]) + name[end:]
		}
	} else if (scheme == "http" || scheme == "https") && strings.HasPrefix(rest, "://") {
		start, end := 3, len(rest)
		if found := strings.IndexAny(rest[start:], "/?#"); found != -1 {
			end = start + found
		}
		host := start
		if at := strings.LastIndex(rest[start:end], "@"); at != -1 {
			host = start + at + 1
		}
		rest = rest[:host] + asciiLower(rest[host:end]) + rest[end:]
	}
	return percentUpper(scheme + rest)
}

// instantOf returns an ECL instant, or false for a value that is not one (left to the schema).
func instantOf(value any) (instant.Instant, bool) {
	parsed, err := instant.Parse(value)
	return parsed, err == nil
}

func derivedNames(item map[string]any) []string {
	derived, isList := pyjson.Array(item["derived_from"])
	if !isList {
		return nil
	}
	var names []string
	for _, candidate := range derived {
		if name, isText := pyjson.Text(candidate); isText {
			names = append(names, name)
		}
	}
	return names
}

// derivedSources returns the keys of the entries that item is computed from, directly or through
// other entries: the names its derived_from gives, other than its own, followed through the
// entries they name, as the reference's _sources finds them.
func derivedSources(item map[string]any, byKey map[string]map[string]any) map[string]bool {
	ownKey, hasOwn := "", false
	if own, isText := pyjson.Text(item["input"]); isText {
		ownKey, hasOwn = InputKey(own), true
	}
	var pending []string
	for _, name := range derivedNames(item) {
		key := InputKey(name)
		if _, known := byKey[key]; known && !(hasOwn && key == ownKey) {
			pending = append(pending, key)
		}
	}
	seen := map[string]bool{}
	for len(pending) > 0 {
		key := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, name := range derivedNames(byKey[key]) {
			source := InputKey(name)
			if _, known := byKey[source]; known && !seen[source] {
				pending = append(pending, source)
			}
		}
	}
	return seen
}

type basisEntry struct {
	position int
	item     map[string]any
}

// OneWayProblems gives (path below the value, message) for each way a decision-basis value breaks
// DCMP2-053 without its response: OneWayProblemsAt with no outcome and no evaluation time.
func OneWayProblems(basis map[string]any, admit bool) [][2]string {
	return OneWayProblemsAt(basis, admit, nil, nil)
}

// OneWayProblemsAt gives (path below the value, message) for each way a decision-basis value
// breaks DCMP2-053, as the reference's decision_basis.one_way_problems does: an input listed more
// than once, names compared by InputKey; an actor_supplied or judgment input, or an input that was
// not available, that supports an outcome; a derived_from that names no other input of the
// record, a verifiable input computed from one that is not verifiable, or an input computed from
// itself through other inputs; an input computed, directly or through other entries, from an
// input that was not available, which counts as not available; for an admit, a required input
// that was not available or no verifiable input that supports it. With the response's outcome
// and evaluated_at (nil when the caller has no response): an outcome less strict than a recorded
// verifiable_only_outcome, an available input obtained after the decision, and a received_at
// after the decision; a record that gives obtained_at without received_at is refused either way.
func OneWayProblemsAt(basis map[string]any, admit bool, outcome, evaluatedAt any) [][2]string {
	inputs, isList := pyjson.Array(basis["inputs"])
	if !isList {
		return nil
	}
	var entries []basisEntry
	for at, candidate := range inputs {
		if item, isObject := pyjson.Object(candidate); isObject {
			entries = append(entries, basisEntry{at, item})
		}
	}
	var problems [][2]string
	byKey := map[string]map[string]any{}
	for _, current := range entries {
		name, isText := pyjson.Text(current.item["input"])
		if !isText {
			continue
		}
		key := InputKey(name)
		if _, seen := byKey[key]; seen {
			problems = append(problems, [2]string{fmt.Sprintf("/inputs/%d/input", current.position), "the record lists this input more than once"})
		} else {
			byKey[key] = current.item
		}
	}
	decided, hasDecided := instantOf(evaluatedAt)
	supported := false
	for _, current := range entries {
		path := fmt.Sprintf("/inputs/%d", current.position)
		supports := pyjson.Equal(current.item["effect"], "supports")
		class, status := current.item["class"], current.item["status"]
		available := pyjson.Equal(status, "available")
		if supports && pyjson.InSet(class, restrictingOnlyClasses) {
			problems = append(problems, [2]string{path + "/effect", "an input of class " + pyjson.Repr(class) + " can only make an outcome stricter"})
		}
		if supports && !available {
			problems = append(problems, [2]string{path + "/effect", "an input whose status is " + pyjson.Repr(status) + " cannot support an outcome"})
		}
		required := current.item["required"] == true
		if admit && required && !available {
			problems = append(problems, [2]string{path + "/status", "an admit cannot proceed while a required input is " + pyjson.Repr(status)})
		}
		ownKey, hasOwn := "", false
		if own, isText := pyjson.Text(current.item["input"]); isText {
			ownKey, hasOwn = InputKey(own), true
		}
		if derived, isDerived := pyjson.Array(current.item["derived_from"]); isDerived {
			for offset, candidate := range derived {
				name, isText := pyjson.Text(candidate)
				source, known := map[string]any(nil), false
				if isText {
					source, known = byKey[InputKey(name)]
				}
				if !isText || (hasOwn && InputKey(name) == ownKey) || !known {
					problems = append(problems, [2]string{fmt.Sprintf("%s/derived_from/%d", path, offset), "the record lists no other input with this name"})
				} else if pyjson.Equal(class, "verifiable") && !pyjson.Equal(source["class"], "verifiable") {
					problems = append(problems, [2]string{path + "/class", "an input computed from an input of class " + pyjson.Repr(source["class"]) + " cannot be verifiable"})
				}
			}
		}
		sources := derivedSources(current.item, byKey)
		if hasOwn && sources[ownKey] {
			problems = append(problems, [2]string{path + "/derived_from", "the input is computed from itself through other inputs"})
		}
		unavailable := false
		for key := range sources {
			if !(hasOwn && key == ownKey) && !pyjson.Equal(byKey[key]["status"], "available") {
				unavailable = true
			}
		}
		if unavailable && available && supports {
			problems = append(problems, [2]string{path + "/effect", "an input computed from an input that was not available cannot support an outcome"})
		}
		if unavailable && available && admit && required {
			problems = append(problems, [2]string{path + "/status", "an admit cannot proceed while a required input is computed from an input that was not available"})
		}
		obtained, hasObtained := instantOf(current.item["obtained_at"])
		if available && hasDecided && hasObtained && instant.Compare(obtained, decided) > 0 {
			problems = append(problems, [2]string{path + "/status", "an input obtained after the decision was not available"})
		}
		described, hasDescribed := instantOf(current.item["value_at"])
		if hasDescribed && hasObtained && instant.Compare(described, obtained) > 0 {
			problems = append(problems, [2]string{path + "/value_at", "the input's value describes a time after it was obtained"})
		}
		if hasDescribed && hasDecided && instant.Compare(described, decided) > 0 {
			problems = append(problems, [2]string{path + "/value_at", "the input's value describes a time after the decision"})
		}
		if available && pyjson.Has(basis, "received_at") && !(pyjson.Has(current.item, "obtained_at") && pyjson.Has(current.item, "value_at")) {
			problems = append(problems, [2]string{path, "a record that gives when the request was received gives when each available input was obtained and the time its value describes"})
		}
		if pyjson.Equal(class, "verifiable") && supports {
			supported = true
		}
	}
	if admit && !supported {
		problems = append(problems, [2]string{"/inputs", "an admit records no verifiable input that supports it"})
	}
	if !pyjson.Has(basis, "received_at") {
		for _, current := range entries {
			if pyjson.Has(current.item, "obtained_at") {
				problems = append(problems, [2]string{"/received_at", "a record that gives when an input was obtained gives when the request was received"})
				break
			}
		}
	}
	if received, hasReceived := instantOf(basis["received_at"]); hasReceived && hasDecided && instant.Compare(received, decided) > 0 {
		problems = append(problems, [2]string{"/received_at", "the request was received after the decision"})
	}
	recorded, recordedIsText := pyjson.Text(basis["verifiable_only_outcome"])
	stated, statedIsText := pyjson.Text(outcome)
	if recordedIsText && statedIsText && rank(stated) >= 0 && rank(recorded) >= 0 && rank(stated) < rank(recorded) {
		problems = append(problems, [2]string{"/verifiable_only_outcome", "the outcome " + pyjson.Repr(stated) + " is less strict than the verifiable-only outcome " + pyjson.Repr(recorded)})
	}
	if recordedIsText && rank(recorded) >= 0 {
		problems = append(problems, verifiableOnlyProblems(recorded, entries, byKey)...)
	}
	return problems
}

// verifiableOnlyProblems is DCMP2-053 on a recorded verifiable_only_outcome, as the reference's
// _verifiable_only_problems gives it: an input supports only a verifiable-only admit
// (ECL1N-0181), and a verifiable-only admit rests on at least one verifiable input that supports
// it and on no required verifiable input that was not available, an input computed from one that
// was not available counting as not available itself. A required actor_supplied or judgment input
// does not change the verifiable-only outcome.
func verifiableOnlyProblems(recorded string, entries []basisEntry, byKey map[string]map[string]any) [][2]string {
	var problems [][2]string
	if recorded != "admit" {
		for _, current := range entries {
			if pyjson.Equal(current.item["effect"], "supports") {
				problems = append(problems, [2]string{fmt.Sprintf("/inputs/%d/effect", current.position), "no input supports an outcome whose verifiable-only outcome is " + pyjson.Repr(recorded)})
			}
		}
		return problems
	}
	supported := false
	for _, current := range entries {
		if pyjson.Equal(current.item["class"], "verifiable") && pyjson.Equal(current.item["effect"], "supports") {
			supported = true
		}
	}
	if !supported {
		problems = append(problems, [2]string{"/verifiable_only_outcome", "a verifiable-only admit records no verifiable input that supports it"})
	}
	for _, current := range entries {
		if current.item["required"] != true || !pyjson.Equal(current.item["class"], "verifiable") {
			continue
		}
		ownKey, hasOwn := "", false
		if own, isText := pyjson.Text(current.item["input"]); isText {
			ownKey, hasOwn = InputKey(own), true
		}
		unavailable := !pyjson.Equal(current.item["status"], "available")
		for key := range derivedSources(current.item, byKey) {
			if !(hasOwn && key == ownKey) && !pyjson.Equal(byKey[key]["status"], "available") {
				unavailable = true
			}
		}
		if unavailable {
			problems = append(problems, [2]string{fmt.Sprintf("/inputs/%d/status", current.position), "a verifiable-only admit cannot have a required verifiable input that was not available"})
		}
	}
	return problems
}

// rank is the place of an outcome in the strictness order, or -1 for another value.
func rank(outcome string) int {
	for index, item := range outcomes {
		if item == outcome {
			return index
		}
	}
	return -1
}

// declarationProblems is the register declarations rule for the decision_inputs of one action
// entry.
func declarationProblems(declared []any, base string) [][2]string {
	var problems [][2]string
	var entries []basisEntry
	for at, candidate := range declared {
		if item, isObject := pyjson.Object(candidate); isObject {
			entries = append(entries, basisEntry{at, item})
		}
	}
	byKey := map[string]map[string]any{}
	for _, current := range entries {
		name, isText := pyjson.Text(current.item["input"])
		if !isText {
			continue
		}
		key := InputKey(name)
		if _, seen := byKey[key]; seen {
			problems = append(problems, [2]string{fmt.Sprintf("%s/%d/input", base, current.position), "the register declares this input more than once for the action class"})
		} else {
			byKey[key] = current.item
		}
	}
	for _, current := range entries {
		path := fmt.Sprintf("%s/%d", base, current.position)
		ownKey, hasOwn := "", false
		if own, isText := pyjson.Text(current.item["input"]); isText {
			ownKey, hasOwn = InputKey(own), true
		}
		if derived, isDerived := pyjson.Array(current.item["derived_from"]); isDerived {
			for offset, candidate := range derived {
				name, isText := pyjson.Text(candidate)
				source, known := map[string]any(nil), false
				if isText {
					source, known = byKey[InputKey(name)]
				}
				if !isText || (hasOwn && InputKey(name) == ownKey) || !known {
					problems = append(problems, [2]string{fmt.Sprintf("%s/derived_from/%d", path, offset), "the register declares no other input of the action class with this name"})
				} else if pyjson.Equal(current.item["class"], "verifiable") && !pyjson.Equal(source["class"], "verifiable") {
					problems = append(problems, [2]string{path + "/class", "an input computed from an input of class " + pyjson.Repr(source["class"]) + " cannot be verifiable"})
				}
			}
		}
		if hasOwn && derivedSources(current.item, byKey)[ownKey] {
			problems = append(problems, [2]string{path + "/derived_from", "the input is computed from itself through other inputs"})
		}
	}
	return problems
}

// RegisterDocumentProblems gives (path, message) for each way a register document breaks
// ecl.rule.register-declarations-consistent.v1 (ECL1N-0178), as the reference's
// register_document_problems does: an action class declared more than once, an input declared
// more than once for a class, a derived_from name that is not another input of the class, an
// input declared verifiable that is computed from one that is not, or an input computed from
// itself through other inputs. Members of another shape are left to the register schema.
func RegisterDocumentProblems(register map[string]any) [][2]string {
	var problems [][2]string
	entries, isList := pyjson.Array(register["entries"])
	if !isList {
		return problems
	}
	classes := map[string]bool{}
	for index, candidate := range entries {
		entry, isObject := pyjson.Object(candidate)
		if !isObject {
			continue
		}
		path := fmt.Sprintf("/entries/%d", index)
		if class, isText := pyjson.Text(entry["action_class_id"]); isText {
			if classes[class] {
				problems = append(problems, [2]string{path + "/action_class_id", "the register declares this action class more than once"})
			} else {
				classes[class] = true
			}
		}
		if declared, isDeclared := pyjson.Array(entry["decision_inputs"]); isDeclared {
			problems = append(problems, declarationProblems(declared, path+"/decision_inputs")...)
		}
	}
	return problems
}

func approvalRecords(value any) []Finding {
	event, isObject := pyjson.Object(pyjson.Get(value, "event"))
	if !pyjson.Equal(pyjson.Get(value, "event_type"), "human_intervention") || !isObject || !pyjson.InSet(event["operation"], approvalOperations) {
		return nil
	}
	issued, isText := pyjson.Text(event["issued_at"])
	if !isText {
		return nil
	}
	var findings []Finding
	indexes, values := extensionValues(value, approvalExtension)
	for position, record := range values {
		presented, presentedIsText := pyjson.Text(record["presented_at"])
		minimum, isInt := pyjson.Int(record["minimum_review_seconds"])
		if !presentedIsText || !isInt {
			continue
		}
		if instant.Compare(timeOf(issued), timeOf(presented).AddSeconds(minimum)) < 0 {
			findings = append(findings, Finding{RuleID: RuleReviewTime, Path: fmt.Sprintf("/extensions/%d/value/presented_at", indexes[position]), Detail: "the decision came sooner than the minimum review time after presentation"})
		}
	}
	return findings
}

func controlChanges(value any) []Finding {
	var findings []Finding
	indexes, values := extensionValues(value, changeExtension)
	for position, change := range values {
		index := indexes[position]
		if approvers, isList := pyjson.Array(change["approved_by"]); isList && pyjson.InList(change["requested_by"], approvers) {
			findings = append(findings, Finding{RuleID: RuleControlChange, Path: fmt.Sprintf("/extensions/%d/value/approved_by", index), Detail: "the requester of a control change cannot approve it"})
		}
		effective, effectiveIsText := pyjson.Text(change["effective_at"])
		if pyjson.InSet(change["change"], disablingChanges) && effectiveIsText {
			expires, expiresIsText := pyjson.Text(change["expires_at"])
			if !expiresIsText || instant.Compare(timeOf(expires), timeOf(effective)) <= 0 {
				findings = append(findings, Finding{RuleID: RuleControlChange, Path: fmt.Sprintf("/extensions/%d/value/expires_at", index), Detail: "a " + pyjson.Str(change["change"]) + " change must expire after it takes effect"})
			}
		}
	}
	return findings
}
