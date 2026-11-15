package validatorx

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
)

// The rules of every ECL object that carries extensions (EXTENSION-REGISTRY-1 section 2 and
// XR1-017), and the two rules that the reference applies to every object it validates. This is
// fresh repository code written from those requirements, beside the imported foundation core,
// which applies XR1-006 and XR1-009 only to the DCMP-2 and EBMP-2 objects it recognizes.
const (
	RuleExtensionVersion  = "ecl.rule.extension-single-version.v1"
	RuleExtensionUnique   = "ecl.rule.extension-identifiers-unique.v1"
	RuleUnknownCritical   = "ecl.rule.unknown-critical-extension-rejected.v1"
	RuleSelfCausation     = "ecl.rule.message-cannot-cause-itself.v1"
	RuleIntegrityPolicy   = "ecl.rule.integrity-threshold-consistent.v1"
	schemaInvalid         = "ecl.error.schema-invalid.v1"
	malformedEntriesError = "extension entries must be objects"
	malformedListError    = "extensions must be an array"
)

// extensionRegistry is the registry snapshot that the extension checks read, as the reference's
// conformance runner gives it: every allocated identifier whatever its status (XR1-017), the
// versions of the active entries, which are the occurrences a consumer that implements every
// active entry knows (XR1-006), and the identifiers whose versions are composable (XR1-010).
type extensionRegistry struct {
	known      map[string]bool
	active     map[string]map[int64]bool
	composable map[string]bool
	applicable ExtensionApplicability
}

// ExtensionApplicability binds each identifier/version to its declared object types.
type ExtensionApplicability map[string]map[int64]map[string]bool

var snapshot = sync.OnceValue(func() extensionRegistry {
	found := extensionRegistry{known: map[string]bool{}, active: map[string]map[int64]bool{}, composable: registry.ComposableExtensions(), applicable: ExtensionApplicability{}}
	for _, entry := range registry.Entries("extensions") {
		found.known[entry.ID] = true
		if found.applicable[entry.ID] == nil {
			found.applicable[entry.ID] = map[int64]map[string]bool{}
		}
		kinds := map[string]bool{}
		for _, kind := range entry.AppliesTo {
			kinds[kind] = true
		}
		found.applicable[entry.ID][entry.Version] = kinds
		if entry.Status != "active" {
			continue
		}
		if found.active[entry.ID] == nil {
			found.active[entry.ID] = map[int64]bool{}
		}
		found.active[entry.ID][entry.Version] = true
	}
	return found
})

// ObjectType identifies the carrying object rather than an envelope's payload.
func ObjectType(root map[string]any) string {
	protocol, _ := root["protocol"].(string)
	if protocol == "DCMP-2" || protocol == "EBMP-2" || protocol == "ECL-WI-1" {
		return protocol
	}
	if kind, ok := root["envelope_version"].(string); ok {
		return kind
	}
	return protocol
}

func configuredExtensions(active map[string]map[int]bool, applicability ExtensionApplicability) extensionRegistry {
	ext := snapshot()
	if applicability != nil {
		ext.applicable = applicability
	}
	if active != nil {
		ext.active = map[string]map[int64]bool{}
		for identifier, versions := range active {
			ext.active[identifier] = map[int64]bool{}
			for version, implemented := range versions {
				ext.active[identifier][int64(version)] = implemented
			}
		}
	}
	return ext
}

// Interpretable applies both implemented-version and carrying-object restrictions.
func Interpretable(root map[string]any, identifier string, version int64, active map[string]map[int]bool, applicability ExtensionApplicability) bool {
	ext := configuredExtensions(active, applicability)
	return ext.active[identifier][version] && ext.applicable[identifier][version][ObjectType(root)]
}

// Allocated reports whether the embedded registry holds an identifier under any status (XR1-017).
func Allocated(identifier string) bool {
	return snapshot().known[identifier]
}

// extensionEntries preserves array positions while leaving malformed entries to the schema.
// Absent or null is no extension; a present member of another type is malformed.
func extensionEntries(root map[string]any) ([]map[string]any, string) {
	raw, present := root["extensions"]
	if !present || raw == nil {
		return nil, ""
	}
	list, isList := raw.([]any)
	if !isList {
		return nil, malformedListError
	}
	entries := make([]map[string]any, 0, len(list))
	for _, item := range list {
		// Keep positions while leaving malformed entries to the schema.
		entry, _ := item.(map[string]any)
		entries = append(entries, entry)
	}
	return entries, ""
}

// ExtensionVersions returns the XR1-010 findings of one object: a second occurrence of an
// extension identifier at another version is a finding at its index, whether or not either
// version is known, unless composable names the identifier. An entry whose id is not a string or
// whose version is not an integer is left to the schema and to XR1-009. The second result is the
// reason the extensions member cannot be read, or "".
func ExtensionVersions(root map[string]any, composable map[string]bool) ([]validator.Finding, string) {
	entries, problem := extensionEntries(root)
	if problem != "" {
		return nil, problem
	}
	findings := []validator.Finding{}
	first := map[string]int64{}
	for index, entry := range entries {
		identifier, isText := entry["id"].(string)
		version, isInteger := pyjson.SchemaInt(entry["version"])
		if !isText || !isInteger || composable[identifier] {
			continue
		}
		earlier, seen := first[identifier]
		if !seen {
			first[identifier] = version
			continue
		}
		if version != earlier {
			findings = append(findings, validator.Finding{
				RuleID: RuleExtensionVersion,
				Path:   fmt.Sprintf("/extensions/%d", index),
				Detail: fmt.Sprintf("extension %s appears at version %d and at version %d", identifier, earlier, version),
			})
		}
	}
	return findings, ""
}

// extensionsUnique is XR1-009 on correctly typed identifier/version pairs.
func extensionsUnique(root map[string]any) ([]validator.Finding, string) {
	entries, problem := extensionEntries(root)
	if problem != "" {
		return nil, problem
	}
	findings := []validator.Finding{}
	seen := map[string]bool{}
	for index, entry := range entries {
		identifier, isText := entry["id"].(string)
		version, isInteger := pyjson.SchemaInt(entry["version"])
		if !isText || !isInteger {
			continue
		}
		key := identifier + "\x00" + strconv.FormatInt(version, 10)
		if seen[key] {
			findings = append(findings, validator.Finding{
				RuleID: RuleExtensionUnique,
				Path:   fmt.Sprintf("/extensions/%d", index),
				Detail: fmt.Sprintf("duplicate extension allocation %s version %d", identifier, version),
			})
		}
		seen[key] = true
	}
	return findings, ""
}

// extensionNamespace is XR1-017: an ecl.* identifier is allocated in the registry snapshot.
func extensionNamespace(root map[string]any, known map[string]bool) ([]validator.Finding, string) {
	entries, problem := extensionEntries(root)
	if problem != "" {
		return nil, problem
	}
	findings := []validator.Finding{}
	for index, entry := range entries {
		identifier, isText := entry["id"].(string)
		if isText && ((strings.HasPrefix(identifier, "ecl.") && !known[identifier]) || reservedExtensionNamespace(identifier)) {
			findings = append(findings, validator.Finding{
				RuleID: RuleExtensionNamespace,
				Path:   fmt.Sprintf("/extensions/%d/id", index),
				Detail: "unallocated ECL extension identifier " + identifier,
			})
		}
	}
	return findings, ""
}

// Only the XR1-017 reservation comparison decodes ASCII unreserved host escapes once
// and removes one terminal DNS dot. Identifier and principal bytes remain unchanged.
func reservedExtensionNamespace(identifier string) bool {
	// URI validation owns malformed inputs before the XR1-017 host comparison.
	if !schema.IsURI(identifier) {
		return false
	}
	parsed, ok := schema.SplitURI(identifier)
	if !ok || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	authority := parsed.Netloc
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	if strings.HasPrefix(authority, "[") {
		return false
	}
	host, _, _ := strings.Cut(authority, ":")
	var comparison strings.Builder
	for index := 0; index < len(host); index++ {
		if host[index] == '%' && index+2 < len(host) {
			decoded, err := strconv.ParseUint(host[index+1:index+3], 16, 8)
			if err == nil && ((decoded >= 'a' && decoded <= 'z') ||
				(decoded >= 'A' && decoded <= 'Z') || (decoded >= '0' && decoded <= '9') ||
				decoded == '-' || decoded == '.' || decoded == '_' || decoded == '~') {
				comparison.WriteByte(byte(decoded))
				index += 2
				continue
			}
		}
		comparison.WriteByte(host[index])
	}
	return strings.EqualFold(strings.TrimSuffix(comparison.String(), "."), "externalcontrollayer.ai")
}

// criticalExtensions is XR1-006: a critical extension that is unknown to the consumer, one without
// an active entry of its identifier and version, is rejected.
func criticalExtensions(root map[string]any, ext extensionRegistry) ([]validator.Finding, string) {
	entries, problem := extensionEntries(root)
	if problem != "" {
		return nil, problem
	}
	findings := []validator.Finding{}
	for index, entry := range entries {
		if entry["critical"] != true {
			continue
		}
		identifier, isText := entry["id"].(string)
		version, isInteger := pyjson.SchemaInt(entry["version"])
		if !isText || !isInteger {
			continue
		}
		if !ext.active[identifier][version] || !ext.applicable[identifier][version][ObjectType(root)] {
			findings = append(findings, validator.Finding{
				RuleID: RuleUnknownCritical,
				Path:   fmt.Sprintf("/extensions/%d/id", index),
				Detail: "unknown critical extension " + pyjson.Str(entry["id"]) + " version " + pyjson.Repr(entry["version"]),
			})
		}
	}
	return findings, ""
}

// selfCausation is the reference's check that an object does not name itself as a causal
// predecessor.
func selfCausation(root map[string]any) ([]validator.Finding, string) {
	objectID := root["message_id"]
	if !pyjson.Truthy(objectID) {
		objectID = root["object_id"]
	}
	if root["protocol"] == "ECL-WI-1" && pyjson.Truthy(root["intent_id"]) {
		objectID = root["intent_id"]
	}
	raw, present := root["workflow"]
	if !present || raw == nil {
		return nil, ""
	}
	workflow, isObject := raw.(map[string]any)
	if !isObject {
		return nil, "workflow must be an object"
	}
	listed := workflow["causal_predecessors"]
	if !pyjson.Truthy(listed) {
		listed = []any{}
	}
	predecessors, isList := listed.([]any)
	if !isList {
		return nil, "causal_predecessors must be an array"
	}
	if root["protocol"] == "DCMP-2" || root["protocol"] == "EBMP-2" {
		// Core identities are schema-required strings. Keep the imported core's
		// typed identity domain while adding shared container diagnostics; a
		// malformed numeric identity must not enter rational comparison here.
		// Use the protocol's own identity even when unrelated fields are present.
		identityMember := "message_id"
		if root["protocol"] == "EBMP-2" {
			identityMember = "object_id"
		}
		identifier, isText := root[identityMember].(string)
		if !isText || identifier == "" {
			return nil, ""
		}
		for _, item := range predecessors {
			if entry, isEntry := item.(map[string]any); isEntry {
				previous, isText := entry["id"].(string)
				if isText && previous == identifier {
					return []validator.Finding{{RuleID: RuleSelfCausation, Path: "/workflow/causal_predecessors", Detail: "an object cannot name itself as a causal predecessor"}}, ""
				}
			}
		}
		return nil, ""
	}
	if !pyjson.Truthy(objectID) {
		return nil, ""
	}
	for _, item := range predecessors {
		if entry, isEntry := item.(map[string]any); isEntry && pyjson.Equal(entry["id"], objectID) {
			return []validator.Finding{{RuleID: RuleSelfCausation, Path: "/workflow/causal_predecessors", Detail: "an object cannot name itself as a causal predecessor"}}, ""
		}
	}
	return nil, ""
}

// SelfCausation applies the shared check, retaining one schema finding when its
// workflow or predecessor container is unreadable.
func SelfCausation(root map[string]any) []validator.Finding {
	found, problem := selfCausation(root)
	if problem != "" {
		return []validator.Finding{{RuleID: schemaInvalid, Path: "/", Detail: "self-causation semantic check rejected malformed input: " + problem}}
	}
	return found
}

// hashable reports whether Python could put value in a set: an object or an array cannot be.
func hashable(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return false
	default:
		return true
	}
}

// integrityPolicy is the reference's check that an integrity policy's required flag, threshold
// and key lists are consistent.
// IntegrityPolicy checks each IE1-013 relation only when that relation's members have the
// schema-required types. Malformed members are left to schema validation; independent,
// correctly typed threshold and key-list relations remain checkable.
func IntegrityPolicy(root map[string]any) ([]validator.Finding, string) {
	policy, isObject := root["integrity_policy"].(map[string]any)
	if !isObject {
		return nil, ""
	}
	required, requiredTyped := policy["required"].(bool)
	keyList := func(name string) ([]any, bool) {
		value, present := policy[name]
		if !present {
			return []any{}, true
		}
		list, isList := value.([]any)
		for _, entry := range list {
			if _, isText := entry.(string); !isText {
				return nil, false
			}
		}
		return list, isList
	}
	requiredKeys, requiredOK := keyList("required_key_ids")
	eligibleKeys, eligibleOK := keyList("eligible_key_ids")
	threshold, isInteger := pyjson.SchemaInt(policy["threshold"])
	invalid := (requiredTyped && isInteger && ((required && threshold < 1) || (!required && threshold != 0))) ||
		(isInteger && requiredOK && threshold < int64(len(requiredKeys)))
	if !invalid && requiredOK && eligibleOK && len(eligibleKeys) > 0 {
		for _, wanted := range requiredKeys {
			if !pyjson.InList(wanted, eligibleKeys) {
				invalid = true
				break
			}
		}
	}
	if invalid {
		return []validator.Finding{{RuleID: RuleIntegrityPolicy, Path: "/integrity_policy", Detail: "integrity required flag, threshold, eligible keys, and required keys are inconsistent"}}, ""
	}
	return nil, ""
}

// ExtensionConsumers runs the extension consumer and value rules under the embedded registry.
// A nil active map selects the embedded registry; an explicit map describes the caller's
// implemented active versions without changing allocation or composability.
func ExtensionConsumers(root map[string]any, active map[string]map[int]bool) []validator.Finding {
	findings := ExtensionRules(root, active, nil)
	entries, problem := extensionEntries(root)
	if problem != "" {
		return findings
	}
	refs := map[string]string{}
	for _, entry := range registry.Entries("extensions") {
		refs[entry.ID] = entry.ValueSchema
	}
	for index, entry := range entries {
		identifier, isText := entry["id"].(string)
		version, isInteger := pyjson.SchemaInt(entry["version"])
		value, present := entry["value"]
		if !isText || !isInteger || !present || refs[identifier] == "" || !Interpretable(root, identifier, version, active, nil) {
			continue
		}
		if valid, err := schema.ECL().Valid(refs[identifier], value); err != nil || !valid {
			findings = append(findings, validator.Finding{RuleID: "ecl.rule.extension-value-valid.v1", Path: fmt.Sprintf("/extensions/%d/value", index), Detail: "value of " + identifier + " does not match its registered schema"})
		}
	}
	return findings
}

// ExtensionRules supplies allocation, version and critical-consumer checks to a configured consumer.
func ExtensionRules(root map[string]any, active map[string]map[int]bool, applicability ExtensionApplicability) []validator.Finding {
	ext := configuredExtensions(active, applicability)
	findings := []validator.Finding{}
	for _, check := range []func() ([]validator.Finding, string){
		func() ([]validator.Finding, string) { return extensionsUnique(root) },
		func() ([]validator.Finding, string) { return ExtensionVersions(root, ext.composable) },
		func() ([]validator.Finding, string) { return extensionNamespace(root, ext.known) },
		func() ([]validator.Finding, string) { return criticalExtensions(root, ext) },
	} {
		found, problem := check()
		if problem != "" {
			findings = append(findings, validator.Finding{RuleID: schemaInvalid, Path: "/", Detail: problem})
		} else {
			findings = append(findings, found...)
		}
	}
	return findings
}

// Common returns the findings that the reference's semantic validator reports for an object of
// no protocol it checks further, such as an ECL-IE-1 envelope or an ECL-WI-1 work intent: the
// extension rules XR1-009, XR1-010, XR1-017 and XR1-006 under the embedded registry, self-
// causation and integrity-policy consistency, in the reference's order. A check that cannot read
// the value it needs reports one schema-invalid finding instead of its own, as the reference does.
func Common(root map[string]any) []validator.Finding {
	return CommonFor(root, nil, nil)
}

// CommonFor applies the caller's implemented versions and object-type declarations.
func CommonFor(root map[string]any, active map[string]map[int]bool, applicability ExtensionApplicability) []validator.Finding {
	ext := configuredExtensions(active, applicability)
	findings := []validator.Finding{}
	guarded := func(name string, check func() ([]validator.Finding, string)) {
		found, problem := check()
		if problem != "" {
			findings = append(findings, validator.Finding{RuleID: schemaInvalid, Path: "/", Detail: name + " semantic check rejected malformed input: " + problem})
			return
		}
		findings = append(findings, found...)
	}
	guarded("extension uniqueness", func() ([]validator.Finding, string) { return extensionsUnique(root) })
	guarded("extension versions", func() ([]validator.Finding, string) { return ExtensionVersions(root, ext.composable) })
	guarded("extension namespace", func() ([]validator.Finding, string) { return extensionNamespace(root, ext.known) })
	guarded("critical extension", func() ([]validator.Finding, string) { return criticalExtensions(root, ext) })
	findings = append(findings, SelfCausation(root)...)
	guarded("integrity policy", func() ([]validator.Finding, string) { return IntegrityPolicy(root) })
	return findings
}

// Composable returns the extension identifiers whose versions the embedded registry declares
// composable (XR1-010).
func Composable() map[string]bool {
	return snapshot().composable
}

// InterpretedOccurrence selects only the embedded registry's active version on its object type.
// It does not validate the extension value or remove unknown data from the carrying object.
func InterpretedOccurrence(value, occurrence any) bool {
	root, isRoot := pyjson.Object(value)
	entry, isEntry := pyjson.Object(occurrence)
	if !isRoot || !isEntry {
		return false
	}
	identifier, isText := pyjson.Text(entry["id"])
	version, isInteger := pyjson.SchemaInt(entry["version"])
	return isText && isInteger && Interpretable(root, identifier, version, nil, nil)
}
