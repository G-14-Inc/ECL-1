package validatorx

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
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
}

var snapshot = sync.OnceValue(func() extensionRegistry {
	found := extensionRegistry{known: map[string]bool{}, active: map[string]map[int64]bool{}, composable: registry.ComposableExtensions()}
	for _, entry := range registry.Entries("extensions") {
		found.known[entry.ID] = true
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

// Allocated reports whether the embedded registry holds an identifier under any status (XR1-017).
func Allocated(identifier string) bool {
	return snapshot().known[identifier]
}

// extensionEntries returns the extensions member of root as the reference's extension checks
// read it: absent or null is no extension, and a member that is not an array of objects is
// malformed (the reference's check raises and reports the input as schema-invalid).
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
		entry, isObject := item.(map[string]any)
		if !isObject {
			return nil, malformedEntriesError
		}
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
		version, isInteger := pyjson.Int(entry["version"])
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

// extensionsUnique is XR1-009: one object carries each pair of identifier and version once. A
// version may be a boolean, as Python's isinstance(x, int) admits, and true is the version 1.
func extensionsUnique(root map[string]any) ([]validator.Finding, string) {
	entries, problem := extensionEntries(root)
	if problem != "" {
		return nil, problem
	}
	findings := []validator.Finding{}
	seen := map[string]bool{}
	for index, entry := range entries {
		identifier, isText := entry["id"].(string)
		version, isInteger := pyjson.PythonInt(entry["version"])
		if !isText || !isInteger {
			return nil, "extension id and version have invalid types"
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
		if isText && strings.HasPrefix(identifier, "ecl.") && !known[identifier] {
			findings = append(findings, validator.Finding{
				RuleID: RuleExtensionNamespace,
				Path:   fmt.Sprintf("/extensions/%d/id", index),
				Detail: "unallocated ECL extension identifier " + identifier,
			})
		}
	}
	return findings, ""
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
		if !pyjson.Truthy(entry["critical"]) {
			continue
		}
		identifier, isText := entry["id"].(string)
		version, isInteger := pyjson.Int(entry["version"])
		if !isText || !isInteger || !ext.active[identifier][version] {
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
// IntegrityPolicy returns the finding of the threshold rule (IE1-013) for one object: a threshold
// that is not an integer, below one when integrity is required, not zero when it is optional, or
// below the number of mandatory signers, or a mandatory signer outside a listed set of eligible
// keys. These are the rule's only conditions. The second result is the reason the key lists
// cannot be read, or "".
func IntegrityPolicy(root map[string]any) ([]validator.Finding, string) {
	policy, isObject := root["integrity_policy"].(map[string]any)
	if !isObject {
		return nil, ""
	}
	required := pyjson.Truthy(policy["required"])
	keyList := func(name string) ([]any, bool) {
		value := policy[name]
		if !pyjson.Truthy(value) {
			return []any{}, true
		}
		list, isList := value.([]any)
		return list, isList
	}
	requiredKeys, requiredOK := keyList("required_key_ids")
	eligibleKeys, eligibleOK := keyList("eligible_key_ids")
	if !requiredOK || !eligibleOK {
		return nil, "integrity key identifiers must be arrays"
	}
	threshold, isInteger := pyjson.Int(policy["threshold"])
	invalid := !isInteger ||
		(required && threshold < 1) ||
		(!required && threshold != 0) ||
		threshold < int64(len(requiredKeys))
	if !invalid && len(eligibleKeys) > 0 {
		// set(required).issubset(eligible): Python hashes the members of both lists.
		for _, item := range append(append([]any{}, requiredKeys...), eligibleKeys...) {
			if !hashable(item) {
				return nil, "unhashable type in an integrity key list"
			}
		}
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

// Common returns the findings that the reference's semantic validator reports for an object of
// no protocol it checks further, such as an ECL-IE-1 envelope or an ECL-WI-1 work intent: the
// extension rules XR1-009, XR1-010, XR1-017 and XR1-006 under the embedded registry, self-
// causation and integrity-policy consistency, in the reference's order. A check that cannot read
// the value it needs reports one schema-invalid finding instead of its own, as the reference does.
func Common(root map[string]any) []validator.Finding {
	ext := snapshot()
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
	guarded("self-causation", func() ([]validator.Finding, string) { return selfCausation(root) })
	guarded("integrity policy", func() ([]validator.Finding, string) { return IntegrityPolicy(root) })
	return findings
}

// Composable returns the extension identifiers whose versions the embedded registry declares
// composable (XR1-010).
func Composable() map[string]bool {
	return snapshot().composable
}
