package validatorx

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
)

// The rule of a native adapter binding (EBMP2-069), written from that requirement. The imported
// core checks other conditions of the same rule and stops at the first failure, so its findings
// give way to these.
var (
	adapterResponsibilities = []string{"Decision", "Authority", "Enforcement", "Provenance", "Verification", "Fleet"}
	adapterMediaTypes       = map[string]string{
		"DCMP-2": "application/vnd.ecl.dcmp+json",
		"EBMP-2": "application/vnd.ecl.ebmp+json",
	}
	adapterAuthorityBoundary = map[string]any{
		"native_authoritative_for_effects":     true,
		"ecl_is_portable_evidence_only":        true,
		"inbound_requires_native_reevaluation": true,
		"conflict_disposition":                 "fail_closed_no_release",
	}
	arrayIndex = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
)

const adapterBindingPrefix = "https://externalcontrollayer.ai/ns/adapter-binding/sha256/"

// objectEntries returns the entries of an array member when every entry is an object.
func objectEntries(root map[string]any, member string) ([]map[string]any, bool) {
	list, isArray := root[member].([]any)
	if !isArray {
		return nil, false
	}
	entries := make([]map[string]any, 0, len(list))
	for _, item := range list {
		entry, isObject := item.(map[string]any)
		if !isObject {
			return nil, false
		}
		entries = append(entries, entry)
	}
	return entries, true
}

// entryStrings returns one member of every entry when each is a string.
func entryStrings(entries []map[string]any, ok bool, member string) ([]string, bool) {
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		text, isText := entry[member].(string)
		if !isText {
			return nil, false
		}
		values = append(values, text)
	}
	return values, true
}

// stringList returns value as an array of strings.
func stringList(value any) ([]string, bool) {
	list, isArray := value.([]any)
	if !isArray {
		return nil, false
	}
	values := make([]string, 0, len(list))
	for _, item := range list {
		text, isText := item.(string)
		if !isText {
			return nil, false
		}
		values = append(values, text)
	}
	return values, true
}

// entryStringLists returns one member of every entry when each is an array of strings.
func entryStringLists(entries []map[string]any, ok bool, member string) ([][]string, bool) {
	if !ok {
		return nil, false
	}
	values := make([][]string, 0, len(entries))
	for _, entry := range entries {
		list, isList := stringList(entry[member])
		if !isList {
			return nil, false
		}
		values = append(values, list)
	}
	return values, true
}

// namesDerivedObject reports whether a JSON Pointer's first reference token is an array index
// (RFC 6901, section 4) less than count.
func namesDerivedObject(pointer string, count int) bool {
	if !strings.HasPrefix(pointer, "/") {
		return false
	}
	token := strings.Split(pointer, "/")[1]
	if !arrayIndex.MatchString(token) || len(token) > len(strconv.Itoa(count)) {
		return false
	}
	index, err := strconv.Atoi(token)
	return err == nil && index < count
}

func distinct(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// AdapterBinding returns the findings of ecl.rule.adapter-source-binding-valid.v1 for a native
// adapter binding: one for each condition of EBMP2-069 that fails. On a schema-invalid binding
// each condition is checked only when every member it names is present with the JSON type that
// the schema requires (DCMP2-043).
func AdapterBinding(root map[string]any) []validator.Finding {
	var findings []validator.Finding
	fail := func(path, detail string) {
		findings = append(findings, validator.Finding{RuleID: validator.RuleAdapterBinding, Path: path, Detail: detail})
	}
	objects, objectsOK := objectEntries(root, "ecl_objects")
	objectIDs, objectIDsOK := entryStrings(objects, objectsOK, "object_id")
	accounting, accountingOK := objectEntries(root, "field_accounting")

	// 1. The digest of the binding without binding_digest.
	if supplied, isObject := root["binding_digest"].(map[string]any); isObject {
		body := make(map[string]any, len(root))
		for key, value := range root {
			if key != "binding_digest" {
				body[key] = value
			}
		}
		if computed, err := canonical.Digest(body); err != nil {
			fail("/binding_digest", fmt.Sprintf("binding body is outside the restricted canonical profile: %v", err))
		} else if !pyjson.Equal(supplied, map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": computed}) {
			fail("/binding_digest", "binding body digest does not match the canonical binding body")
		}
	}

	// 2. The binding identity binds the source and the derived-object list.
	source, sourceOK := root["source"].(map[string]any)
	bindingID, bindingIDOK := root["binding_id"].(string)
	if sourceOK && bindingIDOK && objectIDsOK {
		system, systemOK := source["system"].(string)
		contract, contractOK := source["contract"].(string)
		objectID, objectIDOK := source["object_id"].(string)
		digestValue, digestOK := pyjson.Get(source["object_digest"], "value").(string)
		if systemOK && contractOK && objectIDOK && digestOK {
			identifiers := make([]any, 0, len(objectIDs))
			for _, identifier := range objectIDs {
				identifiers = append(identifiers, identifier)
			}
			seed := map[string]any{"system": system, "contract": contract, "object_id": objectID, "object_digest": digestValue, "ecl_object_ids": identifiers}
			computed, err := canonical.Digest(seed)
			if err != nil || bindingID != adapterBindingPrefix+computed {
				fail("/binding_id", "binding identity does not bind the source and derived-object set")
			}
		}
	}

	// 3. Distinct derived objects.
	if objectIDsOK && !distinct(objectIDs) {
		fail("/ecl_objects", "derived ECL object identifiers are not unique")
	}

	// 4. The media type that each derived object's protocol names.
	protocols, protocolsOK := entryStrings(objects, objectsOK, "protocol")
	mediaTypes, mediaTypesOK := entryStrings(objects, objectsOK, "media_type")
	if protocolsOK && mediaTypesOK {
		for index, protocol := range protocols {
			expected, known := adapterMediaTypes[protocol]
			if !known || expected != mediaTypes[index] {
				fail(fmt.Sprintf("/ecl_objects/%d/media_type", index), "derived-object protocol and media type disagree")
			}
		}
	}

	// 5. Each source field is accounted once.
	if sourcePaths, ok := entryStrings(accounting, accountingOK, "source_path"); ok && !distinct(sourcePaths) {
		fail("/field_accounting", "a source field is accounted more than once")
	}

	// 6. The loss class follows from the dispositions.
	dispositions, dispositionsOK := entryStrings(accounting, accountingOK, "disposition")
	if lossClass, isText := root["loss_class"].(string); dispositionsOK && isText {
		expected := "lossless"
		if contains(dispositions, "rejected") {
			expected = "rejected"
		} else if contains(dispositions, "retained_source_only") {
			expected = "loss_accounted"
		}
		if lossClass != expected {
			fail("/loss_class", "loss class does not match per-field accounting")
		}
	}

	// 7. Every target path begins with the index of a derived object.
	targetLists, targetsOK := entryStringLists(accounting, accountingOK, "target_paths")
	derived, derivedOK := objectEntries(root, "derived_fields")
	derivedTargets, derivedTargetsOK := entryStrings(derived, derivedOK, "target_path")
	if objectsOK && targetsOK && derivedTargetsOK {
		for index, targets := range targetLists {
			for _, target := range targets {
				if !namesDerivedObject(target, len(objects)) {
					fail(fmt.Sprintf("/field_accounting/%d", index), "target path does not name a bound derived-object index")
					break
				}
			}
		}
		for index, target := range derivedTargets {
			if !namesDerivedObject(target, len(objects)) {
				fail(fmt.Sprintf("/derived_fields/%d", index), "target path does not name a bound derived-object index")
			}
		}
	}

	// 8. Each responsibility's coverage names exactly the derived objects that list it.
	listed, listedOK := entryStringLists(objects, objectsOK, "responsibilities")
	coverage, coverageOK := root["responsibility_coverage"].(map[string]any)
	type disposition struct {
		status string
		ids    []string
	}
	dispositionsByResponsibility := map[string]disposition{}
	for _, responsibility := range adapterResponsibilities {
		entry, isObject := coverage[responsibility].(map[string]any)
		status, statusOK := entry["status"].(string)
		ids, idsOK := stringList(entry["object_ids"])
		if !isObject || !statusOK || !idsOK {
			coverageOK = false
			break
		}
		dispositionsByResponsibility[responsibility] = disposition{status, ids}
	}
	if objectIDsOK && listedOK && coverageOK {
		for _, responsibility := range adapterResponsibilities {
			var expected []string
			for index, identifier := range objectIDs {
				if contains(listed[index], responsibility) {
					expected = append(expected, identifier)
				}
			}
			entry := dispositionsByResponsibility[responsibility]
			if (entry.status == "represented") != (len(expected) > 0) || !sameStrings(entry.ids, expected) {
				fail("/responsibility_coverage/"+responsibility, "responsibility coverage disagrees with derived-object metadata")
			}
		}
	}

	// 9. The fail-closed authority boundary, the one value the schema allows, compared as the same
	// JSON value, as the reference's same_json compares it: 1 is not true. The boundary
	// holds booleans and a string, which SchemaEqual compares exactly.
	if boundary, isObject := root["authority_boundary"].(map[string]any); isObject && !pyjson.SchemaEqual(boundary, adapterAuthorityBoundary) {
		fail("/authority_boundary", "adapter authority boundary is not the exact fail-closed boundary")
	}
	return findings
}
