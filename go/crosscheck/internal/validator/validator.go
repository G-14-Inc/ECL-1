// Package validator implements the ECL-1 RC-3 semantics exercised by the
// frozen foundation-vector suite.
package validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/strictjson"
)

const (
	RuleAdapterBinding      = "ecl.rule.adapter-source-binding-valid.v1"
	RuleAdmitAuthority      = "ecl.rule.admit-requires-valid-authority.v1"
	RuleNonAdmitAuthority   = "ecl.rule.non-admit-prohibits-authority.v1"
	RuleExtensionUnique     = "ecl.rule.extension-identifiers-unique.v1"
	RuleIntegrityThreshold  = "ecl.rule.integrity-threshold-consistent.v1"
	RuleExpiryAfterIssue    = "ecl.rule.expiry-after-issue.v1"
	RuleNoSelfCausation     = "ecl.rule.message-cannot-cause-itself.v1"
	RuleUnknownCritical     = "ecl.rule.unknown-critical-extension-rejected.v1"
	RuleBundleAcyclic       = "ecl.rule.bundle-causal-graph-acyclic.v1"
	RuleBundleSequence      = "ecl.rule.bundle-causal-sequence-monotonic.v1"
	RuleBundleObjectUnique  = "ecl.rule.bundle-object-identifiers-unique.v1"
	RulePredecessorDigest   = "ecl.rule.bundle-predecessor-digest-valid.v1"
	RuleLifecycleDerivative = "ecl.rule.lifecycle-derived-artifact-required.v1"
	RuleExecutionTransition = "ecl.rule.execution-state-transition-valid.v1"
	RuleTerminalState       = "ecl.rule.terminal-execution-state-consistent.v1"
	RuleArtifactRecognized  = "ecl.rule.artifact-shape-recognized.v1"
)

// Finding is a deterministic semantic or strict-input rejection.
type Finding struct {
	RuleID string
	Path   string
	Detail string
}

// Options supplies frozen registry state without embedding implementation
// behavior from the candidate's reference package.
type Options struct {
	KnownExtensions map[string]map[int]bool
}

// Validate derives findings from exact artifact bytes. It never receives a
// manifest expectation or expected rule identifier.
func Validate(data []byte, options Options) ([]Finding, error) {
	value, err := strictjson.Parse(data)
	if err != nil {
		var strictErr *strictjson.Error
		if errors.As(err, &strictErr) {
			return []Finding{{
				RuleID: strictErr.RuleID,
				Path:   strictErr.Path,
				Detail: strictErr.Reason,
			}}, nil
		}
		return nil, err
	}
	root, ok := object(value)
	if !ok {
		return []Finding{finding(RuleArtifactRecognized, "/", "artifact root is not an object")}, nil
	}

	// A DCMP-2 or EBMP-2 object is classified by its protocol before the bare-bundle shape: an
	// EBMP-2 bundle manifest also has a records member, which holds references, not records.
	switch {
	case text(root["schema_version"]) == "ecl_adapter_binding_v1":
		return validateAdapter(root)
	case text(root["protocol"]) == "DCMP-2":
		return validateDCMP(root, options), nil
	case text(root["protocol"]) == "EBMP-2":
		return validateRecord(root, options), nil
	case root["records"] != nil:
		return validateBundle(root, options)
	default:
		return []Finding{finding(
			RuleArtifactRecognized,
			"/",
			"artifact is not a recognized RC-3 adapter, DCMP-2, EBMP-2, or bundle object",
		)}, nil
	}
}

func validateAdapter(root map[string]any) ([]Finding, error) {
	fail := func(path, detail string) ([]Finding, error) {
		return []Finding{finding(RuleAdapterBinding, path, detail)}, nil
	}
	digest, ok := object(root["binding_digest"])
	if !ok ||
		text(digest["algorithm"]) != "ecl.digest.sha-256.v1" ||
		len(text(digest["value"])) != 64 {
		return fail("/binding_digest", "binding digest is absent or malformed")
	}
	body := make(map[string]any, len(root)-1)
	for key, value := range root {
		if key != "binding_digest" {
			body[key] = value
		}
	}
	computed, err := canonical.Digest(body)
	if err != nil {
		return nil, fmt.Errorf("canonicalize adapter body: %w", err)
	}
	if computed != text(digest["value"]) {
		return fail("/binding_digest/value", "binding-body digest does not match canonical content")
	}

	boundary, ok := object(root["authority_boundary"])
	if !ok ||
		boundary["native_authoritative_for_effects"] != true ||
		boundary["ecl_is_portable_evidence_only"] != true ||
		boundary["inbound_requires_native_reevaluation"] != true ||
		text(boundary["conflict_disposition"]) != "fail_closed_no_release" {
		return fail("/authority_boundary", "native authority boundary is incomplete or weakened")
	}
	source, ok := object(root["source"])
	if !ok || source["retained"] != true {
		return fail("/source", "native source retention is not explicit")
	}

	derivedIDs := map[string]bool{}
	derived, ok := array(root["ecl_objects"])
	if !ok || len(derived) == 0 {
		return fail("/ecl_objects", "no derived ECL object is declared")
	}
	for index, item := range derived {
		entry, ok := object(item)
		if !ok || text(entry["object_id"]) == "" {
			return fail(fmt.Sprintf("/ecl_objects/%d", index), "derived object identity is missing")
		}
		derivedIDs[text(entry["object_id"])] = true
	}

	accounting, ok := array(root["field_accounting"])
	if !ok || len(accounting) == 0 {
		return fail("/field_accounting", "source field accounting is empty")
	}
	for index, item := range accounting {
		entry, ok := object(item)
		if !ok {
			return fail(fmt.Sprintf("/field_accounting/%d", index), "field accounting entry is not an object")
		}
		targets, _ := array(entry["target_paths"])
		switch text(entry["disposition"]) {
		case "mapped":
			if len(targets) == 0 {
				return fail(fmt.Sprintf("/field_accounting/%d/target_paths", index), "mapped source field has no target")
			}
		case "retained_source_only", "rejected":
			if len(targets) != 0 {
				return fail(fmt.Sprintf("/field_accounting/%d/target_paths", index), "unmapped source field declares a target")
			}
		default:
			return fail(fmt.Sprintf("/field_accounting/%d/disposition", index), "field disposition is unknown")
		}
		if text(root["loss_class"]) == "lossless" && text(entry["disposition"]) != "mapped" {
			return fail("/loss_class", "lossless binding contains an unmapped source field")
		}
	}

	coverage, ok := object(root["responsibility_coverage"])
	if !ok {
		return fail("/responsibility_coverage", "six-responsibility coverage is absent")
	}
	for _, responsibility := range []string{
		"Decision", "Authority", "Enforcement", "Provenance", "Verification", "Fleet",
	} {
		entry, ok := object(coverage[responsibility])
		if !ok {
			return fail("/responsibility_coverage/"+responsibility, "responsibility disposition is absent")
		}
		ids, _ := array(entry["object_ids"])
		if text(entry["status"]) == "represented" && len(ids) == 0 {
			return fail("/responsibility_coverage/"+responsibility, "represented responsibility has no object")
		}
		if text(entry["status"]) != "represented" && len(ids) != 0 {
			return fail("/responsibility_coverage/"+responsibility, "non-represented responsibility names an object")
		}
		for _, id := range ids {
			if !derivedIDs[text(id)] {
				return fail("/responsibility_coverage/"+responsibility, "responsibility references an undeclared ECL object")
			}
		}
	}
	return nil, nil
}

func validateDCMP(root map[string]any, options Options) []Finding {
	findings := make([]Finding, 0)
	outcome := text(root["outcome"])
	authorization, hasAuthorization := object(root["authorization"])
	if outcome == "admit" {
		if !hasAuthorization ||
			text(authorization["authorization_id"]) == "" ||
			text(authorization["audience"]) == "" ||
			text(authorization["use_policy"]) == "" {
			findings = append(findings, finding(
				RuleAdmitAuthority,
				"/authorization",
				"admit response does not carry exact release authority",
			))
		}
	}
	switch outcome {
	case "deny", "hold", "challenge", "expired", "revoked", "cancelled", "superseded":
		if hasAuthorization {
			findings = append(findings, finding(
				RuleNonAdmitAuthority,
				"/authorization",
				"non-admit outcome carries executable authority",
			))
		}
	}

	if issued, issuedOK := timestamp(root["issued_at"]); issuedOK {
		if expires, expiresOK := timestamp(root["expires_at"]); expiresOK && !expires.After(issued) {
			findings = append(findings, finding(
				RuleExpiryAfterIssue,
				"/expires_at",
				"expiry is not strictly later than issue time",
			))
		}
	}
	if hasAuthorization {
		if start, startOK := timestamp(authorization["valid_from"]); startOK {
			if end, endOK := timestamp(authorization["valid_until"]); endOK && !end.After(start) {
				findings = append(findings, finding(
					RuleExpiryAfterIssue,
					"/authorization/valid_until",
					"authorization end is not strictly later than start",
				))
			}
		}
	}

	messageID := text(root["message_id"])
	if workflow, ok := object(root["workflow"]); ok {
		if predecessors, ok := array(workflow["causal_predecessors"]); ok {
			for index, item := range predecessors {
				predecessor, _ := object(item)
				if text(predecessor["id"]) == messageID && messageID != "" {
					findings = append(findings, finding(
						RuleNoSelfCausation,
						fmt.Sprintf("/workflow/causal_predecessors/%d/id", index),
						"message names itself as a causal predecessor",
					))
				}
			}
		}
	}
	findings = append(findings, validateExtensions(root, options)...)
	findings = append(findings, validateIntegrity(root)...)
	return unique(findings)
}

func validateRecord(root map[string]any, options Options) []Finding {
	findings := make([]Finding, 0)
	event, _ := object(root["event"])
	if text(root["event_type"]) == "execution_terminal" {
		state := text(event["state"])
		if !terminalState(state) {
			findings = append(findings, finding(
				RuleTerminalState,
				"/event/state",
				"execution_terminal uses a non-terminal execution state",
			))
		}
		if state == "partially_succeeded" ||
			state == "timed_out" ||
			state == "cancelled" ||
			state == "unknown" {
			if _, sideEffects := array(event["side_effects"]); !sideEffects ||
				text(event["residual_state"]) == "" {
				findings = append(findings, finding(
					RuleTerminalState,
					"/event",
					"bounded terminal state omits side-effect or residual-state evidence",
				))
			}
		}
	}
	if text(root["event_type"]) == "lifecycle_transition" {
		operation := text(event["operation"])
		if (operation == "redact" || operation == "supersede") && event["derived_artifact"] == nil {
			findings = append(findings, finding(
				RuleLifecycleDerivative,
				"/event/derived_artifact",
				"lifecycle operation omits the required derived artifact",
			))
		}
	}
	objectID := text(root["object_id"])
	if workflow, ok := object(root["workflow"]); ok {
		if predecessors, ok := array(workflow["causal_predecessors"]); ok {
			for index, item := range predecessors {
				predecessor, _ := object(item)
				if objectID != "" && text(predecessor["id"]) == objectID {
					findings = append(findings, finding(
						RuleNoSelfCausation,
						fmt.Sprintf("/workflow/causal_predecessors/%d/id", index),
						"event names itself as a causal predecessor",
					))
				}
			}
		}
	}
	findings = append(findings, validateExtensions(root, options)...)
	findings = append(findings, validateIntegrity(root)...)
	return unique(findings)
}

func validateBundle(root map[string]any, options Options) ([]Finding, error) {
	rawRecords, ok := array(root["records"])
	if !ok || len(rawRecords) == 0 {
		return []Finding{finding(RuleArtifactRecognized, "/records", "bundle has no records")}, nil
	}
	records := make([]map[string]any, 0, len(rawRecords))
	byID := make(map[string]map[string]any, len(rawRecords))
	for index, item := range rawRecords {
		record, ok := object(item)
		if !ok {
			return []Finding{finding(
				RuleArtifactRecognized,
				fmt.Sprintf("/records/%d", index),
				"bundle record is not an object",
			)}, nil
		}
		id := text(record["object_id"])
		if id == "" {
			return []Finding{finding(
				RuleArtifactRecognized,
				fmt.Sprintf("/records/%d/object_id", index),
				"bundle record identity is absent",
			)}, nil
		}
		if _, exists := byID[id]; exists {
			return []Finding{finding(
				RuleBundleObjectUnique,
				fmt.Sprintf("/records/%d/object_id", index),
				"bundle repeats an immutable object identity",
			)}, nil
		}
		records = append(records, record)
		byID[id] = record
	}

	graph := make(map[string][]string, len(records))
	for _, record := range records {
		id := text(record["object_id"])
		graph[id] = nil
		workflow, _ := object(record["workflow"])
		predecessors, _ := array(workflow["causal_predecessors"])
		for _, item := range predecessors {
			predecessor, _ := object(item)
			predecessorID := text(predecessor["id"])
			if _, local := byID[predecessorID]; local {
				graph[id] = append(graph[id], predecessorID)
			}
		}
	}
	if graphHasCycle(graph) {
		return []Finding{finding(
			RuleBundleAcyclic,
			"/records",
			"local causal graph contains a cycle",
		)}, nil
	}

	for recordIndex, record := range records {
		workflow, _ := object(record["workflow"])
		predecessors, _ := array(workflow["causal_predecessors"])
		for predecessorIndex, item := range predecessors {
			predecessor, _ := object(item)
			local, exists := byID[text(predecessor["id"])]
			if !exists {
				continue
			}
			digest, _ := object(predecessor["digest"])
			computed, err := canonical.Digest(local)
			if err != nil {
				return nil, fmt.Errorf("canonicalize bundle predecessor: %w", err)
			}
			if text(digest["algorithm"]) != "ecl.digest.sha-256.v1" ||
				text(digest["value"]) != computed {
				return []Finding{finding(
					RulePredecessorDigest,
					fmt.Sprintf(
						"/records/%d/workflow/causal_predecessors/%d/digest",
						recordIndex,
						predecessorIndex,
					),
					"local predecessor digest does not match canonical record content",
				)}, nil
			}
		}
	}

	for recordIndex, record := range records {
		workflow, _ := object(record["workflow"])
		successorSequence, successorOK := integer(workflow["sequence"])
		predecessors, _ := array(workflow["causal_predecessors"])
		for predecessorIndex, item := range predecessors {
			predecessor, _ := object(item)
			local, exists := byID[text(predecessor["id"])]
			if !exists {
				continue
			}
			localWorkflow, _ := object(local["workflow"])
			if !sameSequenceDomain(workflow, localWorkflow) {
				continue
			}
			predecessorSequence, predecessorOK := integer(localWorkflow["sequence"])
			if successorOK && predecessorOK && predecessorSequence >= successorSequence {
				return []Finding{finding(
					RuleBundleSequence,
					fmt.Sprintf(
						"/records/%d/workflow/causal_predecessors/%d",
						recordIndex,
						predecessorIndex,
					),
					"causal predecessor sequence is not lower than successor sequence",
				)}, nil
			}
		}
	}

	if path, revived := terminalRevival(records); revived {
		return []Finding{finding(
			RuleExecutionTransition,
			path,
			"execution attempt returns to a non-terminal state after a terminal outcome",
		)}, nil
	}
	for _, record := range records {
		if findings := validateRecord(record, options); len(findings) > 0 {
			return findings, nil
		}
	}
	return nil, nil
}

func validateExtensions(root map[string]any, options Options) []Finding {
	extensions, ok := array(root["extensions"])
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for index, item := range extensions {
		extension, _ := object(item)
		id := text(extension["id"])
		version, versionOK := integer(extension["version"])
		key := id + "\x00" + strconv.FormatInt(version, 10)
		if seen[key] {
			return []Finding{finding(
				RuleExtensionUnique,
				fmt.Sprintf("/extensions/%d", index),
				"extension identifier and version pair is duplicated",
			)}
		}
		seen[key] = true
		if extension["critical"] == true &&
			(!versionOK || !options.KnownExtensions[id][int(version)]) {
			return []Finding{finding(
				RuleUnknownCritical,
				fmt.Sprintf("/extensions/%d", index),
				"critical extension is not active in the frozen registry",
			)}
		}
	}
	return nil
}

func validateIntegrity(root map[string]any) []Finding {
	policy, ok := object(root["integrity_policy"])
	if !ok {
		return nil
	}
	required, _ := policy["required"].(bool)
	threshold, thresholdOK := integer(policy["threshold"])
	requiredKeys, _ := array(policy["required_key_ids"])
	acceptedSuites, _ := array(policy["accepted_suites"])
	eligibleKeys, _ := array(policy["eligible_key_ids"])
	invalid := !thresholdOK ||
		(required && threshold < 1) ||
		(!required && threshold != 0) ||
		threshold < int64(len(requiredKeys)) ||
		(required && len(acceptedSuites) == 0)
	if !invalid {
		eligible := map[string]bool{}
		for _, item := range eligibleKeys {
			eligible[text(item)] = true
		}
		for _, item := range requiredKeys {
			if !eligible[text(item)] {
				invalid = true
				break
			}
		}
	}
	if !invalid {
		return nil
	}
	return []Finding{finding(
		RuleIntegrityThreshold,
		"/integrity_policy",
		"required flag, threshold, suites, or mandatory signer set is inconsistent",
	)}
}

func terminalRevival(records []map[string]any) (string, bool) {
	type stateObservation struct {
		recordIndex int
		sequence    int64
		state       string
	}
	attempts := map[string][]stateObservation{}
	for index, record := range records {
		event, _ := object(record["event"])
		if text(event["kind"]) != "execution" {
			continue
		}
		attemptID := text(event["attempt_id"])
		workflow, _ := object(record["workflow"])
		sequence, ok := integer(workflow["sequence"])
		if attemptID == "" || !ok {
			continue
		}
		attempts[attemptID] = append(attempts[attemptID], stateObservation{
			recordIndex: index,
			sequence:    sequence,
			state:       text(event["state"]),
		})
	}
	for _, observations := range attempts {
		sort.SliceStable(observations, func(i, j int) bool {
			return observations[i].sequence < observations[j].sequence
		})
		terminalSeen := false
		for _, observation := range observations {
			if terminalSeen && !terminalState(observation.state) {
				return fmt.Sprintf("/records/%d/event/state", observation.recordIndex), true
			}
			if terminalState(observation.state) {
				terminalSeen = true
			}
		}
	}
	return "", false
}

func terminalState(state string) bool {
	switch state {
	case "succeeded", "failed", "partially_succeeded", "timed_out", "cancelled",
		"rolled_back", "compensated", "unknown",
		// The non-release terminal states that EBMP-2 added in RC-4.
		"denied", "held", "challenged", "expired_before_release":
		return true
	default:
		return false
	}
}

func graphHasCycle(graph map[string][]string) bool {
	const (
		unseen   = 0
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var visit func(string) bool
	visit = func(node string) bool {
		switch state[node] {
		case visiting:
			return true
		case done:
			return false
		}
		state[node] = visiting
		for _, next := range graph[node] {
			if visit(next) {
				return true
			}
		}
		state[node] = done
		return false
	}
	for node := range graph {
		if state[node] == unseen && visit(node) {
			return true
		}
	}
	return false
}

func sameSequenceDomain(left, right map[string]any) bool {
	return text(left["workflow_id"]) == text(right["workflow_id"]) &&
		text(left["root_trace_id"]) == text(right["root_trace_id"]) &&
		text(left["workflow_id"]) != ""
}

func unique(findings []Finding) []Finding {
	seen := map[string]bool{}
	output := make([]Finding, 0, len(findings))
	for _, current := range findings {
		if seen[current.RuleID] {
			continue
		}
		seen[current.RuleID] = true
		output = append(output, current)
	}
	return output
}

func finding(rule, path, detail string) Finding {
	return Finding{RuleID: rule, Path: path, Detail: detail}
}

func object(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func array(value any) ([]any, bool) {
	result, ok := value.([]any)
	return result, ok
}

func text(value any) string {
	result, _ := value.(string)
	return result
}

func integer(value any) (int64, bool) {
	switch current := value.(type) {
	case json.Number:
		result, err := strconv.ParseInt(current.String(), 10, 64)
		return result, err == nil
	case int:
		return int64(current), true
	case int64:
		return current, true
	default:
		return 0, false
	}
}

func timestamp(value any) (time.Time, bool) {
	raw := text(value)
	if raw == "" || !strings.HasSuffix(raw, "Z") {
		return time.Time{}, false
	}
	result, err := time.Parse(time.RFC3339Nano, raw)
	return result, err == nil
}
