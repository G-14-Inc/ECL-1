package evidence

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
)

// TerminalStates are the execution states after which an attempt is closed.
var TerminalStates = map[string]bool{
	"succeeded": true, "failed": true, "partially_succeeded": true, "cancelled": true,
	"timed_out": true, "rolled_back": true, "compensated": true, "unknown": true, "denied": true,
	"held": true, "challenged": true, "expired_before_release": true,
}

var allowedTransitions = map[string]map[string]bool{
	"not_started": {"prepared": true, "denied": true, "held": true, "challenged": true, "expired_before_release": true},
	"prepared":    {"released": true, "cancelled": true, "timed_out": true, "denied": true, "held": true, "expired_before_release": true},
	"released":    {"running": true, "succeeded": true, "failed": true, "partially_succeeded": true, "cancelled": true, "timed_out": true, "unknown": true},
	"running":     {"succeeded": true, "failed": true, "partially_succeeded": true, "cancelled": true, "timed_out": true, "rolled_back": true, "compensated": true, "unknown": true},
}

// Limits of the causal analysis.
const (
	MaxRecords      = 1_000_000
	MaxPredecessors = 128
)

const (
	schemaInvalid = "ecl.error.schema-invalid.v1"
	// resourceLimitExceeded is the error of a declared limit of the analysis (IE1-028, EBMP2-062).
	resourceLimitExceeded = "ecl.error.resource-limit-exceeded.v1"
)

// Finding is a rule that records break: the registered identifier, where, and why.
type Finding struct {
	RuleID string
	Path   string
	Detail string
}

// Analysis is the causal closure and execution-state analysis of EBMP-2 records.
type Analysis struct {
	// Status is complete, incomplete (a predecessor is missing or an attempt has no terminal
	// state) or indeterminate (a rule fails).
	Status                   string
	TerminalActionIDs        []string
	OpenActionIDs            []string
	UnresolvedPredecessorIDs []string
	Findings                 []Finding
}

func sequenceOf(record map[string]any, path string, findings *[]Finding) int64 {
	workflow, ok := pyjson.Object(record["workflow"])
	if !ok {
		*findings = append(*findings, Finding{schemaInvalid, path + "/workflow", "workflow must be an object"})
		return 0
	}
	value, ok := pyjson.Int(workflow["sequence"])
	if !ok || value < 0 {
		*findings = append(*findings, Finding{schemaInvalid, path + "/workflow/sequence", "workflow sequence must be a non-negative integer"})
		return 0
	}
	return value
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func lessTuple(left, right []string) bool {
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return len(left) < len(right)
}

func cycleFindings(edges map[string]map[string]bool) []Finding {
	var findings []Finding
	state := map[string]int{}
	reported := map[string]bool{}
	starts := make([]string, 0, len(edges))
	for node := range edges {
		starts = append(starts, node)
	}
	sort.Strings(starts)
	type frame struct {
		node         string
		predecessors []string
		next         int
	}
	for _, start := range starts {
		if state[start] != 0 {
			continue
		}
		state[start] = 1
		path := []string{start}
		positions := map[string]int{start: 0}
		stack := []*frame{{start, sortedKeys(edges[start]), 0}}
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if top.next >= len(top.predecessors) {
				stack = stack[:len(stack)-1]
				state[top.node] = 2
				delete(positions, top.node)
				path = path[:len(path)-1]
				continue
			}
			predecessor := top.predecessors[top.next]
			top.next++
			if _, known := edges[predecessor]; !known {
				continue
			}
			switch state[predecessor] {
			case 0:
				state[predecessor] = 1
				positions[predecessor] = len(path)
				path = append(path, predecessor)
				stack = append(stack, &frame{predecessor, sortedKeys(edges[predecessor]), 0})
				continue
			case 2:
				continue
			}
			cycle := append(append([]string{}, path[positions[predecessor]:]...), predecessor)
			var canonical []string
			for index := 0; index < len(cycle)-1; index++ {
				rotated := append(append(append([]string{}, cycle[index:len(cycle)-1]...), cycle[:index]...), cycle[index])
				if canonical == nil || lessTuple(rotated, canonical) {
					canonical = rotated
				}
			}
			key, _ := json.Marshal(canonical)
			if reported[string(key)] {
				continue
			}
			reported[string(key)] = true
			display := cycle
			if len(cycle) > 18 {
				display = append(append(append([]string{}, cycle[:8]...), "..."), cycle[len(cycle)-8:]...)
			}
			findings = append(findings, Finding{"ecl.rule.bundle-causal-graph-acyclic.v1", "/workflow/causal_predecessors", "causal cycle: " + strings.Join(display, " -> ")})
		}
	}
	return findings
}

type group struct {
	actionID  string
	attemptID string
	records   []map[string]any
}

func executionGroups(records []map[string]any, findings *[]Finding) []*group {
	grouped := map[string]*group{}
	var order []string
	for index, record := range records {
		event := record["event"]
		if !pyjson.Truthy(event) {
			event = map[string]any{}
		}
		if _, ok := pyjson.Object(event); !ok {
			*findings = append(*findings, Finding{schemaInvalid, "/records/" + strconv.Itoa(index) + "/event", "event must be an object"})
			continue
		}
		if !pyjson.Equal(pyjson.Get(event, "kind"), "execution") {
			continue
		}
		actionID, actionOK := pyjson.Text(pyjson.Get(event, "action_id"))
		attemptID, attemptOK := pyjson.Text(pyjson.Get(event, "attempt_id"))
		if !actionOK || !attemptOK {
			*findings = append(*findings, Finding{schemaInvalid, "/records/" + strconv.Itoa(index) + "/event", "execution event requires string action_id and attempt_id"})
			continue
		}
		key, _ := json.Marshal([]string{actionID, attemptID})
		found, exists := grouped[string(key)]
		if !exists {
			found = &group{actionID: actionID, attemptID: attemptID}
			grouped[string(key)] = found
			order = append(order, string(key))
		}
		found.records = append(found.records, record)
	}
	result := make([]*group, 0, len(order))
	for _, key := range order {
		current := grouped[key]
		// The reference computes each sort key once, recording a finding for a bad sequence.
		type keyed struct {
			record   map[string]any
			sequence int64
			id       string
		}
		entries := make([]keyed, len(current.records))
		for index, record := range current.records {
			entries[index] = keyed{record, sequenceOf(record, "/records", findings), pyjson.Str(record["object_id"])}
		}
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].sequence != entries[j].sequence {
				return entries[i].sequence < entries[j].sequence
			}
			return entries[i].id < entries[j].id
		})
		for index, entry := range entries {
			current.records[index] = entry.record
		}
		result = append(result, current)
	}
	return result
}

// ErrLimits is a non-positive analysis limit.
var ErrLimits = errors.New("bundle resource limits must be integers of at least 1")

// Analyze returns the causal closure and execution-state analysis of EBMP-2 records (EBMP-2
// section 4, EBMP2-022 to EBMP2-029): unique object identifiers, digest-bound predecessors, an
// acyclic graph, monotonic sequences within a workflow, and execution attempts whose states move
// only forward. external lists identifiers outside the records that may be named without making
// the closure incomplete.
func Analyze(records []any, external map[string]bool, maxRecords, maxPredecessors int) (*Analysis, error) {
	return AnalyzeGraph(records, external, maxRecords, maxPredecessors, []string{"object_id"}, false)
}

// ContextRule is EBMP2-077: a predecessor that the bundle holds has its successor's root trace
// and is in its successor's workflow, with an attempt no greater, or in the workflow its
// successor names as its parent.
const ContextRule = "ecl.rule.bundle-causal-context-consistent.v1"

// identity returns the record's identifier: the first of members that it carries.
func identity(record map[string]any, members []string) any {
	for _, member := range members {
		if value, present := record[member]; present {
			return value
		}
	}
	return nil
}

// contextConsistent is EBMP2-077 for one predecessor that the records hold.
func contextConsistent(prior, workflow map[string]any) bool {
	priorWorkflow, ok := pyjson.Object(prior["workflow"])
	if !ok || !pyjson.Equal(priorWorkflow["root_trace_id"], workflow["root_trace_id"]) {
		return false
	}
	if pyjson.Equal(priorWorkflow["workflow_id"], workflow["workflow_id"]) {
		before, beforeOK := pyjson.Int(priorWorkflow["attempt"])
		after, afterOK := pyjson.Int(workflow["attempt"])
		return beforeOK && afterOK && before <= after
	}
	parent, isText := pyjson.Text(workflow["parent_workflow_id"])
	return isText && pyjson.Equal(priorWorkflow["workflow_id"], parent)
}

// AnalyzeGraph is Analyze with a record's identifier taken from the first of identifierMembers
// that it carries, so that the bundle verifier analyzes DCMP-2 messages (message_id) and EBMP-2
// records (object_id) as one graph (EBMP2-059); checkContext applies EBMP2-077 to each
// predecessor that the records hold.
func AnalyzeGraph(records []any, external map[string]bool, maxRecords, maxPredecessors int, identifierMembers []string, checkContext bool) (*Analysis, error) {
	if maxRecords < 1 || maxPredecessors < 1 {
		return nil, ErrLimits
	}
	var values []map[string]any
	var findings []Finding
	for index, item := range records {
		if index >= maxRecords {
			findings = append(findings, Finding{resourceLimitExceeded, "/records", "bundle record count exceeds the verifier budget"})
			break
		}
		record, ok := pyjson.Object(item)
		if !ok {
			findings = append(findings, Finding{schemaInvalid, "/records/" + strconv.Itoa(index), "bundle record must be an object"})
			continue
		}
		values = append(values, record)
	}
	byID := map[string]map[string]any{}
	var ids []string
	for index, record := range values {
		objectID, ok := pyjson.Text(identity(record, identifierMembers))
		if !ok || objectID == "" {
			findings = append(findings, Finding{"ecl.rule.bundle-object-identifiers-unique.v1", "/records/" + strconv.Itoa(index) + "/object_id", "bundle record is missing object_id"})
			continue
		}
		if _, exists := byID[objectID]; exists {
			findings = append(findings, Finding{"ecl.rule.bundle-object-identifiers-unique.v1", "/records/" + strconv.Itoa(index) + "/object_id", "duplicate object_id " + objectID})
			continue
		}
		byID[objectID] = record
		ids = append(ids, objectID)
	}
	unresolved := map[string]bool{}
	edges := map[string]map[string]bool{}
	for _, objectID := range ids {
		edges[objectID] = map[string]bool{}
	}
	for _, objectID := range ids {
		record := byID[objectID]
		path := "/records/" + objectID
		sequence := sequenceOf(record, path, &findings)
		workflow, ok := pyjson.Object(record["workflow"])
		if !ok {
			continue
		}
		listed := workflow["causal_predecessors"]
		if !pyjson.Truthy(listed) {
			listed = []any{}
		}
		predecessors, ok := pyjson.Array(listed)
		if !ok {
			findings = append(findings, Finding{schemaInvalid, path + "/workflow/causal_predecessors", "causal_predecessors must be an array"})
			continue
		}
		if len(predecessors) > maxPredecessors {
			findings = append(findings, Finding{resourceLimitExceeded, path + "/workflow/causal_predecessors", "predecessor count exceeds the verifier budget"})
			predecessors = predecessors[:maxPredecessors]
		}
		for _, item := range predecessors {
			predecessor, ok := pyjson.Object(item)
			if !ok {
				findings = append(findings, Finding{schemaInvalid, path + "/workflow/causal_predecessors", "causal predecessor must be an object"})
				continue
			}
			predecessorID, ok := pyjson.Text(predecessor["id"])
			if !ok || predecessorID == "" {
				findings = append(findings, Finding{schemaInvalid, path + "/workflow/causal_predecessors", "causal predecessor requires a non-empty string id"})
				continue
			}
			edges[objectID][predecessorID] = true
			prior, known := byID[predecessorID]
			if !known {
				if !external[predecessorID] {
					unresolved[predecessorID] = true
				}
				continue
			}
			expected := predecessor["digest"]
			if !pyjson.Truthy(expected) {
				expected = map[string]any{}
			}
			matches := false
			if _, isObject := pyjson.Object(expected); isObject && pyjson.Equal(pyjson.Get(expected, "algorithm"), canon.DigestAlgorithm) {
				if digest, err := canon.Digest(prior); err == nil {
					matches = pyjson.Equal(pyjson.Get(expected, "value"), digest)
				}
			}
			if !matches {
				findings = append(findings, Finding{"ecl.rule.bundle-predecessor-digest-valid.v1", "/records/" + objectID + "/workflow/causal_predecessors", "predecessor digest mismatch for " + predecessorID})
			}
			if checkContext && !contextConsistent(prior, workflow) {
				findings = append(findings, Finding{ContextRule, "/records/" + objectID + "/workflow/causal_predecessors", "predecessor " + predecessorID + " is outside the causal context of " + objectID})
			}
			priorSequence := sequenceOf(prior, "/records/"+predecessorID, &findings)
			priorWorkflow, priorOK := pyjson.Object(prior["workflow"])
			if priorOK && pyjson.Equal(priorWorkflow["workflow_id"], workflow["workflow_id"]) && priorSequence >= sequence {
				findings = append(findings, Finding{"ecl.rule.bundle-causal-sequence-monotonic.v1", "/records/" + objectID + "/workflow/sequence", "predecessor " + predecessorID + " does not precede " + objectID})
			}
		}
	}
	findings = append(findings, cycleFindings(edges)...)
	terminal := map[string]bool{}
	open := map[string]bool{}
	for _, current := range executionGroups(values, &findings) {
		states := make([]string, len(current.records))
		for index, record := range current.records {
			event := record["event"]
			if !pyjson.Truthy(event) {
				event = map[string]any{}
			}
			states[index] = pyjson.Str(pyjson.Get(event, "state"))
		}
		for index := 0; index+1 < len(states); index++ {
			prior, next := states[index], states[index+1]
			allowed, known := allowedTransitions[prior]
			if TerminalStates[prior] || !known || !allowed[next] {
				findings = append(findings, Finding{"ecl.rule.execution-state-transition-valid.v1", "/attempts/" + current.attemptID, "invalid execution transition " + prior + " -> " + next})
			}
		}
		if len(states) > 0 && TerminalStates[states[len(states)-1]] {
			terminal[current.actionID] = true
		} else {
			open[current.actionID] = true
		}
	}
	status := "complete"
	switch {
	case len(unresolved) > 0 || len(open) > 0:
		status = "incomplete"
	case len(findings) > 0:
		status = "indeterminate"
	}
	sortFindings(findings)
	return &Analysis{
		Status:                   status,
		TerminalActionIDs:        sortedKeys(terminal),
		OpenActionIDs:            sortedKeys(open),
		UnresolvedPredecessorIDs: sortedKeys(unresolved),
		Findings:                 findings,
	}, nil
}
