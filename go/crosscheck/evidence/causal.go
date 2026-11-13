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
	"prepared":    {"released": true, "cancelled": true, "timed_out": true, "denied": true, "held": true, "challenged": true, "expired_before_release": true},
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
			// A simple DFS cycle has unique IDs: the least rotation starts at the least ID.
			first := 0
			for index := 1; index < len(cycle)-1; index++ {
				if cycle[index] < cycle[first] {
					first = index
				}
			}
			canonical := append(append(append([]string{}, cycle[first:len(cycle)-1]...), cycle[:first]...), cycle[first])
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

func executionGroups(records []map[string]any, findings *[]Finding, identifierMembers []string) []*group {
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
			identifier, _ := pyjson.Text(identity(record, identifierMembers))
			entries[index] = keyed{record, sequenceOf(record, "/records", findings), identifier}
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
// and is in its successor's workflow, its named parent, or a child with a held origin path.
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
	childParent, hasChildParent := pyjson.Text(priorWorkflow["parent_workflow_id"])
	return (isText && pyjson.Equal(priorWorkflow["workflow_id"], parent)) || (hasChildParent && pyjson.Equal(childParent, workflow["workflow_id"]))
}

// childOriginFindings performs O(V+E) extra work with iterative multi-source propagation.
// Child edges already satisfy digest, root, workflow, parent, attempt and sequence constraints.
func childOriginFindings(childEdges map[string]map[string]bool, seeds map[string]bool, missing, parentConflicts map[string]map[string]bool, joins [][2]string, unresolved map[string]bool) []Finding {
	successors := map[string][]string{}
	for child, predecessors := range childEdges {
		for prior := range predecessors {
			successors[prior] = append(successors[prior], child)
		}
	}
	propagate := func(seeds map[string]bool) map[string]bool {
		reached := map[string]bool{}
		pending := []string{}
		for seed := range seeds {
			reached[seed] = true
			pending = append(pending, seed)
		}
		for i := 0; i < len(pending); i++ {
			for _, child := range successors[pending[i]] {
				if !reached[child] {
					reached[child] = true
					pending = append(pending, child)
				}
			}
		}
		return reached
	}
	originated := propagate(seeds)
	missingSeeds := map[string]bool{}
	for child := range missing {
		missingSeeds[child] = true
	}
	uncertain := propagate(missingSeeds)
	needed := map[string]bool{}
	var findings []Finding
	for _, join := range joins {
		parent, child := join[0], join[1]
		if originated[child] {
			continue
		}
		if uncertain[child] {
			needed[child] = true
		} else {
			findings = append(findings, Finding{ContextRule, "/records/" + parent + "/workflow/causal_predecessors", "child predecessor " + child + " has no digest-bound origin in its declared parent workflow"})
		}
	}
	pending := []string{}
	for child := range needed {
		pending = append(pending, child)
	}
	for i := 0; i < len(pending); i++ {
		child := pending[i]
		for id := range missing[child] {
			unresolved[id] = true
		}
		for prior := range childEdges[child] {
			if uncertain[prior] && !needed[prior] {
				needed[prior] = true
				pending = append(pending, prior)
			}
		}
	}
	ancestry := map[string]bool{}
	ancestors := []string{}
	for _, join := range joins {
		if !ancestry[join[1]] {
			ancestry[join[1]] = true
			ancestors = append(ancestors, join[1])
		}
	}
	for i := 0; i < len(ancestors); i++ {
		child := ancestors[i]
		for prior := range parentConflicts[child] {
			findings = append(findings, Finding{ContextRule, "/records/" + child + "/workflow/causal_predecessors", "child predecessor " + prior + " changes the declared parent in joined child ancestry"})
		}
		for prior := range childEdges[child] {
			if !ancestry[prior] {
				ancestry[prior] = true
				ancestors = append(ancestors, prior)
			}
		}
	}
	return findings
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
			return &Analysis{Status: "indeterminate", TerminalActionIDs: []string{}, OpenActionIDs: []string{}, UnresolvedPredecessorIDs: []string{}, Findings: []Finding{{resourceLimitExceeded, "/records", "bundle record count exceeds the verifier budget"}}}, nil
		}
		record, ok := pyjson.Object(item)
		if !ok {
			findings = append(findings, Finding{schemaInvalid, "/records/" + strconv.Itoa(index), "bundle record must be an object"})
			continue
		}
		values = append(values, record)
	}
	byID := map[string]map[string]any{}
	collidingIDs := map[string]bool{}
	var ids []string
	for index, record := range values {
		objectID, ok := pyjson.Text(identity(record, identifierMembers))
		if !ok || objectID == "" {
			findings = append(findings, Finding{"ecl.rule.bundle-object-identifiers-unique.v1", "/records/" + strconv.Itoa(index) + "/object_id", "bundle record is missing object_id"})
			continue
		}
		if collidingIDs[objectID] {
			continue
		}
		if _, exists := byID[objectID]; exists {
			collidingIDs[objectID] = true
			delete(byID, objectID)
			continue
		}
		byID[objectID] = record
	}
	for objectID := range byID {
		ids = append(ids, objectID)
	}
	sort.Strings(ids)
	for _, objectID := range sortedKeys(collidingIDs) {
		findings = append(findings, Finding{"ecl.rule.bundle-object-identifiers-unique.v1", "/records/" + objectID + "/object_id", "duplicate object_id " + objectID})
	}
	unresolved := map[string]bool{}
	childEdges := map[string]map[string]bool{}
	originSeeds := map[string]bool{}
	missingOrigins := map[string]map[string]bool{}
	parentConflicts := map[string]map[string]bool{}
	parentJoins := [][2]string{}
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
			return &Analysis{Status: "indeterminate", TerminalActionIDs: []string{}, OpenActionIDs: []string{}, UnresolvedPredecessorIDs: []string{}, Findings: []Finding{{resourceLimitExceeded, path + "/workflow/causal_predecessors", "predecessor count exceeds the verifier budget"}}}, nil
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
			if collidingIDs[predecessorID] {
				continue
			}
			prior, known := byID[predecessorID]
			if !known {
				if !external[predecessorID] {
					unresolved[predecessorID] = true
				}
				if _, hasParent := pyjson.Text(workflow["parent_workflow_id"]); checkContext && hasParent {
					if missingOrigins[objectID] == nil {
						missingOrigins[objectID] = map[string]bool{}
					}
					missingOrigins[objectID][predecessorID] = true
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
			contextValid := checkContext && contextConsistent(prior, workflow)
			if checkContext && !contextValid {
				findings = append(findings, Finding{ContextRule, "/records/" + objectID + "/workflow/causal_predecessors", "predecessor " + predecessorID + " is outside the causal context of " + objectID})
			}
			priorSequence := sequenceOf(prior, "/records/"+predecessorID, &findings)
			priorWorkflow, priorOK := pyjson.Object(prior["workflow"])
			sameWorkflow := priorOK && pyjson.Equal(priorWorkflow["workflow_id"], workflow["workflow_id"])
			if contextValid && priorOK {
				parent, hasParent := pyjson.Text(workflow["parent_workflow_id"])
				priorParent := priorWorkflow["parent_workflow_id"]
				if !sameWorkflow && pyjson.Equal(priorParent, workflow["workflow_id"]) {
					parentJoins = append(parentJoins, [2]string{objectID, predecessorID})
				}
				if matches && hasParent {
					if !sameWorkflow && pyjson.Equal(priorWorkflow["workflow_id"], parent) {
						originSeeds[objectID] = true
					} else if sameWorkflow && pyjson.Equal(priorParent, parent) && priorSequence < sequence {
						if childEdges[objectID] == nil {
							childEdges[objectID] = map[string]bool{}
						}
						childEdges[objectID][predecessorID] = true
					} else if sameWorkflow && !pyjson.Equal(priorParent, parent) {
						if parentConflicts[objectID] == nil {
							parentConflicts[objectID] = map[string]bool{}
						}
						parentConflicts[objectID][predecessorID] = true
					}
				}
			}
			if sameWorkflow && priorSequence >= sequence {
				findings = append(findings, Finding{"ecl.rule.bundle-causal-sequence-monotonic.v1", "/records/" + objectID + "/workflow/sequence", "predecessor " + predecessorID + " does not precede " + objectID})
			}
		}
	}
	if checkContext {
		findings = append(findings, childOriginFindings(childEdges, originSeeds, missingOrigins, parentConflicts, parentJoins, unresolved)...)
	}
	findings = append(findings, cycleFindings(edges)...)
	terminal := map[string]bool{}
	open := map[string]bool{}
	uniqueValues := []map[string]any{}
	for _, record := range values {
		identifier, valid := pyjson.Text(identity(record, identifierMembers))
		// Only records with a valid, unambiguous graph identifier may determine an attempt.
		if valid && identifier != "" && !collidingIDs[identifier] {
			uniqueValues = append(uniqueValues, record)
		}
	}
	for _, current := range executionGroups(uniqueValues, &findings, identifierMembers) {
		states := make([]string, len(current.records))
		for index, record := range current.records {
			event := record["event"]
			if !pyjson.Truthy(event) {
				event = map[string]any{}
			}
			states[index] = pyjson.Str(pyjson.Get(event, "state"))
		}
		invalidTransition := false
		for index := 0; index+1 < len(states); index++ {
			prior, next := states[index], states[index+1]
			allowed, known := allowedTransitions[prior]
			if TerminalStates[prior] || !known || !allowed[next] {
				invalidTransition = true
				findings = append(findings, Finding{"ecl.rule.execution-state-transition-valid.v1", "/attempts/" + current.attemptID, "invalid execution transition " + prior + " -> " + next})
			}
		}
		if invalidTransition {
			continue
		}
		if len(states) > 0 && TerminalStates[states[len(states)-1]] {
			terminal[current.actionID] = true
		} else {
			open[current.actionID] = true
		}
	}
	status := "complete"
	switch {
	case len(collidingIDs) > 0:
		status = "indeterminate"
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
