package semantic

import "externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"

// workIntentFindings checks declarations; it does not resolve the causal object.
func workIntentFindings(root map[string]any) []Finding {
	found := []Finding{}
	issued, ie := instant.Parse(root["issued_at"])
	expiry, ee := instant.Parse(root["expires_at"])
	if ie == nil && ee == nil && instant.Compare(expiry, issued) <= 0 {
		found = append(found, Finding{RuleID: "ecl.rule.expiry-after-issue.v1", Path: "/expires_at", Detail: "expires_at must be later than issued_at"})
	}
	workflow, ok := root["workflow"].(map[string]any)
	if !ok {
		return found
	}
	reference, _ := root["parent_workflow"].(map[string]any)
	parent, hasParent := reference["uri"].(string)
	contextParent, hasContextParent := workflow["parent_workflow_id"].(string)
	rule := "ecl.rule.work-intent-context-consistent.v1"
	if hasParent && hasContextParent && parent != contextParent {
		found = append(found, Finding{RuleID: rule, Path: "/parent_workflow/uri", Detail: "parent workflow identifiers disagree"})
	}
	workflowID, isText := workflow["workflow_id"].(string)
	for _, pair := range []struct {
		path, id string
		present  bool
	}{
		{"/parent_workflow/uri", parent, hasParent}, {"/workflow/parent_workflow_id", contextParent, hasContextParent},
	} {
		if isText && pair.present && pair.id == workflowID {
			found = append(found, Finding{RuleID: rule, Path: pair.path, Detail: "a workflow cannot identify itself as its parent"})
		}
	}
	if hasParent || hasContextParent {
		if predecessors, ok := workflow["causal_predecessors"].([]any); ok && len(predecessors) == 0 {
			found = append(found, Finding{RuleID: rule, Path: "/workflow/causal_predecessors", Detail: "a child work intent names its creating or delegating causal predecessor"})
		}
	}
	return found
}
