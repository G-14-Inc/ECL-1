package evidence

import (
	"fmt"
	"sort"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

// The parser limits of the reference for one signed object: an object nested deeper than 32
// levels or holding more than 10 000 values gets one finding and nothing else is checked.
const (
	MaxObjectDepth = 32
	MaxObjectNodes = 10_000
	maxPerRule     = 100
)

var protocolSchemas = map[string]string{
	"DCMP-2": "https://externalcontrollayer.ai/ns/schema/dcmp/2",
	"EBMP-2": "https://externalcontrollayer.ai/ns/schema/ebmp/2",
}

const envelopeSchema = "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1"

func cutText(text string) string {
	if utf8.RuneCountInString(text) <= 200 {
		return text
	}
	return string([]rune(text)[:199]) + "…"
}

func limitExceeded(value any) string {
	nodes := 1
	type pending struct {
		value any
		depth int
	}
	stack := []pending{{value, 1}}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.depth > MaxObjectDepth {
			return fmt.Sprintf("nesting depth exceeds %d", MaxObjectDepth)
		}
		var children []any
		switch container := current.value.(type) {
		case []any:
			children = container
		case map[string]any:
			for _, key := range pyjson.Keys(container) {
				children = append(children, container[key])
			}
		}
		nodes += len(children)
		if nodes > MaxObjectNodes {
			return fmt.Sprintf("node count exceeds %d", MaxObjectNodes)
		}
		for _, child := range children {
			switch child.(type) {
			case []any, map[string]any:
				stack = append(stack, pending{child, current.depth + 1})
			}
		}
	}
	return ""
}

// ObjectFindings returns the schema and semantic findings for a DCMP-2, EBMP-2 or ECL-IE-1 value,
// as the reference's object_findings and the bundle verifier give them for each signed payload.
// Anything that is not one of those objects yields one schema-invalid finding; the error is for a
// value that cannot be checked at all.
func ObjectFindings(value any) ([]Finding, error) {
	return objectFindings(value)
}

// objectFindings returns the schema and semantic findings for a DCMP-2, EBMP-2 or ECL-IE-1
// value, as the bundle verifier applies them to each signed payload. Anything that is not one of
// those objects yields one schema-invalid finding.
func objectFindings(value any) ([]Finding, error) {
	invalid := func(path, message string) Finding {
		return Finding{RuleID: schemaInvalid, Path: cutText(path), Detail: cutText(message)}
	}
	object, ok := pyjson.Object(value)
	if !ok {
		return []Finding{invalid("/", "an ECL object must be a JSON object")}, nil
	}
	if excess := limitExceeded(object); excess != "" {
		return []Finding{invalid("/", excess)}, nil
	}
	protocol, _ := pyjson.Text(object["protocol"])
	reference, isProtocol := protocolSchemas[protocol]
	if !isProtocol {
		if !pyjson.Equal(object["envelope_version"], "ECL-IE-1") {
			return []Finding{invalid("/", "not a DCMP-2 or EBMP-2 object, and not an ECL-IE-1 envelope")}, nil
		}
		reference = envelopeSchema
	}
	errorsFound, err := schema.ECL().Errors(reference, object, maxPerRule+1)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for index, item := range errorsFound {
		if index == maxPerRule {
			findings = append(findings, invalid("/", "more schema errors follow, and are not listed"))
			break
		}
		findings = append(findings, invalid(item.Path, item.Keyword+": "+item.Message))
	}
	if isProtocol {
		found, err := semantic.Validate(object, semantic.Registered())
		if err != nil {
			findings = append(findings, invalid("/", "semantic validation could not be completed: "+err.Error()))
		} else {
			counts := map[string]int{}
			for _, item := range found {
				counts[item.RuleID]++
				if counts[item.RuleID] <= maxPerRule {
					findings = append(findings, Finding{RuleID: item.RuleID, Path: cutText(item.Path), Detail: cutText(item.Detail)})
				}
			}
			rules := map[string]any{}
			for rule := range counts {
				rules[rule] = nil
			}
			for _, rule := range pyjson.Keys(rules) {
				if counts[rule] > maxPerRule {
					findings = append(findings, Finding{RuleID: rule, Path: "/", Detail: fmt.Sprintf("%d more follow, and are not listed", counts[rule]-maxPerRule)})
				}
			}
		}
	}
	sortFindings(findings)
	return findings, nil
}

func sortFindings(findings []Finding) {
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
