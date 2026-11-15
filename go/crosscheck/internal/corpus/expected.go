package corpus

import (
	"reflect"
	"sort"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
)

// ExpectedScope is a vector's expected_scope: the two lists of EBMP2-076 in table order and the
// reasons of the items that a reason keeps out of established.
type ExpectedChecks struct {
	Checks  []string `json:"checks"`
	Objects []int    `json:"objects"`
}

type ExpectedScope struct {
	Established    []string                   `json:"established"`
	NotEstablished []string                   `json:"not_established"`
	Reasons        map[string]string          `json:"reasons"`
	Checks         *map[string]ExpectedChecks `json:"checks,omitempty"`
}

// ExpectedEffect is one entry of a vector's expected_effects: the level that every terminal
// effect of the action must have (EBMP2-061).
type ExpectedEffect struct {
	ActionID string `json:"action_id"`
	Level    string `json:"level"`
}

// ReportMatches reports whether a report's scope, evidence levels and unresolved predecessors are
// those a vector names, when it names them, as scripts/run_conformance.py compares them: the scope
// lists exactly and the reasons as a map, for each listed action every reported level of its
// terminal effects, and the unresolved predecessor identifiers as a set. A nil report matches only
// a vector that names none of them.
func ReportMatches(report *evidence.Report, scope *ExpectedScope, effects []ExpectedEffect, unresolved *[]string) bool {
	if scope == nil && effects == nil && unresolved == nil {
		return true
	}
	if report == nil {
		return false
	}
	if scope != nil {
		if strings.Join(report.Scope.Established, "\x00") != strings.Join(scope.Established, "\x00") ||
			strings.Join(report.Scope.NotEstablished, "\x00") != strings.Join(scope.NotEstablished, "\x00") ||
			len(report.Scope.Reasons) != len(scope.Reasons) {
			return false
		}
		for item, reason := range scope.Reasons {
			if report.Scope.Reasons[item] != reason {
				return false
			}
		}
		if scope.Checks != nil {
			if len(report.Scope.Checks) != len(*scope.Checks) {
				return false
			}
			for item, want := range *scope.Checks {
				got, present := report.Scope.Checks[item]
				if !present {
					return false
				}
				checks, objects := append([]string{}, got.Checks...), append([]int{}, got.Objects...)
				wantedChecks, wantedObjects := append([]string{}, want.Checks...), append([]int{}, want.Objects...)
				sort.Strings(checks)
				sort.Ints(objects)
				sort.Strings(wantedChecks)
				sort.Ints(wantedObjects)
				for i := 1; i < len(checks); i++ {
					if checks[i] == checks[i-1] {
						return false
					}
				}
				for i := 1; i < len(objects); i++ {
					if objects[i] == objects[i-1] {
						return false
					}
				}
				if !reflect.DeepEqual(checks, wantedChecks) || !reflect.DeepEqual(objects, wantedObjects) {
					return false
				}
			}
		}
	}
	if unresolved != nil {
		got := map[string]bool{}
		for _, identifier := range report.UnresolvedPredecessorIDs {
			got[identifier] = true
		}
		want := map[string]bool{}
		for _, identifier := range *unresolved {
			want[identifier] = true
		}
		if len(got) != len(report.UnresolvedPredecessorIDs) || len(got) != len(want) {
			return false
		}
		for identifier := range want {
			if !got[identifier] {
				return false
			}
		}
	}
	// Unicode White_Space, shared with the report checker; retain IDs unchanged.
	const observationWhiteSpace = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
	if effects != nil {
		for _, effect := range report.Effects {
			if strings.Trim(effect.ActionID, observationWhiteSpace) == "" {
				return false
			}
		}
	}
	for _, expected := range effects {
		levels := map[string]bool{}
		for _, effect := range report.Effects {
			if effect.ActionID == expected.ActionID {
				levels[effect.Level] = true
			}
		}
		if len(levels) != 1 || !levels[expected.Level] {
			return false
		}
	}
	return true
}
