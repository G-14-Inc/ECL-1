package corpus

import (
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
)

// ExpectedScope is a vector's expected_scope: the two lists of EBMP2-076 in table order and the
// reasons of the items that a reason keeps out of established.
type ExpectedScope struct {
	Established    []string          `json:"established"`
	NotEstablished []string          `json:"not_established"`
	Reasons        map[string]string `json:"reasons"`
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
		if len(got) != len(want) {
			return false
		}
		for identifier := range want {
			if !got[identifier] {
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
