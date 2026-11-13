package corpus

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"sort"
)

// recordObservations binds actual values without substituting expected values.
// An absent report is null; empty observed arrays are arrays, not null.
func recordObservations(result *Result, vector Vector, verdict string, report *evidence.Report, canonical string) {
	if result.Status == "unsupported" {
		return
	}
	pointer := func(value any) *any { return &value }
	if vector.ExpectedVerdict != "" {
		result.ObservedVerdict = pointer(nil)
		if verdict != "" {
			result.ObservedVerdict = pointer(verdict)
		}
	}
	if vector.CanonicalHash != "" {
		result.ObservedCanonical = pointer(nil)
		if canonical != "" {
			result.ObservedCanonical = pointer(canonical)
		}
	}
	if vector.ExpectedScope != nil {
		result.ObservedScope = pointer(nil)
		if report != nil {
			reasons := map[string]string{}
			for key, value := range report.Scope.Reasons {
				reasons[key] = value
			}
			checks := map[string]ExpectedChecks{}
			for item, entry := range report.Scope.Checks {
				indexes := append([]int{}, entry.Objects...)
				sort.Ints(indexes)
				checks[item] = ExpectedChecks{Checks: append([]string{}, entry.Checks...), Objects: indexes}
			}
			result.ObservedScope = pointer(ExpectedScope{
				Established:    append([]string{}, report.Scope.Established...),
				NotEstablished: append([]string{}, report.Scope.NotEstablished...), Reasons: reasons, Checks: &checks})
		}
	}
	if vector.ExpectedEffects != nil {
		result.ObservedEffects = pointer(nil)
		if report != nil {
			effects := []ExpectedEffect{}
			for _, e := range report.Effects {
				effects = append(effects, ExpectedEffect{ActionID: e.ActionID, Level: e.Level})
			}
			result.ObservedEffects = pointer(effects)
		}
	}
	if vector.ExpectedUnresolved != nil {
		result.ObservedUnresolved = pointer(nil)
		if report != nil {
			result.ObservedUnresolved = pointer(append([]string{}, report.UnresolvedPredecessorIDs...))
		}
	}
}
