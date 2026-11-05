package evidence_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

const cases = "testdata/verifier-cases"

func caseFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cases, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func casePolicy(t *testing.T, data []byte) *trust.Policy {
	t.Helper()
	policy, err := trust.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func caseVerify(t *testing.T, bundle []byte, policy *trust.Policy, options evidence.Options) *evidence.Report {
	t.Helper()
	value, err := strict.Parse(bundle)
	if err != nil {
		t.Fatal(err)
	}
	report, err := evidence.Verify(value, policy, options)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func levels(report *evidence.Report) string {
	var result []string
	for _, effect := range report.Effects {
		result = append(result, effect.Level)
	}
	return strings.Join(result, " ")
}

// F01: an observation is a node of the causal graph: a missing predecessor leaves the closure
// incomplete, a wrong digest or another attempt and trace is invalid, and a valid observation
// corroborates.
func TestObservationsAreNodesOfTheCausalGraph(t *testing.T) {
	policy := casePolicy(t, caseFile(t, "probe-policy.json"))
	for name, expected := range map[string]string{
		"valid-observation.json":                    "verified complete  corroborated",
		"missing-observation-predecessor.json":      "incomplete incomplete ecl.error.causal-closure-incomplete.v1 issuer-asserted",
		"wrong-observation-predecessor-digest.json": "invalid indeterminate ecl.rule.bundle-predecessor-digest-valid.v1 issuer-asserted",
		"observation-wrong-attempt.json":            "invalid indeterminate ecl.rule.bundle-causal-context-consistent.v1 issuer-asserted",
	} {
		report := caseVerify(t, caseFile(t, name), policy, evidence.Options{Now: now})
		got := fmt.Sprintf("%s %s %s %s", report.Verdict, report.CausalStatus, strings.Join(evidence.ReportedIdentifiers(report), " "), levels(report))
		if got != expected {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// F02: an attestation that binds the payload alone (no covered.signatures) is invalid.
func TestAnAttestationWithoutSignatureBindingIsInvalid(t *testing.T) {
	report := caseVerify(t, caseFile(t, "timed-bundle.json"), casePolicy(t, caseFile(t, "current-tsa-valid-policy.json")), evidence.Options{
		Now: "2026-09-29T10:00:02.000000Z", RequireTrustedTime: true,
		History: []*trust.Policy{casePolicy(t, caseFile(t, "past-timed-policy.json"))},
	})
	if primary := evidence.PrimaryFinding(report); report.Verdict != evidence.Invalid || primary == nil || *primary != evidence.TrustedTimeInvalid {
		t.Fatalf("%s %v", report.Verdict, report.Findings)
	}
}

type verifierCase struct {
	Name                      string            `json:"name"`
	Bundle                    json.RawMessage   `json:"bundle"`
	Policy                    json.RawMessage   `json:"policy"`
	History                   []json.RawMessage `json:"history"`
	Register                  json.RawMessage   `json:"register"`
	Now                       string            `json:"now"`
	RequireTrustedTime        bool              `json:"require_trusted_time"`
	AcceptCurrentTrustFailure bool              `json:"accept_current_trust_failure"`
	Expected                  struct {
		Identifiers []string        `json:"identifiers"`
		Report      json.RawMessage `json:"report"`
	} `json:"expected"`
}

func loadCases(t *testing.T) []verifierCase {
	t.Helper()
	var document struct {
		Cases []verifierCase `json:"cases"`
	}
	if err := json.Unmarshal(caseFile(t, "cases.json"), &document); err != nil {
		t.Fatal(err)
	}
	return document.Cases
}

func caseOptions(t *testing.T, item verifierCase) evidence.Options {
	t.Helper()
	options := evidence.Options{Now: item.Now, RequireTrustedTime: item.RequireTrustedTime, AcceptCurrentTrustFailure: item.AcceptCurrentTrustFailure}
	for _, older := range item.History {
		options.History = append(options.History, casePolicy(t, older))
	}
	if len(item.Register) > 0 && string(item.Register) != "null" {
		register, err := evidence.LoadRegister(item.Register)
		if err != nil {
			t.Fatal(err)
		}
		options.Register = register
	}
	return options
}

// canonical returns the canonical JSON text of a report value, each finding reduced to its code.
func canonical(t *testing.T, value map[string]any) string {
	t.Helper()
	if findings, isList := value["findings"].([]any); isList {
		codes := make([]any, len(findings))
		for index, finding := range findings {
			text, _ := finding.(string)
			codes[index] = strings.SplitN(text, ":", 2)[0]
		}
		value["findings"] = codes
	}
	encoded, err := canon.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// F01 to F04, F08 and the claim-to-check map: the Go lane gives each case the JSON report that
// the reference gives it, member for member, findings compared by code (tests/verifier_cases.py
// writes the cases with the reference's reports).
func TestTheSecondRoundCasesGiveTheReferenceReports(t *testing.T) {
	cases := loadCases(t)
	if len(cases) < 40 {
		t.Fatalf("%d cases", len(cases))
	}
	for _, item := range cases {
		report := caseVerify(t, item.Bundle, casePolicy(t, item.Policy), caseOptions(t, item))
		if got, want := fmt.Sprint(evidence.ReportedIdentifiers(report)), fmt.Sprint(item.Expected.Identifiers); got != want {
			t.Errorf("%s: identifiers %s want %s", item.Name, got, want)
		}
		expected, err := strict.Parse(item.Expected.Report)
		if err != nil {
			t.Fatal(err)
		}
		expectedObject, _ := expected.(map[string]any)
		if got, want := canonical(t, report.JSON()), canonical(t, expectedObject); got != want {
			t.Errorf("%s: report differs\n got %s\nwant %s", item.Name, got, want)
		}
	}
}

// The claim-to-check map: the lane requires the checks that registries/scope-checks.json lists.
func TestTheLaneRequiresTheChecksThatTheRegistryLists(t *testing.T) {
	var registry struct {
		Checks []struct {
			ID string `json:"id"`
		} `json:"checks"`
		Items []struct {
			Item           string   `json:"item"`
			Established    string   `json:"established"`
			ObjectSet      *string  `json:"object_set"`
			RequiredChecks []string `json:"required_checks"`
		} `json:"items"`
	}
	if err := json.Unmarshal(vectors.Read(t, "registries/scope-checks.json"), &registry); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, check := range registry.Checks {
		ids = append(ids, check.ID)
	}
	if fmt.Sprint(ids) != fmt.Sprint(evidence.ScopeCheckIDs) {
		t.Fatalf("%v", ids)
	}
	checked := 0
	for _, item := range registry.Items {
		if item.Established != "checked" {
			continue
		}
		checked++
		if fmt.Sprint(item.RequiredChecks) != fmt.Sprint(evidence.ScopeRequiredChecks[item.Item]) || item.ObjectSet == nil || *item.ObjectSet != evidence.ScopeObjectSets[item.Item] {
			t.Errorf("%s: %v %v", item.Item, item.RequiredChecks, evidence.ScopeRequiredChecks[item.Item])
		}
	}
	if checked != len(evidence.ScopeRequiredChecks) {
		t.Fatalf("%d checked items", checked)
	}
}

func fullReport(t *testing.T) *evidence.Report {
	t.Helper()
	for _, item := range loadCases(t) {
		if item.Name == "trusted-time-verified" {
			report := caseVerify(t, item.Bundle, casePolicy(t, item.Policy), caseOptions(t, item))
			if report.Verdict != evidence.Verified {
				t.Fatalf("%v", report.Findings)
			}
			return report
		}
	}
	t.Fatal("no trusted-time case")
	return nil
}

// The claim-to-check map: each established item names every required check over its whole
// object set, and no item is established when a check did not run over its object set.
func TestNoItemIsEstablishedWhenACheckDidNotRunOverItsObjectSet(t *testing.T) {
	report := fullReport(t)
	if len(report.Scope.Checks) != len(report.Scope.Established) {
		t.Fatalf("%v %v", report.Scope.Checks, report.Scope.Established)
	}
	for _, item := range report.Scope.Established {
		entry := report.Scope.Checks[item]
		if fmt.Sprint(entry.Checks) != fmt.Sprint(evidence.ScopeRequiredChecks[item]) {
			t.Errorf("%s: %v", item, entry.Checks)
		}
		dropped := *report
		dropped.Scope.Checks = map[string]evidence.ScopeItemChecks{}
		for name, value := range report.Scope.Checks {
			dropped.Scope.Checks[name] = value
		}
		dropped.Scope.Checks[item] = evidence.ScopeItemChecks{Checks: entry.Checks[1:], Objects: entry.Objects}
		if scope := evidence.ScopeOf(&dropped); strings.Contains(" "+strings.Join(scope.Established, " ")+" ", " "+item+" ") {
			t.Errorf("%s established without %s", item, entry.Checks[0])
		}
		kind := evidence.ScopeObjectSets[item]
		if len(entry.Objects) > 0 && (kind == "bundle-objects" || kind == "trust-dependencies" || kind == "object-signatures" || kind == "decision-responses") {
			fewer := dropped
			fewer.Scope.Checks[item] = evidence.ScopeItemChecks{Checks: entry.Checks, Objects: entry.Objects[1:]}
			if scope := evidence.ScopeOf(&fewer); strings.Contains(" "+strings.Join(scope.Established, " ")+" ", " "+item+" ") {
				t.Errorf("%s established over a part of its object set", item)
			}
		}
	}
	for _, item := range []string{"trusted-time", "current-trust"} {
		if !strings.Contains(strings.Join(report.Scope.Established, " "), item) {
			t.Errorf("%s not established", item)
		}
	}
	// A time authority that fails now keeps current-trust out of the scope.
	failing := *report
	failing.TrustDependencies = append([]evidence.TrustDependency{}, report.TrustDependencies...)
	for index := range failing.TrustDependencies {
		if failing.TrustDependencies[index].Role == "time-authority" {
			failing.TrustDependencies[index].Current = evidence.Revoked
		}
	}
	if scope := evidence.ScopeOf(&failing); strings.Contains(strings.Join(scope.Established, " "), "current-trust") {
		t.Error("current-trust established with a failing time authority")
	}
}
