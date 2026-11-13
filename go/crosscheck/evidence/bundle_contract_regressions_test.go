package evidence_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

const bundleContractRoot = "tests/fixtures/bundle-contract-regressions/"

func TestBundleContractRegressionSignedContracts(t *testing.T) {
	var manifest struct {
		Now   string `json:"now"`
		Cases []struct {
			ID           string  `json:"id"`
			Bundle       string  `json:"bundle"`
			Policy       string  `json:"policy"`
			Verdict      string  `json:"verdict"`
			Primary      *string `json:"primary"`
			InvalidExtra bool    `json:"invalid_extra_signature"`
			EmptyGuard   bool    `json:"continuation_empty_key_guard"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(vectors.Read(t, bundleContractRoot+"manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			report, _, err := evidence.VerifyBytes(vectors.Read(t, bundleContractRoot+item.Bundle), vectors.Read(t, bundleContractRoot+item.Policy), nil, evidence.Options{Now: manifest.Now})
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != item.Verdict {
				t.Fatalf("got %s want %s: %#v", report.Verdict, item.Verdict, report.Findings)
			}
			var primary *string
			if len(report.Findings) > 0 {
				primary = &report.Findings[0].Code
			}
			if !reflect.DeepEqual(primary, item.Primary) {
				t.Fatalf("unexpected primary: %#v", report.Findings)
			}
			if item.InvalidExtra {
				if slices.Contains(report.Scope.Established, "envelope-signatures") {
					t.Fatal("unverified extra signature establishes envelope-signatures")
				}
				found := false
				for _, d := range report.TrustDependencies {
					if d.KeyID == "urn:example:key:probe-extra-approval-key" && d.Historical == "ecl.error.integrity-invalid.v1" {
						found = true
					}
				}
				if !found {
					t.Fatal("missing invalid-signature dependency")
				}
			}
			if item.EmptyGuard {
				found := false
				for _, f := range report.Findings {
					if f.Code == "ecl.error.decision-binding-invalid.v1" {
						found = true
					}
				}
				if !found {
					t.Fatal("empty approval keys did not reject continuation")
				}
			}
		})
	}
}

func TestBundleContractRegressionCausalContracts(t *testing.T) {
	var manifest struct {
		Cases []struct {
			ID      string          `json:"id"`
			Records json.RawMessage `json:"records"`
			Options struct {
				MaxRecords      int `json:"max_records"`
				MaxPredecessors int `json:"max_predecessors_per_record"`
			} `json:"options"`
			Status     string   `json:"status"`
			Unresolved []string `json:"unresolved"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(vectors.Read(t, bundleContractRoot+"causal.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	var duplicates []*evidence.Analysis
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			records, err := strict.Parse(item.Records)
			if err != nil {
				t.Fatal(err)
			}
			maxRecords, maxPredecessors := item.Options.MaxRecords, item.Options.MaxPredecessors
			if maxRecords == 0 {
				maxRecords = 1000000
			}
			if maxPredecessors == 0 {
				maxPredecessors = 128
			}
			report, err := evidence.Analyze(records.([]any), nil, maxRecords, maxPredecessors)
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != item.Status || !slices.Equal(report.UnresolvedPredecessorIDs, item.Unresolved) {
				t.Fatalf("unexpected analysis: %#v", report)
			}
			if len(item.ID) > 4 && item.ID[:4] == "f004" {
				duplicates = append(duplicates, report)
			}
		})
	}
	for _, report := range duplicates {
		if !reflect.DeepEqual(report, duplicates[0]) {
			t.Fatal("duplicate graph report depends on input order")
		}
	}
}

func TestBundleContractRegressionBooleanWaiverControls(t *testing.T) {
	suite := "conformance/suites/evidence-bundle/"
	for _, option := range []bool{false, true} {
		report, _, err := evidence.VerifyBytes(vectors.Read(t, suite+"bundle-current-trust-failed-revoked-after-use.json"), vectors.Read(t, suite+"trust-policy-revoked-after-use.json"), [][]byte{vectors.Read(t, suite+"trust-policy.json")}, evidence.Options{Now: "2026-10-01T00:00:00Z", AcceptCurrentTrustFailure: option})
		if err != nil {
			t.Fatal(err)
		}
		expected := "current-trust-failed"
		if option {
			expected = "verified"
		}
		if report.Verdict != expected || report.AcceptedCurrentTrustFailure != option {
			t.Fatalf("unexpected waiver result %#v", report)
		}
	}
}
