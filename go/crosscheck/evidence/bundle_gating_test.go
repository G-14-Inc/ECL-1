package evidence_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func TestCompleteBundleFindings(t *testing.T) {
	var manifest struct {
		TrustPolicy string `json:"trust_policy"`
		EvaluatedAt string `json:"evaluated_at"`
		Cases       []struct {
			ID        string   `json:"id"`
			Path      string   `json:"path"`
			Rationale string   `json:"rationale"`
			Verdict   string   `json:"expected_verdict"`
			Findings  []string `json:"expected_findings"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(vectors.Read(t, "tests/fixtures/bundle-gating/expected.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			bundle, err := strict.Parse(vectors.Read(t, item.Path))
			if err != nil {
				t.Fatal(err)
			}
			report, err := evidence.Verify(bundle, load(t, manifest.TrustPolicy), evidence.Options{Now: manifest.EvaluatedAt})
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != item.Verdict {
				t.Fatalf("verdict: %s, want %s", report.Verdict, item.Verdict)
			}
			actual := make([]string, 0, len(report.Findings))
			for _, f := range report.Findings {
				actual = append(actual, f.Code+": "+f.Message)
			}
			if !reflect.DeepEqual(actual, item.Findings) {
				t.Fatalf("%s\ngot %#v\nwant %#v", item.Rationale, actual, item.Findings)
			}
		})
	}
}

func TestSignerTrustDependencies(t *testing.T) {
	type dependency struct {
		KeyID      string `json:"key_id"`
		Historical string `json:"historical"`
		Current    string `json:"current"`
	}
	var manifest struct {
		TrustPolicy string `json:"trust_policy"`
		EvaluatedAt string `json:"evaluated_at"`
		Cases       []struct {
			ID           string       `json:"id"`
			Path         string       `json:"path"`
			WrapEnvelope bool         `json:"wrap_envelope"`
			Verdict      string       `json:"expected_verdict"`
			Dependencies []dependency `json:"expected_dependencies"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(vectors.Read(t, "tests/fixtures/bundle-gating/trust-dependencies.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			value, err := strict.Parse(vectors.Read(t, item.Path))
			if err != nil {
				t.Fatal(err)
			}
			if item.WrapEnvelope {
				value = map[string]any{"schema_version": "ecl_evidence_bundle_v1", "envelopes": []any{value}}
			}
			report, err := evidence.Verify(value, load(t, manifest.TrustPolicy), evidence.Options{Now: manifest.EvaluatedAt})
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != item.Verdict {
				t.Fatalf("verdict: %s, want %s", report.Verdict, item.Verdict)
			}
			actual := []dependency{}
			for _, d := range report.TrustDependencies {
				if d.Role == "signer" {
					actual = append(actual, dependency{d.KeyID, d.Historical, d.Current})
				}
			}
			if !reflect.DeepEqual(actual, item.Dependencies) {
				t.Fatalf("got %#v; want %#v", actual, item.Dependencies)
			}
		})
	}
}
