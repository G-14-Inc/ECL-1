package evidence_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

type designVector struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Policy  string `json:"trust_policy_path"`
	Now     string `json:"evaluated_at"`
	Verdict string `json:"expected_verdict"`
	Primary string `json:"expected_primary_id"`
}

func designVectors(t *testing.T, path string) []designVector {
	t.Helper()
	var manifest struct {
		Vectors []designVector `json:"vectors"`
	}
	if err := json.Unmarshal(vectors.Read(t, path), &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Vectors
}

func designPayloads(t *testing.T, vector designVector) []map[string]any {
	t.Helper()
	var bundle struct {
		Envelopes []struct {
			Payload string `json:"payload"`
		} `json:"envelopes"`
	}
	if err := json.Unmarshal(vectors.Read(t, vector.Path), &bundle); err != nil {
		t.Fatal(err)
	}
	out := []map[string]any{}
	for _, e := range bundle.Envelopes {
		raw, err := base64.StdEncoding.DecodeString(e.Payload)
		if err != nil {
			t.Fatal(err)
		}
		value, err := strict.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, value.(map[string]any))
	}
	return out
}

func TestPublicReviewSignedDesignDecisions(t *testing.T) {
	cases := designVectors(t, "conformance/suites/public-review-design-decisions/manifest.json")
	for _, v := range designVectors(t, "conformance/suites/evidence-bundle/manifest.json") {
		if v.ID == "bundle-invalid-continuation-second-of-one-challenge" || v.ID == "bundle-invalid-continuation-second-of-one-challenge-approval-absent" {
			cases = append(cases, v)
		}
	}
	for _, v := range cases {
		t.Run(v.ID, func(t *testing.T) {
			bundle, err := strict.Parse(vectors.Read(t, v.Path))
			if err != nil {
				t.Fatal(err)
			}
			r, err := evidence.Verify(bundle, load(t, v.Policy), evidence.Options{Now: v.Now})
			if err != nil {
				t.Fatal(err)
			}
			primary := ""
			if p := evidence.PrimaryFinding(r); p != nil {
				primary = *p
			}
			if r.Verdict != v.Verdict || primary != v.Primary {
				t.Fatalf("%s %s; want %s %s; %v", r.Verdict, primary, v.Verdict, v.Primary, r.Findings)
			}
			if v.Verdict == "invalid" {
				if len(r.Findings) != 1 || r.Findings[0].Code != v.Primary {
					t.Fatalf("unexpected findings: %v", r.Findings)
				}
			} else if len(r.Findings) != 0 {
				t.Fatalf("unexpected findings: %v", r.Findings)
			}
			if strings.Contains(v.ID, "approval-absent") && v.Verdict == "incomplete" {
				for _, scope := range r.Scope.Established {
					if scope == "bindings" || scope == "causal-completeness" {
						t.Fatalf("incomplete history established %s", scope)
					}
				}
				if len(r.UnresolvedPredecessorIDs) == 0 {
					t.Fatal("missing approval not retained")
				}
			}
			for _, payload := range designPayloads(t, v) {
				findings, err := evidence.ObjectFindings(payload)
				if err != nil || len(findings) != 0 {
					t.Fatalf("payload control: %v %v", findings, err)
				}
			}
		})
	}
}

func TestPublicReviewRequestExpiryPairs(t *testing.T) {
	for _, v := range designVectors(t, "conformance/suites/public-review-design-decisions/manifest.json") {
		if !strings.HasPrefix(v.ID, "request-expiry-") {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			p := designPayloads(t, v)
			for _, skew := range []int64{0, 1} {
				err := evidence.CheckResponseBinding(p[0], p[1], skew)
				if v.Verdict == "invalid" {
					var binding *evidence.BindingError
					if !errors.As(err, &binding) || binding.Code != evidence.RequestBindingInvalid || !strings.Contains(binding.Message, "evaluated_at") {
						t.Fatalf("%v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPublicReviewRequestExpiryPrecedence(t *testing.T) {
	var vector designVector
	for _, v := range designVectors(t, "conformance/suites/public-review-design-decisions/manifest.json") {
		if v.ID == "request-expiry-admit-equal" {
			vector = v
		}
	}
	for _, tc := range []struct{ name, code, fragment string }{
		{"digest", evidence.DigestMismatch, "digest"},
		{"issued", evidence.RequestBindingInvalid, "issued_at"},
		{"expiry", evidence.RequestBindingInvalid, "evaluated_at"},
		{"audience", evidence.AudienceMismatch, "audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := designPayloads(t, vector)
			p[1]["authorization"].(map[string]any)["audience"] = "urn:example:wrong-audience"
			switch tc.name {
			case "digest":
				p[1]["workflow"].(map[string]any)["causal_predecessors"].([]any)[0].(map[string]any)["digest"].(map[string]any)["value"] = strings.Repeat("f", 64)
			case "issued":
				p[1]["issued_at"] = "2026-09-29T09:59:59.999999999Z"
			case "audience":
				p[1]["evaluated_at"] = "2026-09-29T10:00:00.099999999Z"
			}
			err := evidence.CheckResponseBinding(p[0], p[1], 0)
			var binding *evidence.BindingError
			if !errors.As(err, &binding) || binding.Code != tc.code || !strings.Contains(binding.Message, tc.fragment) {
				t.Fatalf("%v", err)
			}
		})
	}
}
