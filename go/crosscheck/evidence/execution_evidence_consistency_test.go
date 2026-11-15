// Signed execution and report-scope regressions. Robert F. Tilley Jr.; G-14, Inc.
package evidence_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

const executionEvidenceRoot = "tests/fixtures/execution-evidence-consistency/"

func TestExecutionEvidenceConsistency(t *testing.T) {
	var manifest struct {
		Now   string
		Cases []struct {
			ID, Bundle, Policy, Verdict string
			Primary                     *string
			Direct                      map[string]*string
		}
	}
	if err := json.Unmarshal(vectors.Read(t, executionEvidenceRoot+"manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.ID, func(t *testing.T) {
			raw := vectors.Read(t, executionEvidenceRoot+c.Bundle)
			report, _, err := evidence.VerifyBytes(raw, vectors.Read(t, executionEvidenceRoot+c.Policy), nil, evidence.Options{Now: manifest.Now})
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != c.Verdict {
				t.Fatalf("got %s want %s: %+v", report.Verdict, c.Verdict, report.Findings)
			}
			var primary *string
			if code, ok := report.JSON()["primary"].(string); ok {
				primary = &code
			}
			if !reflect.DeepEqual(primary, c.Primary) {
				t.Fatalf("primary got %v want %v", primary, c.Primary)
			}
			if c.Verdict == "invalid" {
				if len(report.Scope.Established) != 0 {
					t.Fatal(report.Scope)
				}
			} else {
				if !slices.Contains(report.Scope.Established, "bindings") || slices.Contains(report.Scope.Established, "causal-completeness") != (c.Verdict == "verified") {
					t.Fatal(report.Scope)
				}
			}
			var bundle struct{ Envelopes []struct{ Payload string } }
			if err := json.Unmarshal(raw, &bundle); err != nil {
				t.Fatal(err)
			}
			payloads := []map[string]any{}
			var response any
			for _, e := range bundle.Envelopes {
				bytes, err := base64.StdEncoding.DecodeString(e.Payload)
				if err != nil {
					t.Fatal(err)
				}
				value, err := strict.Parse(bytes)
				if err != nil {
					t.Fatal(err)
				}
				p := value.(map[string]any)
				payloads = append(payloads, p)
				if p["message_type"] == "decision_response" {
					response = p
				}
			}
			for _, event := range payloads {
				kind, _ := event["event_type"].(string)
				want, ok := c.Direct[kind]
				if !ok {
					continue
				}
				var code *string
				if err := evidence.CheckEventBinding(event, payloads[0], response); err != nil {
					var binding *evidence.BindingError
					if !errors.As(err, &binding) {
						t.Fatal(err)
					}
					code = &binding.Code
				}
				if !reflect.DeepEqual(code, want) {
					t.Fatalf("%s binding got %v want %v", kind, code, want)
				}
			}
		})
	}
}

func TestReconstructedExecutionReportConsistency(t *testing.T) {
	var manifest struct {
		Now   string
		Cases []struct {
			ID     string
			Remove json.RawMessage
		} `json:"reconstructed_scopes"`
	}
	if err := json.Unmarshal(vectors.Read(t, executionEvidenceRoot+"manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.ID, func(t *testing.T) {
			suite := "conformance/suites/evidence-bundle/"
			base, _, err := evidence.VerifyBytes(vectors.Read(t, suite+"bundle-valid-trusted-time.json"), vectors.Read(t, suite+"trust-policy-time-authority.json"), nil, evidence.Options{Now: manifest.Now})
			if err != nil {
				t.Fatal(err)
			}
			if base.Verdict != "verified" {
				t.Fatal(base.Findings)
			}
			r := *base
			r.EnvelopeChecks = append([]evidence.EnvelopeCheck{}, base.EnvelopeChecks...)
			r.TrustDependencies = append([]evidence.TrustDependency{}, base.TrustDependencies...)
			switch c.ID {
			case "signer-historical-invalid", "time-authority-historical-invalid", "current-signer-invalid":
				role := "signer"
				if c.ID == "time-authority-historical-invalid" {
					role = "time-authority"
				}
				found := false
				for i, d := range r.TrustDependencies {
					if d.Role == role {
						if c.ID == "current-signer-invalid" {
							r.TrustDependencies[i].Current = "ecl.error.integrity-invalid.v1"
						} else {
							r.TrustDependencies[i].Historical = "ecl.error.integrity-invalid.v1"
						}
						found = true
						break
					}
				}
				if !found {
					t.Fatal("fixture lacks trust dependency")
				}
			case "missing-trusted-time":
				r.EnvelopeChecks[0].TrustedTime = nil
			case "envelope-historical-invalid":
				r.EnvelopeChecks[0].Historical = "ecl.error.integrity-invalid.v1"
			case "missing-signer-dependency":
				next := []evidence.TrustDependency{}
				for _, d := range r.TrustDependencies {
					if !(d.Index == 0 && d.Role == "signer") {
						next = append(next, d)
					}
				}
				r.TrustDependencies = next
			case "invalid-verdict":
				r.Verdict = "invalid"
			}
			want := []string{}
			if string(c.Remove) != "\"all\"" {
				var remove []string
				if err := json.Unmarshal(c.Remove, &remove); err != nil {
					t.Fatal(err)
				}
				for _, name := range base.Scope.Established {
					if !slices.Contains(remove, name) {
						want = append(want, name)
					}
				}
			}
			if got := evidence.ScopeOf(&r).Established; !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}
