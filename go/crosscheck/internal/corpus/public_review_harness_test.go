package corpus

import (
	"encoding/json"
	"errors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPublicReviewHarnessVectors(t *testing.T) {
	var manifest Manifest
	root := context().Root
	if err := decode(root, "conformance/suites/repair-harness/manifest.json", &manifest); err != nil {
		t.Fatal(err)
	}
	policy, err := loadPolicyFile(root, manifest.TrustPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range manifest.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			local := context()
			local.TrustPolicy = policy
			local.Reports = map[string]*evidence.Report{}
			data, err := read(root, vector.Path)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := Evaluate(data, vector, local)
			if err != nil {
				t.Fatal(err)
			}
			if vector.Expected == "pass" {
				if len(actual) != 0 {
					t.Fatal(actual)
				}
			} else if len(actual) == 0 || actual[0] != vector.Primary {
				t.Fatalf("%v, want %s", actual, vector.Primary)
			}
			if vector.ExpectedVerdict != "" && local.Verdicts[vector.ID] != vector.ExpectedVerdict {
				t.Fatal(local.Verdicts)
			}
			if !ReportMatches(local.Reports[vector.ID], vector.ExpectedScope, vector.ExpectedEffects, vector.ExpectedUnresolved) {
				t.Fatalf("scope differs: %#v", local.Reports[vector.ID])
			}
		})
	}
}

func TestPublicReviewScopeChecksCannotBeOmitted(t *testing.T) {
	want := map[string]ExpectedChecks{"release-within-authority": {Checks: []string{"release-window"}, Objects: []int{0, 1, 3, 4}}}
	expected := &ExpectedScope{Established: []string{"release-within-authority"}, Reasons: map[string]string{}, Checks: &want}
	for _, test := range []struct {
		name    string
		checks  []string
		objects []int
		met     bool
	}{
		{"valid order independent", []string{"release-window"}, []int{4, 3, 1, 0}, true},
		{"missing check", []string{}, []int{0, 1, 3, 4}, false},
		{"extra check", []string{"release-window", "current-status"}, []int{0, 1, 3, 4}, false},
		{"missing object", []string{"release-window"}, []int{0, 1, 3}, false},
		{"wrong object", []string{"release-window"}, []int{0, 1, 2, 4}, false},
		{"duplicate object", []string{"release-window"}, []int{0, 1, 3, 4, 4}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := &evidence.Report{Scope: evidence.ReportScope{Established: expected.Established, Reasons: map[string]string{}, Checks: map[string]evidence.ScopeItemChecks{"release-within-authority": {Checks: test.checks, Objects: test.objects}}}}
			if ReportMatches(report, expected, nil, nil) != test.met {
				t.Fatal(report.Scope)
			}
		})
	}
}

func TestPublicReviewLazyContextOrderingAndCompatibility(t *testing.T) {
	root := context().Root
	policy, err := loadPolicyFile(root, "conformance/suites/envelope/trust-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	load := func(name string) any {
		t.Helper()
		b, e := os.ReadFile(filepath.Join(root, "conformance/suites/repair-harness/repair-harness-envelope-"+name+".json"))
		if e != nil {
			t.Fatal(e)
		}
		var value any
		if e = json.Unmarshal(b, &value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	for _, name := range []string{"array", "media-before-time", "budget-before-payload", "missing-policy-and-time"} {
		calls := 0
		_, err := envelope.VerifyWithContext(load(name), policy.Keyring(), func(any) (envelope.Context, error) { calls++; return envelope.Context{}, errors.New("must not run") })
		if err == nil || calls != 0 {
			t.Fatalf("%s: %d calls, %v", name, calls, err)
		}
	}
	value := load("valid-control")
	payload, err := envelope.DecodeCanonicalJSONPayload(value.(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policy.VerificationContext(payload.(map[string]any)["issued_at"].(string), "ecl.time.issued-at.v1")
	if err != nil {
		t.Fatal(err)
	}
	direct, err := envelope.Verify(value, policy.Keyring(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	lazy, err := envelope.VerifyWithContext(value, policy.Keyring(), func(any) (envelope.Context, error) { return ctx, nil })
	if err != nil || !reflect.DeepEqual(direct, lazy) {
		t.Fatal(err)
	}
	_, err = envelope.VerifyWithContext(value, policy.Keyring(), func(any) (envelope.Context, error) { return envelope.Context{}, errors.New("context unavailable") })
	var refusal *envelope.Error
	if !errors.As(err, &refusal) || refusal.Code != envelope.SignaturePolicyInvalid {
		t.Fatal(err)
	}
}
