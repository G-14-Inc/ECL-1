package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func path(name string) string {
	return filepath.Join(vectors.Root(), filepath.FromSlash(name))
}

func TestExitStatusesAndOutput(t *testing.T) {
	suite := "conformance/suites/evidence-bundle/"
	cases := []struct {
		arguments []string
		status    int
		contains  string
	}{
		{[]string{path("conformance/fixtures/evidence/succeeded.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, 0, "verdict: verified"},
		{[]string{path("conformance/fixtures/evidence/tampered.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, 1, "verdict: invalid"},
		{[]string{path(suite + "bundle-incomplete-no-terminal.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, 3, "causal: incomplete"},
		{[]string{path(suite + "bundle-current-trust-failed-revoked-after-use.json"), "--trust-policy", path(suite + "trust-policy-revoked-after-use.json"), "--trust-policy-history", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, 4, "current=ecl.error.revoked.v1"},
		{[]string{path(suite + "bundle-current-trust-failed-revoked-after-use.json"), "--trust-policy", path(suite + "trust-policy-revoked-after-use.json"), "--trust-policy-history", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--accept-current-trust-failure"}, 0, "accepted: current trust failure"},
		{[]string{path("conformance/fixtures/evidence/succeeded.json")}, 2, ""},
		{[]string{path("conformance/fixtures/evidence/succeeded.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "yesterday"}, 2, ""},
		{[]string{path("conformance/fixtures/evidence/succeeded.json"), "--trust-policy", path("conformance/fixtures/evidence/succeeded.json")}, 2, ""},
		// DCMP2-053: the decision basis is required of every decision response; the option that once
		// waived it is a usage error.
		{[]string{path("conformance/fixtures/evidence/succeeded.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, 0, "established: decision-basis-recorded: "},
		{[]string{path(suite + "bundle-invalid-missing-decision-basis.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, 1, "ecl.rule.decision-basis-required.v1"},
		{[]string{path(suite + "bundle-invalid-missing-decision-basis.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--no-require-decision-basis"}, 2, ""},
		{[]string{path(suite + "bundle-valid-decision-basis-matches-register.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--register", path(suite + "register.json")}, 0, "\ndecision-basis register: urn:example:register:bundle sha256:"},
		// Without a register, the command says what it did not check.
		{[]string{path(suite + "bundle-valid-decision-basis-matches-register.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, 0, "\ndecision-basis register: none; declared classes not checked against a register\n"},
		{[]string{path(suite + "bundle-valid-decision-basis-matches-register.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--register", path(suite + "register-version-2.json")}, 1, "ecl.rule.decision-basis-matches-register.v1"},
		{[]string{path(suite + "bundle-valid-decision-basis-matches-register.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--register", path(suite + "trust-policy.json")}, 2, ""},
		{[]string{path(suite + "bundle-valid-decision-basis-matches-register.json"), "--trust-policy", path(suite + "trust-policy.json"), "--register"}, 2, ""},
	}
	for _, item := range cases {
		var stdout, stderr bytes.Buffer
		if status := run(item.arguments, &stdout, &stderr); status != item.status || !strings.Contains(stdout.String(), item.contains) {
			t.Errorf("%v: %d %q %q", item.arguments, status, stdout.String(), stderr.String())
		}
	}
}

func TestExplicitEmptyEvaluationTimeIsAUsageError(t *testing.T) {
	for _, flags := range [][]string{
		{"--now", ""},
		{"--now", "2026-10-01T00:00:00Z", "--now", ""},
	} {
		arguments := []string{path("conformance/fixtures/evidence/succeeded.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--json"}
		var stdout, stderr bytes.Buffer
		status := run(append(arguments, flags...), &stdout, &stderr)
		if status != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid evaluation time") {
			t.Errorf("%v: status %d, stdout %q, stderr %q", flags, status, stdout.String(), stderr.String())
		}
	}
}

// EBMP2-076: the text form puts the items the verdict does not establish right after the verdict,
// then the items the verifier checked, then the rest of the report.
func TestScopeComesWithTheVerdict(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run([]string{path("conformance/fixtures/evidence/succeeded.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, &stdout, &stderr)
	output := stdout.String()
	if status != 0 || !strings.HasPrefix(output, "verdict: verified\nnot-established: trusted-time: ") {
		t.Fatalf("%d %q %q", status, output, stderr.String())
	}
	notEstablished := strings.Index(output, "\nnot-established: recorded-times-true: ")
	established := strings.Index(output, "\nestablished: envelope-signatures: ")
	profile := strings.Index(output, "\nverification-profile: ")
	if notEstablished < 0 || established < notEstablished || profile < established {
		t.Fatal(output)
	}
	stdout.Reset()
	status = run([]string{path("conformance/fixtures/evidence/tampered.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, &stdout, &stderr)
	if status != 1 || !strings.HasPrefix(stdout.String(), "verdict: invalid\nprimary: ecl.error.signature-policy-invalid.v1\nnot-established: envelope-signatures: ") || strings.Contains(stdout.String(), "\nestablished: ") {
		t.Fatal(stdout.String())
	}
}

// DCMP2-053: a register that breaks the register declarations rule is a usage error.
func TestRegisterThatBreaksTheRegisterRule(t *testing.T) {
	suite := "conformance/suites/evidence-bundle/"
	var stdout, stderr bytes.Buffer
	status := run([]string{path(suite + "bundle-valid-decision-basis-matches-register.json"), "--trust-policy", path(suite + "trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--register", path("conformance/suites/document-coverage/register-invalid-action-class-declared-twice.json")}, &stdout, &stderr)
	if status != 2 || !strings.Contains(stderr.String(), "malformed register: the register breaks ecl.rule.register-declarations-consistent.v1: /entries/1/action_class_id") {
		t.Fatalf("%d %q %q", status, stdout.String(), stderr.String())
	}
}

func TestJSONIsCanonical(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run([]string{path("conformance/fixtures/evidence/corroborated.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--json"}, &stdout, &stderr)
	if status != 0 {
		t.Fatal(stderr.String())
	}
	value, err := strict.Parse(bytes.TrimSuffix(stdout.Bytes(), []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	if value.(map[string]any)["verdict"] != "verified" || !strings.HasPrefix(stdout.String(), `{"accepted_current_trust_failure":false,`) {
		t.Fatal(stdout.String())
	}
}

func TestJSONPrimaryMatchesDecidedBundleFinding(t *testing.T) {
	ids := map[string]bool{
		"bundle-incomplete-no-terminal":                 true,
		"bundle-current-trust-failed-revoked-after-use": true,
		"bundle-current-trust-failed-order":             true,
		"bundle-invalid-missing-decision-basis":         true,
		"bundle-valid-succeeded":                        true,
	}
	for _, vector := range vectors.Suite(t, "evidence-bundle").Vectors {
		if !ids[vector.ID] {
			continue
		}
		arguments := packageArguments(vector, "")
		var stdout, stderr bytes.Buffer
		status := run(append(arguments, "--json"), &stdout, &stderr)
		var value map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
			t.Fatal(vector.ID, err)
		}
		primary, present := value["primary"]
		if !present || (vector.Primary == "" && primary != nil) || (vector.Primary != "" && primary != vector.Primary) || status != exits[vector.ExpectedVerdict] {
			t.Fatalf("%s: status %d, primary %v, want %s", vector.ID, status, primary, vector.Primary)
		}
		stdout.Reset()
		if run(arguments, &stdout, &stderr) != status || strings.Contains(stdout.String(), "primary: "+vector.Primary+"\n") != (vector.Primary != "") {
			t.Fatal(vector.ID, stdout.String())
		}
		if vector.ID == "bundle-current-trust-failed-revoked-after-use" {
			stdout.Reset()
			if run(append(arguments, "--accept-current-trust-failure", "--json"), &stdout, &stderr) != 0 {
				t.Fatal(stderr.String())
			}
			if err := json.Unmarshal(stdout.Bytes(), &value); err != nil || value["primary"] != nil || value["accepted_current_trust_failure"] != true {
				t.Fatal(stdout.String(), err)
			}
		}
	}
}
