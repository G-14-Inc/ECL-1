package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// F06 (TP1-007): the command reports every refusal of a declared limit on one line with
// ecl.error.resource-limit-exceeded.v1 first, and exits 2; a file exactly at its limit is read.
func TestCommandLimitRefusalsNameTheRegisteredCode(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		file := filepath.Join(directory, name)
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	bundle := path("conformance/fixtures/evidence/succeeded.json")
	policy := path("conformance/fixtures/evidence/trust-policy.json")
	large := func(size int) []byte { return bytes.Repeat([]byte(" "), size) }
	deep := append(bytes.Repeat([]byte("["), 300), bytes.Repeat([]byte("]"), 300)...)
	prefix := "error: " + evidence.ResourceLimitExceeded + ": "
	for name, arguments := range map[string][]string{
		"bundle bytes":   {write("bundle.json", large(evidence.MaxBundleBytes+1)), "--trust-policy", policy},
		"bundle nesting": {write("deep.json", deep), "--trust-policy", policy},
		"policy bytes":   {bundle, "--trust-policy", write("policy.json", large(trust.MaxPolicyBytes+1))},
		"history bytes":  {bundle, "--trust-policy", policy, "--trust-policy-history", write("history.json", large(trust.MaxPolicyBytes+1))},
		"register bytes": {bundle, "--trust-policy", policy, "--register", write("register.json", large(evidence.MaxRegisterBytes+1))},
		"policy nesting": {bundle, "--trust-policy", write("deep-policy.json", deep)},
	} {
		var stdout, stderr bytes.Buffer
		status := run(append(arguments, "--now", "2026-10-01T00:00:00Z"), &stdout, &stderr)
		if status != 2 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), prefix) || strings.Count(stderr.String(), "\n") != 1 {
			t.Errorf("%s: %d %q %q", name, status, stdout.String(), stderr.String())
		}
	}
	at := append(large(evidence.MaxBundleBytes-2), "{}"...)
	var stdout, stderr bytes.Buffer
	status := run([]string{write("at-limit.json", at), "--trust-policy", policy, "--now", "2026-10-01T00:00:00Z"}, &stdout, &stderr)
	if status != 1 || stderr.Len() != 0 || !strings.HasPrefix(stdout.String(), "verdict: invalid") {
		t.Errorf("bundle at the limit: %d %q %q", status, stdout.String(), stderr.String())
	}
}

// EBMP2-076 and TP1-006: the text form names the checks behind each established item and every
// trust dependency.
func TestTextNamesChecksAndTrustDependencies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run([]string{path("conformance/fixtures/evidence/corroborated.json"), "--trust-policy", path("conformance/fixtures/evidence/trust-policy.json"), "--now", "2026-10-01T00:00:00Z"}, &stdout, &stderr)
	output := stdout.String()
	for _, line := range []string{
		"\nchecks envelope-signatures: envelope-integrity,time-not-after-evaluation,historical-signers,current-compromise-knowledge,trusted-time-countersignatures objects=0,1,2,3,4,5\n",
		"\ndependency 5: role=signer key=urn:example:key:bundle-observer counter=- at=",
	} {
		if status != 0 || !strings.Contains(output, line) {
			t.Errorf("%d missing %q in %q", status, line, output)
		}
	}
}
