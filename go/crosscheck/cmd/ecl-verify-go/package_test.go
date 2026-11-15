package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/offline"
)

func packageArguments(vector vectors.Vector, file string) []string {
	if file == "" {
		file = path(vector.Path)
	}
	arguments := []string{file, "--trust-policy", path(vector.TrustPolicyPath), "--now", vector.EvaluatedAt}
	for _, older := range vector.TrustPolicyHistory {
		arguments = append(arguments, "--trust-policy-history", path(older))
	}
	return arguments
}

func packageVector(t *testing.T, id string) vectors.Vector {
	t.Helper()
	for _, vector := range vectors.Suite(t, "offline-package").Vectors {
		if vector.ID == id {
			return vector
		}
	}
	t.Fatalf("no package vector %s", id)
	return vectors.Vector{}
}

// A file that begins with PK is an offline package (IE1-022): the command reports what
// offline.VerifyBytes reports, with the exit status of its verdict.
func TestEveryPackageVectorAsTheLibraryReportsIt(t *testing.T) {
	for _, vector := range vectors.Suite(t, "offline-package").Vectors {
		var stdout, stderr bytes.Buffer
		status := run(append(packageArguments(vector, ""), "--json"), &stdout, &stderr)
		var history [][]byte
		for _, older := range vector.TrustPolicyHistory {
			history = append(history, vectors.Read(t, older))
		}
		report, _, err := offline.VerifyBytes(vectors.Read(t, vector.Path), vectors.Read(t, vector.TrustPolicyPath), history, offline.Options{Options: evidence.Options{Now: vector.EvaluatedAt}})
		if err != nil {
			t.Fatal(vector.ID, err)
		}
		expected, err := canon.Marshal(report.JSON())
		if err != nil {
			t.Fatal(vector.ID, err)
		}
		if stdout.String() != string(expected)+"\n" || stderr.Len() != 0 {
			t.Errorf("%s: %q %q", vector.ID, stdout.String(), stderr.String())
		}
		if report.Verdict != vector.ExpectedVerdict || status != exits[vector.ExpectedVerdict] {
			t.Errorf("%s: verdict %s, status %d", vector.ID, report.Verdict, status)
		}
		var value map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
			t.Fatal(vector.ID, err)
		}
		primary, present := value["primary"]
		if !present || (vector.Primary == "" && primary != nil) || (vector.Primary != "" && primary != vector.Primary) {
			t.Errorf("%s: primary %v, want %s", vector.ID, primary, vector.Primary)
		}
		stdout.Reset()
		if textStatus := run(packageArguments(vector, ""), &stdout, &stderr); textStatus != status || strings.Contains(stdout.String(), "primary: "+vector.Primary+"\n") != (vector.Primary != "") {
			t.Errorf("%s: text primary differs: %s", vector.ID, stdout.String())
		}
	}
}

func TestPackageOutputAndDecisionBasisOptions(t *testing.T) {
	valid := packageVector(t, "package-valid-corroborated")
	register := path("conformance/suites/evidence-bundle/register-version-2.json")
	cases := []struct {
		arguments []string
		status    int
		contains  string
	}{
		{packageArguments(valid, ""), 0, "verdict: verified\n"},
		{packageArguments(valid, ""), 0, "established: decision-basis-recorded: "},
		{append(packageArguments(valid, ""), "--no-require-decision-basis"), 2, ""},
		{append(packageArguments(valid, ""), "--register", register), 1, "finding: ecl.rule.decision-basis-matches-register.v1: "},
		{packageArguments(packageVector(t, "package-invalid-entry-name-over-limit"), ""), 1, "finding: ecl.error.resource-limit-exceeded.v1: "},
		// Input that cannot be verified at all is a usage error, for a package as for a bundle.
		{append(packageArguments(valid, ""), "--now", "yesterday"), 2, ""},
		{append(packageArguments(valid, ""), "--trust-policy", path(valid.Path)), 2, ""},
	}
	for _, item := range cases {
		var stdout, stderr bytes.Buffer
		if status := run(item.arguments, &stdout, &stderr); status != item.status || !strings.Contains(stdout.String(), item.contains) {
			t.Errorf("%v: %d %q %q", item.arguments, status, stdout.String(), stderr.String())
		}
	}
}

func TestAFileThatDoesNotBeginWithPKIsReadAsABundle(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-json.zip")
	if err := os.WriteFile(file, []byte("P not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	status := run(packageArguments(packageVector(t, "package-valid-verified"), file), &stdout, &stderr)
	if status != 2 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "error: ecl.rule.json-strict-syntax.v1: malformed bundle JSON") {
		t.Fatalf("%d %q %q", status, stdout.String(), stderr.String())
	}
}
