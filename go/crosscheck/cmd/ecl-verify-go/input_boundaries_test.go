package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyRegisterAndPositionalOperandsAreNotIgnored(t *testing.T) {
	base := []string{path("conformance/suites/evidence-bundle/bundle-valid-decision-basis-matches-register.json"),
		"--trust-policy", path("conformance/suites/evidence-bundle/trust-policy.json"), "--now", "2026-10-01T00:00:00Z", "--json"}
	cases := [][]string{
		append(append([]string{}, base...), "--register", ""),
		append(append([]string{}, base...), "--register", path("conformance/suites/evidence-bundle/register-version-2.json"), "--register", ""),
		append([]string{""}, base...),
	}
	for _, arguments := range cases {
		var stdout, stderr bytes.Buffer
		if status := run(arguments, &stdout, &stderr); status != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%q: status=%d stdout=%q stderr=%q", arguments, status, stdout.String(), stderr.String())
		}
	}
}

func TestUntrustedZIPNamesHaveJSONRefusalReports(t *testing.T) {
	var fixtures struct {
		Cases []struct {
			ID         string `json:"id"`
			ArchiveHex string `json:"archive_hex"`
			Primary    string `json:"primary"`
		} `json:"cases"`
	}
	data, err := os.ReadFile(path("tests/fixtures/offline-cli-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixtures.Cases {
		t.Run(item.ID, func(t *testing.T) {
			data, err := hex.DecodeString(item.ArchiveHex)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "input.zip")
			if err = os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			status := run([]string{file, "--trust-policy", path("conformance/suites/offline-package/trust-policy.json"),
				"--now", "2026-10-01T00:00:00Z", "--json"}, &stdout, &stderr)
			if status != 1 || stderr.Len() != 0 {
				t.Fatalf("status=%d stderr=%q", status, stderr.String())
			}
			var report map[string]any
			if err = json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report["verdict"] != "invalid" || report["primary"] != item.Primary {
				t.Fatal(report)
			}
			if len(report["scope"].(map[string]any)["established"].([]any)) != 0 {
				t.Fatal(report)
			}
		})
	}
}
