package bindings

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestMCPRecoveryReasonPriority(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "tests/fixtures/mcp-recovery-reason-priority/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID          string   `json:"id"`
			Path        string   `json:"path"`
			SHA256      string   `json:"sha256"`
			Accepted    bool     `json:"accepted"`
			SchemaValid bool     `json:"schema_valid"`
			Rules       []string `json:"expected_rules"`
			State       string   `json:"expected_state"`
			Paths       []string `json:"required_finding_paths"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, item.Path))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != item.SHA256 {
				t.Fatal("fixture hash mismatch")
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			var value map[string]any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if member(value, "terminal", "event", "state") != item.State {
				t.Fatal("fixture state mismatch")
			}
			found, err := EvaluateRecord(manifest.Schema, value)
			if err != nil {
				t.Fatal(err)
			}
			rules := []string{}
			for _, finding := range found {
				rules = append(rules, finding.RuleID)
			}
			slices.Sort(rules)
			rules = slices.Compact(rules)
			if (!slices.Contains(rules, "ecl.error.schema-invalid.v1")) != item.SchemaValid {
				t.Fatalf("schema mismatch: %+v", found)
			}
			if !slices.Equal(rules, item.Rules) {
				t.Fatalf("want rules=%v; got %+v", item.Rules, found)
			}
			if (len(found) == 0) != item.Accepted {
				t.Fatalf("want accepted=%v; got %+v", item.Accepted, found)
			}
			for _, required := range item.Paths {
				matched := false
				for _, finding := range found {
					if finding.Path == required {
						matched = true
					}
				}
				if !matched {
					t.Fatalf("missing finding path %q: %+v", required, found)
				}
			}
			after, err := json.Marshal(value)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("record mutated")
			}
		})
	}
}
