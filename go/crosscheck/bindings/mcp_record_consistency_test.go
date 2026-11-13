package bindings

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"testing"
)

func TestMCPRecordConsistency(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "mcp-record-consistency")
	read := func(file string) []byte {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct {
		Cases []struct {
			ID, File           string
			Accepted           bool
			DirectAccepted     bool   `json:"direct_accepted"`
			SchemaValid        bool   `json:"schema_valid"`
			RequiredDirectRule string `json:"required_direct_rule"`
		}
	}
	if err := json.Unmarshal(read("manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			parsed, err := strict.Parse(read(item.File))
			if err != nil {
				t.Fatal(err)
			}
			value := parsed.(map[string]any)
			before, _ := json.Marshal(value)
			found, err := EvaluateRecord(MCPExchangeSchema, value)
			if err != nil {
				t.Fatal(err)
			}
			direct := checkMCP(value)
			schemaInvalid, requiredFound := false, false
			for _, finding := range found {
				if finding.RuleID == "ecl.error.schema-invalid.v1" {
					schemaInvalid = true
				}
			}
			for _, finding := range direct {
				if finding.RuleID == item.RequiredDirectRule {
					requiredFound = true
				}
			}
			if schemaInvalid == item.SchemaValid {
				t.Errorf("schema validity disagrees: %+v", found)
			}
			if !item.DirectAccepted && !requiredFound {
				t.Errorf("required diagnostic %s absent: %+v", item.RequiredDirectRule, direct)
			}
			if (len(found) == 0) != item.Accepted {
				t.Errorf("accepted=%v wanted=%v: %+v", len(found) == 0, item.Accepted, found)
			}
			if (len(direct) == 0) != item.DirectAccepted {
				t.Errorf("direct accepted=%v wanted=%v: %+v", len(direct) == 0, item.DirectAccepted, direct)
			}
			after, _ := json.Marshal(value)
			if string(before) != string(after) {
				t.Fatal("record checker mutated input")
			}
		})
	}
}
