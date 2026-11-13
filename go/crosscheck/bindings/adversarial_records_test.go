package bindings

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestAdversarialBindingRecords(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "adversarial-bindings")
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			ID, File, Schema string
			Rules            []string `json:"expected_rules"`
		}
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, item.File))
			if err != nil {
				t.Fatal(err)
			}
			record, err := strict.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := EvaluateRecord(item.Schema, record)
			if err != nil {
				t.Fatal(err)
			}
			unique := map[string]bool{}
			for _, finding := range findings {
				unique[finding.RuleID] = true
			}
			rules := []string{}
			for rule := range unique {
				rules = append(rules, rule)
			}
			sort.Strings(rules)
			if !reflect.DeepEqual(rules, item.Rules) {
				t.Fatalf("got %v want %v: %v", rules, item.Rules, findings)
			}
		})
	}
}
