package evidence_test

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"testing"
)

func TestRegisterRequiredFlags(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "register-required-flags", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := strict.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range parsed.([]any) {
		entry := item.(map[string]any)
		t.Run(entry["id"].(string), func(t *testing.T) {
			register := entry["register"].(map[string]any)
			basis := entry["basis"].(map[string]any)
			basis["register"], err = evidence.RegisterReference(register)
			if err != nil {
				t.Fatal(err)
			}
			problems, err := evidence.RegisterProblems(basis, register, entry["action_class"])
			if err != nil {
				t.Fatal(err)
			}
			required := false
			for _, problem := range problems {
				if problem[0] != "/inputs/0/required" {
					t.Errorf("unrelated finding: %v", problem)
				}
				required = required || problem[0] == "/inputs/0/required"
			}
			if required != entry["required_problem"].(bool) {
				t.Errorf("required flag problem=%v, want %v", required, entry["required_problem"])
			}
		})
	}
}
