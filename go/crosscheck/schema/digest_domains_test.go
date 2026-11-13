package schema_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"os"
	"testing"
)

func TestDigestDomains(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/schema-digest-domains.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID     string `json:"id"`
		Schema string `json:"schema"`
		Value  any    `json:"value"`
		Valid  bool   `json:"valid"`
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			valid, err := schema.ECL().Valid(c.Schema, c.Value)
			if err != nil || valid != c.Valid {
				t.Errorf("valid=%v want=%v err=%v", valid, c.Valid, err)
			}
		})
	}
}
