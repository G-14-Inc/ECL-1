package schema_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"os"
	"testing"
)

func TestSchemaConstructorDomains(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/schema-constructor-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []map[string]any
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c["id"].(string), func(t *testing.T) {
			want := c["build"].(bool)
			if own, ok := c["go_build"].(bool); ok {
				want = own
			}
			set, err := schema.NewSet(map[string]any{"urn:case": c["schema"]})
			if (err == nil) != want {
				t.Fatalf("build error=%v, expected build=%v", err, want)
			}
			if err == nil {
				if expected, has := c["valid"].(bool); has {
					got, err := set.Valid("urn:case", c["instance"])
					if err != nil || got != expected {
						t.Errorf("valid=%v err=%v, expected %v", got, err, expected)
					}
				}
			}
		})
	}
}
