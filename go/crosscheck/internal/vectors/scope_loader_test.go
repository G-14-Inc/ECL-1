package vectors

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestScopeSupportingChecksSurviveVectorLoading(t *testing.T) {
	for _, checks := range []string{"{}", `{"release-within-authority":{"checks":["release-window","authority-link"],"objects":[0,2]}}`} {
		t.Run(checks, func(t *testing.T) {
			raw := []byte(`{"expected_scope":{"established":[],"not_established":[],"reasons":{},"checks":` + checks + `}}`)
			var vector Vector
			if err := json.Unmarshal(raw, &vector); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(vector.ExpectedScope)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			var expected any
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(checks), &expected); err != nil {
				t.Fatal(err)
			}
			if value, present := got["checks"]; !present || !reflect.DeepEqual(value, expected) {
				t.Fatalf("supporting checks lost or changed: %s", encoded)
			}
		})
	}
	var vector Vector
	if err := json.Unmarshal([]byte(`{"expected_scope":{"established":[],"not_established":[],"reasons":{}}}`), &vector); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(vector.ExpectedScope)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(encoded, &got)
	if _, present := got["checks"]; present {
		t.Fatal("an omitted checks expectation became mandatory")
	}
}
