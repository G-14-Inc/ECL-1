package schema_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"testing"
)

func TestUntypedNumberBoundsUnaffected(t *testing.T) {
	const id = "urn:example:schema:untyped-maximum"
	set, err := schema.NewSet(map[string]any{id: map[string]any{"$id": id, "maximum": json.Number("1")}})
	if err != nil {
		t.Fatal(err)
	}
	// A small bounded exponent just outside SchemaInt's new fallback budget is
	// still a number for the existing generic JSON Schema comparison API.
	for _, c := range []struct {
		value any
		want  bool
	}{{json.Number("1e4301"), false}, {json.Number("0.5"), true}, {true, true}} {
		got, err := set.Valid(id, c.value)
		if err != nil || got != c.want {
			t.Errorf("%T number bound: got%v err%v want%v", c.value, got, err, c.want)
		}
	}
}
