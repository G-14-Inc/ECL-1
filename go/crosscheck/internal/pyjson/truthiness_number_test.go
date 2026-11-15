package pyjson

import (
	"encoding/json"
	"testing"
)

func TestJSONNumberTruthinessWithoutRationalExpansion(t *testing.T) {
	for literal, want := range map[string]bool{
		"0": false, "-0": false, "0.0": false, "-0.0e-4301": false, "0e4301": false,
		"1e4301": true, "1e-4301": true, "-1.5": true, "1/2": true, "01": true,
	} {
		if got := Truthy(json.Number(literal)); got != want {
			t.Errorf("%s:got%v,want%v", literal, got, want)
		}
	}
}
