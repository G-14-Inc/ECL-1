package pyjson

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestSchemaIntegerHostRepresentations(t *testing.T) {
	for _, value := range []any{int(1), int64(1), float64(1), json.Number("1"), json.Number("1.0"), json.Number("1e0")} {
		if got, ok := SchemaInt(value); !ok || got != 1 {
			t.Errorf("%T(%v): %v %v", value, value, got, ok)
		}
	}
	for _, value := range []any{true, false, 1.5, math.NaN(), math.Inf(1), math.Inf(-1), float64(9007199254740992), "1", nil} {
		if _, ok := SchemaInt(value); ok {
			t.Errorf("accepted %T(%v)", value, value)
		}
	}
	for _, value := range []float64{0, math.Copysign(0, -1), -1, 9007199254740991} {
		if got, ok := SchemaInt(value); !ok || got != int64(value) {
			t.Errorf("refused bounded whole float: %v", value)
		}
	}
	if _, ok := Int(float64(1)); ok {
		t.Fatal("changed exact Int host contract")
	}
	if got, ok := PythonInt(true); !ok || got != 1 {
		t.Fatal("changed PythonInt boolean contract")
	}
}

func TestSchemaIntegerRationalFallbackBudget(t *testing.T) {
	for _, literal := range []string{"1e4301", "1e-4301", strings.Repeat("1", 4301)} {
		if _, ok := SchemaInt(json.Number(literal)); ok {
			t.Errorf("accepted representation outside host budget: length %d", len(literal))
		}
	}
	for _, literal := range []string{"1e4300", "1e-4300", strings.Repeat("1", 4300), "1.5", "1e-3"} {
		if !boundedNumberLiteral(literal) {
			t.Errorf("refused representation inside host budget: length %d", len(literal))
		}
	}
}

func TestSchemaIntegerExactRationalIntegrality(t *testing.T) {
	for literal, want := range map[string]int64{"100e-2": 1, "0e4300": 0, "-0.0": 0, "-100e-2": -1} {
		if got, ok := SchemaInt(json.Number(literal)); !ok || got != want {
			t.Errorf("%s: %d %v", literal, got, ok)
		}
	}
	if _, ok := SchemaInt(json.Number("1.5")); ok {
		t.Fatal("fractional exact ratio read as integer")
	}
}
