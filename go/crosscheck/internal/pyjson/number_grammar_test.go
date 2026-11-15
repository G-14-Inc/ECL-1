package pyjson

import (
	"encoding/json"
	"testing"
)

func TestNumberGrammar(t *testing.T) {
	for _, s := range []string{"+10", "010", "01.0", "1/2", "0x10", "1_000", ".5", "1.", " 1", "1 ", "NaN", "Inf", "", "1e"} {
		t.Run("invalid-"+s, func(t *testing.T) {
			if _, ok := Number(json.Number(s)); ok {
				t.Errorf("accepted non-JSON number %q", s)
			}
			if _, ok := Int(json.Number(s)); ok {
				t.Errorf("accepted non-JSON integer %q", s)
			}
		})
	}
	for _, s := range []string{"0", "-0", "1", "-10", "1.5", "1e2", "1E-2", "-1.25e+3"} {
		t.Run("valid-"+s, func(t *testing.T) {
			if _, ok := Number(json.Number(s)); !ok {
				t.Errorf("refused JSON number %q", s)
			}
		})
	}
	for _, s := range []string{"0", "-0", "1", "-10", "9007199254740991"} {
		if _, ok := Int(json.Number(s)); !ok {
			t.Errorf("refused JSON integer %q", s)
		}
	}
	for _, s := range []string{"1.0", "1e2", "1E-2"} {
		if _, ok := Int(json.Number(s)); ok {
			t.Errorf("accepted fraction/exponent as lexical integer %q", s)
		}
	}
}
