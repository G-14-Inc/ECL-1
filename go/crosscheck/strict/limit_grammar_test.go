package strict_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"testing"
)

func TestLimitNumberGrammar(t *testing.T) {
	for _, s := range []string{"+10", "010", "00", "1/2", "1.0", "1e1", " 10", "10 ", "0", "-1", "999999999999999999999999"} {
		t.Run("invalid-"+s, func(t *testing.T) {
			if _, err := strict.LimitFromJSON("MaxDepth", json.Number(s)); err == nil {
				t.Errorf("accepted invalid limit %q", s)
			}
		})
	}
	for _, s := range []string{"1", "10", "4096"} {
		t.Run("valid-"+s, func(t *testing.T) {
			if _, err := strict.LimitFromJSON("MaxDepth", json.Number(s)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
