package canonical

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInternalCanonicalIntegerProfile(t *testing.T) {
	for _, v := range []any{int64(9007199254740992), int64(-9007199254740992), uint64(9007199254740992), ^uint64(0), json.Number("9007199254740992"), json.Number("-9007199254740992"), json.Number("-0"), json.Number("01"), json.Number("-00"), json.Number("-"), json.Number("1e0"), json.Number("1.0"), json.Number("+1")} {
		if raw, err := Marshal(map[string]any{"n": v}); err == nil {
			t.Errorf("accepted %T: %s", v, raw)
		}
		if value, err := Digest(v); err == nil || value != "" {
			t.Errorf("digest for %T: %s %v", v, value, err)
		}
	}
	// A huge lexical integer does not get copied into an error message.
	if _, err := Marshal(json.Number(strings.Repeat("0", 100000))); err == nil || len(err.Error()) > 200 {
		t.Fatal(err)
	}
	for _, v := range []any{int(0), int8(-128), uint8(255), int16(-32768), uint16(65535), int32(-2147483648), uint32(4294967295), int64(9007199254740991), int64(-9007199254740991), uint64(9007199254740991), json.Number("0")} {
		if _, err := Marshal(v); err != nil {
			t.Errorf("refused valid %T: %v", v, err)
		}
	}
}

func TestInternalCanonicalScalarProfile(t *testing.T) {
	noncharacters := []rune{}
	for code := rune(0xFDD0); code <= 0xFDEF; code++ {
		noncharacters = append(noncharacters, code)
	}
	for plane := 0; plane <= 16; plane++ {
		noncharacters = append(noncharacters, rune(plane*0x10000+0xFFFE), rune(plane*0x10000+0xFFFF))
	}
	if len(noncharacters) != 66 {
		t.Fatal(len(noncharacters))
	}
	for _, code := range noncharacters {
		for _, v := range []any{string(code), map[string]any{string(code): 0}} {
			if _, err := Marshal(v); err == nil {
				t.Errorf("accepted U+%04X", code)
			}
		}
	}
	for _, code := range []rune{0, 0x1F, 0xFDCF, 0xFDF0, 0xFFFD, 0x1FFFD, 0x10FFFD, 0x1F680} {
		if _, err := Marshal(map[string]any{string(code): string(code)}); err != nil {
			t.Errorf("U+%04X: %v", code, err)
		}
	}
}

func TestInternalCanonicalExactBudgets(t *testing.T) {
	cases := []struct {
		value        any
		text         string
		nodes, depth int
	}{
		{nil, "null", 1, 0}, {false, "false", 1, 0}, {"\x00\n\\\"🚀", `"\u0000\n\\\"🚀"`, 1, 0},
		{[]any{}, "[]", 1, 0}, {map[string]any{}, "{}", 1, 0},
		{map[string]any{"a": []any{true, nil, json.Number("-12")}}, `{"a":[true,null,-12]}`, 5, 2},
	}
	for _, c := range cases {
		for _, offset := range []int{-1, 0, 1} {
			b := valueBudget{depthLimit: 256, nodeLimit: 1000000, byteLimit: len(c.text) + offset}
			err := b.visit(c.value, 0)
			if (err != nil) != (offset < 0) {
				t.Fatalf("%s offset %d: %v", c.text, offset, err)
			}
			if err == nil && (b.bytes != len(c.text) || b.nodes != c.nodes) {
				t.Fatalf("%s counted %+v", c.text, b)
			}
		}
		raw, err := Marshal(c.value)
		if err != nil || string(raw) != c.text {
			t.Fatalf("got %s %v, want %s", raw, err, c.text)
		}
		b := valueBudget{depthLimit: c.depth, nodeLimit: c.nodes, byteLimit: len(c.text)}
		if err := b.visit(c.value, 0); err != nil {
			t.Fatal(err)
		}
		b.nodes = 0
		b.bytes = 0
		b.nodeLimit = c.nodes - 1
		if err := b.visit(c.value, 0); err == nil {
			t.Fatal("node limit not enforced")
		}
	}
}

func TestInternalCanonicalCyclicValuesRefuseBoundedly(t *testing.T) {
	object := map[string]any{}
	object["self"] = object
	array := make([]any, 1)
	array[0] = array
	for _, v := range []any{object, array} {
		if _, err := Marshal(v); err == nil || !strings.Contains(err.Error(), resourceLimit) {
			t.Fatal(err)
		}
	}
}
