package strict_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func TestStrictJSONVectors(t *testing.T) {
	count := 0
	for _, name := range []string{"foundation", "strict-failure"} {
		for _, vector := range vectors.Suite(t, name).Vectors {
			if vector.Stage != "strict-json" {
				continue
			}
			count++
			limits := strict.DefaultLimits
			if declared := vector.StrictJSONLimits; declared != nil {
				limits = strict.Limits{MaxBytes: declared.MaxBytes, MaxDepth: declared.MaxDepth, MaxNodes: declared.MaxNodes}
			}
			_, err := strict.ParseLimited(vectors.Read(t, vector.Path), limits)
			var refusal *strict.Error
			switch {
			case vector.Expected == "pass" && err != nil:
				t.Errorf("%s: %v", vector.ID, err)
			case vector.Expected == "fail" && (!errors.As(err, &refusal) || refusal.RuleID != vector.Primary):
				t.Errorf("%s: %v", vector.ID, err)
			}
		}
	}
	if count == 0 {
		t.Fatal("no strict-json vectors")
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]string{
		`{"a":1,"a":2}`:      strict.RuleNoDuplicateMembers,
		`[1.5]`:              strict.RuleRestrictedNumbers,
		`[1e3]`:              strict.RuleRestrictedNumbers,
		`[-0]`:               strict.RuleRestrictedNumbers,
		`[9007199254740992]`: strict.RuleRestrictedNumbers,
		`["\ud800"]`:         strict.RuleStrictSyntax,
		`["\udfff"]`:         strict.RuleStrictSyntax,
		"[\"\xff\"]":         strict.RuleStrictSyntax,
		"[\"\xef\xbf\xbf\"]": strict.RuleStrictSyntax,
		`["\uffff"]`:         strict.RuleStrictSyntax,
		`["\ufdd0"]`:         strict.RuleStrictSyntax,
		`["\ud83f\udffe"]`:   strict.RuleStrictSyntax,
		"\xef\xbb\xbf{}":     strict.RuleStrictSyntax,
		`[NaN]`:              strict.RuleStrictSyntax,
		`[1,]`:               strict.RuleStrictSyntax,
		`[1] [2]`:            strict.RuleStrictSyntax,
		`[01]`:               strict.RuleStrictSyntax,
		// The order of IE1-037, whatever the position of each defect in the text.
		`{"a":1.5,"a":1}`:        strict.RuleNoDuplicateMembers,
		`{"a":"\ud800","a":"x"}`: strict.RuleStrictSyntax,
		`{"a":1,"a":2`:           strict.RuleStrictSyntax,
		strings.Repeat("[", 200): strict.RuleStrictSyntax,
		// The declared nesting limit is 256 levels, counted from 0.
		strings.Repeat("[", 258) + strings.Repeat("]", 258):     strict.ResourceLimitExceeded,
		strings.Repeat("[", 20000) + strings.Repeat("]", 20000): strict.ResourceLimitExceeded,
	}
	for input, rule := range cases {
		_, err := strict.Parse([]byte(input))
		var refusal *strict.Error
		if !errors.As(err, &refusal) || refusal.RuleID != rule {
			t.Errorf("%.20q: %v", input, err)
		}
	}
	for _, input := range []string{`["\ud83d\ude00"]`, `["\ue000"]`, `[9007199254740991]`, `{"a":{"a":1}}`, strings.Repeat("[", 257) + strings.Repeat("]", 257)} {
		if _, err := strict.Parse([]byte(input)); err != nil {
			t.Errorf("%q: %v", input, err)
		}
	}
}

func ExampleParse() {
	_, err := strict.Parse([]byte(`{"amount": 1.5}`))
	fmt.Println(err)
	value, _ := strict.Parse([]byte(`{"amount": 15}`))
	fmt.Printf("%v\n", value)
	// Output:
	// ecl.rule.json-restricted-numbers.v1 at /amount: floating-point and exponent forms are prohibited
	// map[amount:15]
}

// The declared limits of IE1-028: every limit is at least 1 and at most what the imported core
// applies, and a parse under other limits is refused, before the input is read, as a limit.
func TestLimitsAreCheckedBeforeTheInput(t *testing.T) {
	for _, limits := range []strict.Limits{
		{MaxBytes: 0, MaxDepth: 4, MaxNodes: 8},
		{MaxBytes: 64, MaxDepth: -1, MaxNodes: 8},
		{MaxBytes: 64, MaxDepth: 4, MaxNodes: 0},
		{MaxBytes: strict.MaxBytesCeiling + 1, MaxDepth: 4, MaxNodes: 8},
		{MaxBytes: 64, MaxDepth: strict.MaxDepthCeiling + 1, MaxNodes: 8},
		{MaxBytes: 64, MaxDepth: 4, MaxNodes: strict.MaxNodesCeiling + 1},
		{},
	} {
		for _, input := range []string{`[0,1,2]`, "[[[[", "[\"\xff\"]"} {
			_, err := strict.ParseLimited([]byte(input), limits)
			var refusal *strict.Error
			if !errors.As(err, &refusal) || refusal.RuleID != strict.ConfigurationInvalid || !strings.Contains(refusal.Reason, "the limit") {
				t.Errorf("%+v %q: %v", limits, input, err)
			}
		}
	}
	if _, err := strict.ParseLimited([]byte(`[0,1,2]`), strict.DefaultLimits); err != nil {
		t.Error(err)
	}
	// The declared defaults, the ceilings as admissible limits, and an input nested
	// to the ceiling, which the repository's own builder makes.
	if strict.DefaultLimits != (strict.Limits{MaxBytes: 16 * 1024 * 1024, MaxDepth: 256, MaxNodes: 1_000_000}) || strict.Ceilings != (strict.Limits{MaxBytes: 2_147_483_647, MaxDepth: 4_096, MaxNodes: 100_000_000}) {
		t.Fatalf("%+v %+v", strict.DefaultLimits, strict.Ceilings)
	}
	if _, err := strict.ParseLimited([]byte(`[0,1,2]`), strict.Ceilings); err != nil {
		t.Error(err)
	}
	if _, err := strict.ParseLimited([]byte(nested(4_097, "")), strict.Limits{MaxBytes: 64 * 1024, MaxDepth: 4_096, MaxNodes: 5_000}); err != nil {
		t.Error(err)
	}
	_, err := strict.ParseLimited([]byte(nested(4_098, "")), strict.Limits{MaxBytes: 64 * 1024, MaxDepth: 4_096, MaxNodes: 5_000})
	var refusal *strict.Error
	if !errors.As(err, &refusal) || refusal.RuleID != strict.ResourceLimitExceeded {
		t.Errorf("one level beyond the ceiling: %v", err)
	}
	// A configured limit read from JSON: exact positive integers within the ceiling only.
	for _, value := range []any{json.Number("250"), 250, int64(250)} {
		if limit, err := strict.LimitFromJSON("MaxDepth", value); err != nil || limit != 250 {
			t.Errorf("%v: %v %d", value, err, limit)
		}
	}
	for _, value := range []any{nil, json.Number("1.5"), json.Number("1e2"), json.Number("0"), json.Number("-1"), json.Number("4097"), json.Number("10000000000000000000000000000000"), 1.5, "250", true, json.Number("9007199254740992")} {
		_, err := strict.LimitFromJSON("MaxDepth", value)
		if !errors.As(err, &refusal) || refusal.RuleID != strict.ConfigurationInvalid {
			t.Errorf("%v: %v", value, err)
		}
	}
}

func flatArray(count int, tail string) string {
	return "[" + strings.Repeat("0,", count-1) + "0" + tail + "]"
}

func nested(depth int, tail string) string {
	return strings.Repeat("[", depth) + strings.Repeat("]", depth) + tail
}

// The order of IE1-037 under small declared limits: the grammar (check 2) before the limits
// (check 3) wherever each defect lies, as the Python verifier's packages/ecl-verify/tests/test_strict_json_limits.py has it.
func TestTheGrammarComesBeforeTheLimits(t *testing.T) {
	limits := func(maxBytes, maxDepth, maxNodes int) strict.Limits {
		return strict.Limits{MaxBytes: maxBytes, MaxDepth: maxDepth, MaxNodes: maxNodes}
	}
	cases := []struct {
		input  string
		limits strict.Limits
		rule   string
	}{
		{flatArray(20, ""), limits(4096, 8, 8), strict.ResourceLimitExceeded},
		{flatArray(20, ","), limits(4096, 8, 8), strict.RuleStrictSyntax},
		{`[0,0,0,0,0,0,0,0,0,0] x`, limits(4096, 8, 8), strict.RuleStrictSyntax},
		{`[[[[[[]]]]]]`, limits(4096, 4, 100), strict.ResourceLimitExceeded},
		{`[[[[[[]]]]]]]`, limits(4096, 4, 100), strict.RuleStrictSyntax},
		{`[[[[[[`, limits(4096, 4, 100), strict.RuleStrictSyntax},
		{`[1.5,"￿",{"a":1,"a":2},0,0,0,0,0,0,0]`, limits(4096, 8, 8), strict.ResourceLimitExceeded},
		{"[0,0,0,0,0,0,0,0,0,\"\xff\"]", limits(4096, 8, 8), strict.RuleStrictSyntax},
		{`[0,0,0,0,0,0,0,0,0,NaN]`, limits(4096, 8, 8), strict.RuleStrictSyntax},
		{flatArray(8, ""), limits(4096, 8, 9), ""},
		{`[[[[[]]]]]`, limits(4096, 4, 100), ""},
		{nested(40, "x"), limits(16, 8, 100), strict.ResourceLimitExceeded},
		{`{"a":1.5,"a":"\ud800"}`, strict.DefaultLimits, strict.RuleStrictSyntax},
		{`{"a":1.5,"a":2}`, strict.DefaultLimits, strict.RuleNoDuplicateMembers},
		{`{"a":1,"a":2}`, strict.DefaultLimits, strict.RuleNoDuplicateMembers},
		{`{"😀":1,"😀":2}`, strict.DefaultLimits, strict.RuleNoDuplicateMembers},
		{`{"\ud800":1,"\ud801":2}`, strict.DefaultLimits, strict.RuleStrictSyntax},
		{`[1.5,-0,{"b":1}]`, strict.DefaultLimits, strict.RuleRestrictedNumbers},
		{nested(strict.GrammarNestingBound+1, "x"), strict.DefaultLimits, strict.RuleStrictSyntax},
		{nested(strict.GrammarNestingBound+2, "x"), strict.DefaultLimits, strict.ResourceLimitExceeded},
		{nested(strict.GrammarNestingBound+2, ""), strict.DefaultLimits, strict.ResourceLimitExceeded},
	}
	for _, item := range cases {
		_, err := strict.ParseLimited([]byte(item.input), item.limits)
		var refusal *strict.Error
		switch {
		case item.rule == "" && err != nil:
			t.Errorf("%.40q %+v: %v", item.input, item.limits, err)
		case item.rule != "" && (!errors.As(err, &refusal) || refusal.RuleID != item.rule):
			t.Errorf("%.40q %+v: %v, want %s", item.input, item.limits, err, item.rule)
		}
	}
}

// IE1-029: a refusal under a small value limit allocates a constant amount, whatever the input
// (500,000 values under a limit of 8).
func TestARefusalDoesNotBuildTheInput(t *testing.T) {
	limits := strict.Limits{MaxBytes: strict.MaxInputBytes, MaxDepth: strict.MaxDepth, MaxNodes: 8}
	for _, data := range [][]byte{[]byte(flatArray(500_000, "")), []byte(flatArray(500_000, ","))} {
		allocated := testing.AllocsPerRun(3, func() { _, _ = strict.ParseLimited(data, limits) })
		if allocated > 64 {
			t.Errorf("%d allocations for a refusal of %d bytes", int(allocated), len(data))
		}
	}
}
