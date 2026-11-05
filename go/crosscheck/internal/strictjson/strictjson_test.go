package strictjson

import (
	"errors"
	"testing"
)

func TestParseAcceptsRestrictedJSON(t *testing.T) {
	value, err := Parse([]byte(`{"safe":9007199254740991,"nested":[true,null,"\uD83D\uDE80"]}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if value == nil {
		t.Fatal("Parse() returned nil")
	}
}

func TestParseRejectsDuplicateAtAnyDepth(t *testing.T) {
	_, err := Parse([]byte(`{"outer":{"x":1,"x":2}}`))
	assertRule(t, err, RuleNoDuplicateMembers)
}

func TestParseRejectsRestrictedNumbers(t *testing.T) {
	cases := []string{
		`{"n":1.25}`,
		`{"n":1e2}`,
		`{"n":-0}`,
		`{"n":9007199254740992}`,
		`{"n":-9007199254740992}`,
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			_, err := Parse([]byte(input))
			assertRule(t, err, RuleRestrictedNumbers)
		})
	}
}

func TestParseRejectsInvalidUnicode(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"x":"\uD800"}`),
		[]byte(`{"x":"\uDC00"}`),
		{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	}
	for _, input := range cases {
		_, err := Parse(input)
		assertRule(t, err, RuleRestrictedUnicode)
	}
}

func TestParseRejectsTrailingValue(t *testing.T) {
	_, err := Parse([]byte(`{} {}`))
	assertRule(t, err, RuleSyntaxValid)
}

func assertRule(t *testing.T, err error, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Parse() unexpectedly succeeded; want %s", rule)
	}
	var strictErr *Error
	if !errors.As(err, &strictErr) {
		t.Fatalf("Parse() error type = %T; want *Error", err)
	}
	if strictErr.RuleID != rule {
		t.Fatalf("RuleID = %q; want %q (error: %v)", strictErr.RuleID, rule, err)
	}
}
