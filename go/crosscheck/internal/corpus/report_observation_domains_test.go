// Replay comparisons retain exact action identifiers. Robert F. Tilley Jr.; G-14, Inc.
package corpus

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"testing"
)

func TestReportEffectIdentifierDomains(t *testing.T) {
	for _, c := range []struct {
		name, text string
		met        bool
	}{
		{"empty", "", false}, {"space", " ", false}, {"ascii", "\t\n\r\v\f", false},
		{"next-line", "\u0085", false}, {"nbsp", "\u00a0", false}, {"ogham", "\u1680", false},
		{"spaces", "\u2000\u200a", false}, {"separators", "\u2028\u2029", false}, {"narrow-medium-ideographic", "\u202f\u205f\u3000", false},
		{"token", "custom-token", true}, {"spacing", " token ", true}, {"bom-not-whitespace", "\ufeff", true}, {"control-not-whitespace", "\x1c", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			report := &evidence.Report{Effects: []evidence.EffectEvidence{{ActionID: "control", Level: "none"}, {ActionID: c.text, Level: "none"}}}
			want := []ExpectedEffect{{ActionID: "control", Level: "none"}}
			if ReportMatches(report, nil, want, nil) != c.met {
				t.Fatalf("unexpected comparison for %q", c.text)
			}
			if report.Effects[1].ActionID != c.text {
				t.Fatal("identity changed")
			}
		})
	}
}
func TestReportNoEffectExpectationIsUnchanged(t *testing.T) {
	if !ReportMatches(nil, nil, nil, nil) {
		t.Fatal("invented expectation")
	}
}

func TestReportEmptyEffectExpectationChecksRetainedActionNames(t *testing.T) {
	report := &evidence.Report{Effects: []evidence.EffectEvidence{{ActionID: "   ", Level: "none"}}}
	if ReportMatches(report, nil, []ExpectedEffect{}, nil) {
		t.Fatal("blank extra action accepted")
	}
	if !ReportMatches(&evidence.Report{}, nil, []ExpectedEffect{}, nil) {
		t.Fatal("empty observation rejected")
	}
}
