package bindings

import (
	"encoding/json"
	"errors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"testing"
)

func TestSingleUseCapability(t *testing.T) {
	root := os.Getenv("ECL_CAPABILITY_FIXTURES")
	if root == "" {
		root = filepath.Join("..", "..", "..", "tests", "fixtures", "single-use-capability")
	}
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			ID, File, Kind    string
			Expected          *string
			RefusalExpected   *string `json:"refusal_expected"`
			AuthorityExpected *string `json:"authority_expected"`
		}
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	bindingCode := func(err error) string {
		if err == nil {
			return ""
		}
		var refusal *evidence.BindingError
		if errors.As(err, &refusal) {
			return refusal.Code
		}
		t.Fatal(err)
		return ""
	}
	expected := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	firstCode := func(values []codedProblem) string {
		if len(values) == 0 {
			return ""
		}
		return values[0].code
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, item.File))
			if err != nil {
				t.Fatal(err)
			}
			value, err := strict.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			r := value.(map[string]any)
			switch item.Kind {
			case "pair":
				if actual := bindingCode(evidence.CheckResponseBinding(r["request"], r["response"], 0)); actual != expected(item.Expected) {
					t.Fatalf("got %q want %q", actual, expected(item.Expected))
				}
			case "event":
				if actual := bindingCode(evidence.CheckEventBinding(r["released"], r["request"], r["response"])); actual != expected(item.Expected) {
					t.Fatalf("event got %q want %q", actual, expected(item.Expected))
				}
				if actual := bindingCode(evidence.CheckAuthorityEventBinding(r["consumed"], r["response"])); actual != expected(item.AuthorityExpected) {
					t.Fatalf("authority got %q want %q", actual, expected(item.AuthorityExpected))
				}
			case "oauth":
				if actual := firstCode(oauthPresentationChecks(r)); actual != expected(item.Expected) {
					t.Fatalf("presentation got %q want %q", actual, expected(item.Expected))
				}
				want := item.RefusalExpected
				if want == nil {
					want = item.Expected
				}
				if actual := firstCode(oauthRefusalProblems(r)); actual != expected(want) {
					t.Fatalf("refusal got %q want %q", actual, expected(want))
				}
			case "mcp":
				findings := checkMCP(r)
				cause, refused := MCPRefusalCause(r)
				if item.Expected == nil {
					if len(findings) > 0 || refused {
						t.Fatalf("control refused: %v %v", findings, cause)
					}
				} else {
					found := false
					for _, f := range findings {
						found = found || f.RuleID == *item.Expected
					}
					if !found || !refused || cause.Cause != "decision-invalid" {
						t.Fatalf("unsupported forward was not refused: %v %v", findings, cause)
					}
				}
			default:
				t.Fatal(item.Kind)
			}
		})
	}
}
