package evidence_test

import (
	"encoding/json"
	"errors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleMappingLimits(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "bundle-contract-regressions")
	raw, e := os.ReadFile(filepath.Join(root, "f001-prepared-control.bundle.json"))
	if e != nil {
		t.Fatal(e)
	}
	pb, e := os.ReadFile(filepath.Join(root, "f001-prepared-control.policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	policy, e := trust.Load(pb)
	if e != nil {
		t.Fatal(e)
	}
	bundle := func(value any) map[string]any {
		v, e := strict.Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		b := v.(map[string]any)
		b["envelopes"].([]any)[0].(map[string]any)["extensions"] = []any{map[string]any{"id": "com.example.annotation.v1", "version": json.Number("1"), "critical": false, "value": value}}
		return b
	}
	nodes := func(value any) int {
		todo := []any{value}
		n := 0
		for len(todo) > 0 {
			v := todo[len(todo)-1]
			todo = todo[:len(todo)-1]
			n++
			switch x := v.(type) {
			case []any:
				todo = append(todo, x...)
			case map[string]any:
				for _, child := range x {
					todo = append(todo, child)
				}
			}
		}
		return n
	}
	for _, row := range []struct {
		name   string
		excess bool
	}{{"depth-at", false}, {"depth-over", true}, {"nodes-at", false}, {"nodes-over", true}, {"cycle", true}, {"shared", false}, {"shared-over", true}, {"large-string", false}} {
		t.Run(row.name, func(t *testing.T) {
			var value any
			if strings.HasPrefix(row.name, "depth") {
				count := strict.MaxDepth - 5
				if row.excess {
					count++
				}
				for i := 0; i < count; i++ {
					value = []any{value}
				}
			} else if strings.HasPrefix(row.name, "nodes") {
				count := strict.MaxNodes - nodes(bundle([]any{}))
				if row.excess {
					count++
				}
				v := make([]any, count)
				for i := range v {
					v[i] = json.Number("0")
				}
				value = v
			} else if row.name == "cycle" {
				v := map[string]any{}
				v["self"] = v
				value = v
			} else if row.name == "shared" {
				shared := map[string]any{"values": []any{json.Number("1"), json.Number("2")}}
				value = []any{shared, shared}
			} else if row.name == "shared-over" {
				for i := 0; i < 20; i++ {
					value = []any{value, value}
				}
			} else {
				value = strings.Repeat("a", 1024*1024+1)
			}
			report, e := evidence.Verify(bundle(value), policy, evidence.Options{Now: "2026-10-01T00:00:00Z"})
			if e != nil {
				t.Fatal(e)
			}
			want := "verified"
			if row.excess {
				want = "invalid"
			}
			if report.Verdict != want {
				t.Fatalf("got %s: %+v", report.Verdict, report.Findings)
			}
			if row.excess && (len(report.Findings) == 0 || report.Findings[0].Code != evidence.ResourceLimitExceeded || len(report.EnvelopeChecks) != 0) {
				t.Errorf("wrong resource stage: %+v", report)
			}
		})
	}
	b, _ := json.Marshal(bundle(strings.Repeat("a", 1024*1024+1)))
	_, _, e = evidence.VerifyBytes(b, pb, nil, evidence.Options{Now: "2026-10-01T00:00:00Z"})
	var refusal *evidence.InputError
	if !errors.As(e, &refusal) || refusal.Code != evidence.ResourceLimitExceeded {
		t.Fatalf("byte limit: %v", e)
	}
}
