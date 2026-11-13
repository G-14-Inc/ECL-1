package canon_test

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"strings"
	"testing"
)

func TestProducerCanonicalDepthBoundaryAndCycle(t *testing.T) {
	for _, depth := range []int{canon.MaxDepth - 1, canon.MaxDepth, canon.MaxDepth + 1} {
		var value any = 0
		for i := 0; i < depth; i++ {
			value = []any{value}
		}
		_, err := canon.Marshal(value)
		if (err != nil) != (depth > canon.MaxDepth) {
			t.Fatalf("depth %d: %v", depth, err)
		}
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, err := canon.Marshal(cycle); err == nil || !strings.Contains(err.Error(), "ecl.error.resource-limit-exceeded.v1") {
		t.Fatal(err)
	}
}

func TestProducerCanonicalNodeBoundary(t *testing.T) {
	for _, count := range []int{canon.MaxNodes - 1, canon.MaxNodes, canon.MaxNodes + 1} {
		value := make([]any, count-1)
		_, err := canon.Marshal(value)
		if (err != nil) != (count > canon.MaxNodes) {
			t.Fatalf("nodes %d: %v", count, err)
		}
	}
}
