package evidence_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func budgetFixture(t *testing.T) (map[string]any, *trust.Policy) {
	t.Helper()
	value, err := strict.Parse(vectors.Read(t, "conformance/suites/evidence-bundle/bundle-valid-trusted-time.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any), load(t, "conformance/suites/evidence-bundle/trust-policy-time-authority.json")
}
func budgetCounter(outer any) map[string]any {
	return outer.(map[string]any)["countersignatures"].([]any)[0].(map[string]any)
}
func budgetStatement(t *testing.T, a map[string]any) map[string]any {
	t.Helper()
	value, err := envelope.DecodeCanonicalJSONPayload(a)
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}
func replaceBudgetPayload(t *testing.T, a, statement map[string]any) {
	t.Helper()
	raw, err := canon.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	a["payload"] = base64.StdEncoding.EncodeToString(raw)
	a["payload_digest"].(map[string]any)["value"] = hex.EncodeToString(digest[:])
}
func budgetNodes(value any) int {
	n := 1
	switch v := value.(type) {
	case map[string]any:
		for _, x := range v {
			n += budgetNodes(x)
		}
	case []any:
		for _, x := range v {
			n += budgetNodes(x)
		}
	}
	return n
}
func budgetTotal(t *testing.T, bundle map[string]any) int {
	n := 0
	for _, outer := range bundle["envelopes"].([]any) {
		e := outer.(map[string]any)
		n += budgetNodes(budgetStatement(t, e))
		for _, entry := range e["countersignatures"].([]any) {
			n += budgetNodes(budgetStatement(t, entry.(map[string]any)["attestation"].(map[string]any)))
		}
	}
	return n
}
func budgetResult(t *testing.T, bundle map[string]any, policy *trust.Policy) *evidence.Report {
	t.Helper()
	report, err := evidence.Verify(bundle, policy, evidence.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return report
}
func requireBudgetPrimary(t *testing.T, bundle map[string]any, policy *trust.Policy, want string) {
	t.Helper()
	report := budgetResult(t, bundle, policy)
	got := evidence.PrimaryFinding(report)
	if got == nil || *got != want {
		t.Fatalf("primary %v, want %s", got, want)
	}
}
func TestAttestationSharedPayloadBudget(t *testing.T) {
	bundle, policy := budgetFixture(t)
	if got := budgetResult(t, bundle, policy).Verdict; got != "verified" {
		t.Fatal(got)
	}
	for _, offset := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			bundle, policy := budgetFixture(t)
			a := budgetCounter(bundle["envelopes"].([]any)[0])["attestation"].(map[string]any)
			statement := budgetStatement(t, a)
			statement["padding"] = []any{}
			replaceBudgetPayload(t, a, statement)
			padding := make([]any, evidence.MaxTotalPayloadNodes+offset-budgetTotal(t, bundle))
			for i := range padding {
				padding[i] = 0
			}
			statement["padding"] = padding
			replaceBudgetPayload(t, a, statement)
			if got := budgetTotal(t, bundle); got != evidence.MaxTotalPayloadNodes+offset {
				t.Fatal(got)
			}
			want := evidence.TrustedTimeInvalid
			if offset > 0 {
				want = evidence.ResourceLimitExceeded
			}
			requireBudgetPrimary(t, bundle, policy, want)
		})
	}
}
func TestAttestationSplitAndMalformedOuterBudget(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprint(malformed), func(t *testing.T) {
			bundle, policy := budgetFixture(t)
			count, size := 2, 50000
			if malformed {
				count, size = 1, 100001
			}
			for _, outer := range bundle["envelopes"].([]any)[:count] {
				a := budgetCounter(outer)["attestation"].(map[string]any)
				statement := budgetStatement(t, a)
				padding := make([]any, size)
				for i := range padding {
					padding[i] = 0
				}
				statement["padding"] = padding
				replaceBudgetPayload(t, a, statement)
			}
			if malformed {
				bundle["envelopes"].([]any)[0].(map[string]any)["payload_digest"].(map[string]any)["value"] = strings.Repeat("0", 64)
			}
			requireBudgetPrimary(t, bundle, policy, evidence.ResourceLimitExceeded)
		})
	}
}
func TestAttestationRegisteredFutureClaim(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(fmt.Sprint(registered), func(t *testing.T) {
			bundle, policy := budgetFixture(t)
			entry := budgetCounter(bundle["envelopes"].([]any)[0])
			a := entry["attestation"].(map[string]any)
			statement := budgetStatement(t, a)
			statement["issued_at"] = "2099-01-01T00:00:00Z"
			replaceBudgetPayload(t, a, statement)
			want := evidence.ClockRegressed
			if !registered {
				entry["claim"] = "ecl.claim.unregistered.v1"
				want = evidence.TrustedTimeInvalid
			}
			requireBudgetPrimary(t, bundle, policy, want)
		})
	}
}
func TestAttestationSignatureFailureClassification(t *testing.T) {
	for _, size := range []int{20000, 21848, 21852} {
		bundle, policy := budgetFixture(t)
		a := budgetCounter(bundle["envelopes"].([]any)[0])["attestation"].(map[string]any)
		a["signatures"].([]any)[0].(map[string]any)["signature"] = strings.Repeat("A", size)
		requireBudgetPrimary(t, bundle, policy, evidence.TrustedTimeInvalid)
	}
}

func TestAttestationDepthPreservesEarlierCheck(t *testing.T) {
	bundle, policy := budgetFixture(t)
	outer := bundle["envelopes"].([]any)[0].(map[string]any)
	outer["payload_digest"].(map[string]any)["value"] = strings.Repeat("0", 64)
	a := budgetCounter(outer)["attestation"].(map[string]any)
	raw := []byte(strings.Repeat("[", 257) + "0" + strings.Repeat("]", 257))
	digest := sha256.Sum256(raw)
	a["payload"] = base64.StdEncoding.EncodeToString(raw)
	a["payload_digest"].(map[string]any)["value"] = hex.EncodeToString(digest[:])
	report := budgetResult(t, bundle, policy)
	if got := evidence.PrimaryFinding(report); got == nil || *got != evidence.ResourceLimitExceeded {
		t.Fatalf("primary %v, want %s", got, evidence.ResourceLimitExceeded)
	}
	if len(report.EnvelopeChecks) != 1 {
		t.Fatalf("lost earlier payload check: %v", report.EnvelopeChecks)
	}
}
