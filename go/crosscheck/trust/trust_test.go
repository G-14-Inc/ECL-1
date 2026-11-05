package trust_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// Every trust-policy vector loads, or is refused with its expected code: those of the
// trust-policy suite and the policies of the key-roles suite (TP1-009).
func TestTrustPolicySuite(t *testing.T) {
	var suite []vectors.Vector
	for _, name := range []string{"trust-policy", "key-roles"} {
		suite = append(suite, vectors.Suite(t, name).Vectors...)
	}
	for _, vector := range suite {
		if vector.Stage != "trust-policy" {
			continue
		}
		_, err := trust.Load(vectors.Read(t, vector.Path))
		var refusal *trust.Error
		switch {
		case vector.Expected == "pass" && err != nil:
			t.Errorf("%s: %v", vector.ID, err)
		case vector.Expected == "fail" && (!errors.As(err, &refusal) || refusal.Code != vector.Primary):
			t.Errorf("%s: %v, not %s", vector.ID, err, vector.Primary)
		}
	}
}

// TP1-009: a key holds at most one of the role purposes; the evidence-event purpose is no role.
func TestOneKeyOneRole(t *testing.T) {
	cases := []struct {
		purposes []string
		conflict int
	}{
		{[]string{trust.PurposeDecisionRequest, trust.PurposeEvidenceEvent}, 0},
		{[]string{trust.PurposeDecisionResponse}, 0},
		{[]string{trust.PurposeEvidenceEvent}, 0},
		{[]string{trust.PurposeDecisionRequest, trust.PurposeDecisionResponse}, 2},
		{[]string{trust.PurposeTrustedTime, trust.PurposeObservation, trust.PurposeEvidenceEvent}, 2},
		{[]string{trust.PurposeDecisionResponse, trust.PurposeObservation, trust.PurposeTrustedTime, trust.PurposeDecisionRequest}, 4},
	}
	for _, item := range cases {
		if roles := trust.RoleConflict(item.purposes); len(roles) != item.conflict {
			t.Errorf("%v: %v", item.purposes, roles)
		}
	}
	if roles := trust.RoleConflict([]string{trust.PurposeTrustedTime, trust.PurposeDecisionRequest}); roles[0] != trust.PurposeDecisionRequest {
		t.Errorf("not in the order of RolePurposes: %v", roles)
	}
	policy, err := trust.Load(vectors.Read(t, "conformance/suites/key-roles/trust-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range policy.Keyring() {
		if len(key.RolePurposes) == 0 {
			t.Errorf("%s: the keyring does not carry the key's purposes", key.KeyID)
		}
	}
}

func TestLimitsAndShape(t *testing.T) {
	if _, err := trust.Load([]byte(strings.Repeat(" ", trust.MaxPolicyBytes+1))); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatal(err)
	}
	for _, input := range []string{"", "{}", "[]", "\xef\xbb\xbf{}", `{"a":1,"a":1}`} {
		var refusal *trust.Error
		if _, err := trust.Load([]byte(input)); !errors.As(err, &refusal) || refusal.Code != trust.SchemaInvalid {
			t.Errorf("%q: %v", input, err)
		}
	}
}

func TestKeyringAndContext(t *testing.T) {
	policy, err := trust.Load(vectors.Read(t, "conformance/suites/evidence-bundle/trust-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	ring := policy.Keyring()
	if len(ring) != len(policy.Keys) {
		t.Fatal("keyring size")
	}
	for _, key := range ring {
		if len(key.Purposes) == 0 || key.TrustPolicyIDs[0] != policy.ID {
			t.Fatalf("%+v", key)
		}
	}
	context, err := policy.VerificationContext("2026-10-01T00:00:00Z", "ecl.time.observed-at.v1")
	if err != nil || context.TrustPolicyDigest != policy.Digest || len(context.AllowedSuites) == 0 {
		t.Fatalf("%+v %v", context, err)
	}
	if _, err := policy.VerificationContext("2026-10-01T00:00:00Z", "ecl.time.unregistered.v1"); err == nil {
		t.Fatal("an unregistered time policy was accepted")
	}
}

func ExampleLoad() {
	data, _ := vectors.ReadFile("conformance/suites/trust-policy/trust-policy-invalid-small-order-00.json")
	_, err := trust.Load(data)
	var refusal *trust.Error
	if errors.As(err, &refusal) {
		fmt.Println(refusal.Code)
	}
	// Output: ecl.error.semantic-invalid.v1
}
