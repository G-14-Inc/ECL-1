package evidence_test

import (
	"bytes"
	"errors"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// padded is `body` preceded by spaces to `size` bytes, strict JSON of exactly that size.
func padded(size int, body string) []byte {
	return append(bytes.Repeat([]byte(" "), size-len(body)), body...)
}

func deep(levels int) []byte {
	return append(bytes.Repeat([]byte("["), levels), bytes.Repeat([]byte("]"), levels)...)
}

func limitCode(t *testing.T, name string, err error) {
	t.Helper()
	var input *evidence.InputError
	if !errors.As(err, &input) || input.Code != evidence.ResourceLimitExceeded {
		t.Errorf("%s: want %s, got %#v", name, evidence.ResourceLimitExceeded, err)
	}
}

// F06 (TP1-007, IE1-028): every refusal of a declared limit at the byte interface is
// ecl.error.resource-limit-exceeded.v1, one unit over the limit, at the byte guard and in the
// strict parse; input exactly at the limit is read.
func TestByteInterfaceLimitsCarryTheRegisteredCode(t *testing.T) {
	bundle := vectors.Read(t, "conformance/fixtures/evidence/succeeded.json")
	policy := vectors.Read(t, "conformance/fixtures/evidence/trust-policy.json")
	options := evidence.Options{Now: now}
	_, _, err := evidence.VerifyBytes(make([]byte, evidence.MaxBundleBytes+1), policy, nil, options)
	limitCode(t, "bundle bytes", err)
	_, _, err = evidence.VerifyBytes(deep(300), policy, nil, options)
	limitCode(t, "bundle nesting", err)
	_, _, err = evidence.VerifyBytes(bundle, make([]byte, trust.MaxPolicyBytes+1), nil, options)
	limitCode(t, "policy bytes", err)
	_, _, err = evidence.VerifyBytes(bundle, deep(300), nil, options)
	limitCode(t, "policy nesting", err)
	_, _, err = evidence.VerifyBytes(bundle, policy, [][]byte{make([]byte, trust.MaxPolicyBytes+1)}, options)
	limitCode(t, "history bytes", err)
	_, err = evidence.LoadRegister(make([]byte, evidence.MaxRegisterBytes+1))
	limitCode(t, "register bytes", err)
	_, err = evidence.LoadRegister(deep(300))
	limitCode(t, "register nesting", err)

	// Exactly at each byte limit: the bundle is read and reported; the policy is read and refused
	// by its schema, not by the limit.
	report, _, err := evidence.VerifyBytes(padded(evidence.MaxBundleBytes, "{}"), policy, nil, options)
	if err != nil || report.Verdict != evidence.Invalid {
		t.Errorf("bundle at the limit: %v %v", report, err)
	}
	var input *evidence.InputError
	_, _, err = evidence.VerifyBytes(bundle, padded(trust.MaxPolicyBytes, "{}"), nil, options)
	if !errors.As(err, &input) || input.Code != trust.SchemaInvalid {
		t.Errorf("policy at the limit: %v", err)
	}
	_, err = evidence.LoadRegister(padded(evidence.MaxRegisterBytes, "{}"))
	if !errors.As(err, &input) || input.Code != evidence.SchemaInvalid {
		t.Errorf("register at the limit: %v", err)
	}
}
