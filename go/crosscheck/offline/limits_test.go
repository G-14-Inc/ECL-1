package offline

import (
	"errors"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// F06 (TP1-007): a trust policy beyond its byte limit, current or historical, is refused at the
// offline package's byte interface with ecl.error.resource-limit-exceeded.v1.
func TestPackageBytePolicyLimitCarriesTheRegisteredCode(t *testing.T) {
	policy := repository(t, "conformance/fixtures/evidence/trust-policy.json")
	options := Options{Options: evidence.Options{Now: now}}
	for name, call := range map[string]func() error{
		"policy": func() error {
			_, _, err := VerifyBytes(nil, make([]byte, trust.MaxPolicyBytes+1), nil, options)
			return err
		},
		"history": func() error {
			_, _, err := VerifyBytes(nil, policy, [][]byte{make([]byte, trust.MaxPolicyBytes+1)}, options)
			return err
		},
	} {
		var input *evidence.InputError
		if err := call(); !errors.As(err, &input) || input.Code != evidence.ResourceLimitExceeded {
			t.Errorf("%s: %#v", name, err)
		}
	}
}
