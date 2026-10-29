package evidence

import (
	"errors"
	"fmt"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// MaxBundleBytes is the size limit of an evidence bundle file (TP1-007), enforced before parsing.
const MaxBundleBytes = 1024 * 1024

// InputError is input that cannot be verified at all, such as a malformed trust policy or a
// bundle file that is not strict JSON. The reference command-line verifier exits with 2 for it.
type InputError struct {
	Message string
	// Code is the registered code of the underlying refusal, when there is one. Every refusal of a
	// declared limit, at a byte guard or in the strict parse, is ecl.error.resource-limit-exceeded.v1
	// (TP1-007, IE1-028).
	Code string
}

func (e *InputError) Error() string { return e.Message }

func loadPolicy(data []byte, kind string) (*trust.Policy, error) {
	if len(data) > trust.MaxPolicyBytes {
		return nil, &InputError{Message: kind + " file exceeds the 256 KiB limit", Code: ResourceLimitExceeded}
	}
	policy, err := trust.Load(data)
	if err != nil {
		var refusal *trust.Error
		if errors.As(err, &refusal) {
			return nil, &InputError{Message: "malformed " + kind + ": " + refusal.Message, Code: refusal.Code}
		}
		return nil, err
	}
	return policy, nil
}

// VerifyBytes verifies a bundle file against a trust policy file and earlier versions of it,
// with the byte limits that TRUST-POLICY-1 sets for a verifier interface (TP1-007): each trust
// policy at most 256 KiB and the bundle at most 1 MiB, enforced before parsing. options.History
// is ignored; the history files take its place. A register file is read with LoadRegister and
// given as options.Register. Input that cannot be verified is an *InputError.
func VerifyBytes(bundle, policy []byte, history [][]byte, options Options) (*Report, *trust.Policy, error) {
	current, err := loadPolicy(policy, "trust policy")
	if err != nil {
		return nil, nil, err
	}
	options.History = nil
	for _, data := range history {
		older, err := loadPolicy(data, "trust policy history")
		if err != nil {
			return nil, nil, err
		}
		options.History = append(options.History, older)
	}
	if len(bundle) > MaxBundleBytes {
		return nil, nil, &InputError{Message: "bundle file exceeds the 1 MiB limit", Code: ResourceLimitExceeded}
	}
	value, err := strict.Parse(bundle)
	if err != nil {
		var refusal *strict.Error
		if errors.As(err, &refusal) {
			return nil, nil, &InputError{Message: "malformed bundle JSON: " + refusal.Error(), Code: refusal.RuleID}
		}
		return nil, nil, err
	}
	report, err := Verify(value, current, options)
	if err != nil {
		if errors.Is(err, ErrInvalidNow) || errors.Is(err, ErrNegativeSkew) {
			return nil, nil, &InputError{Message: fmt.Sprintf("invalid evaluation time or option: %v", err)}
		}
		if errors.Is(err, ErrInvalidRegister) {
			return nil, nil, &InputError{Message: "malformed register: " + err.Error()}
		}
		return nil, nil, err
	}
	return report, current, nil
}
