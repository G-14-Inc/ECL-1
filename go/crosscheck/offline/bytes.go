package offline

import (
	"errors"
	"fmt"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func loadPolicy(data []byte, kind string) (*trust.Policy, error) {
	if len(data) > trust.MaxPolicyBytes {
		return nil, &evidence.InputError{Message: kind + " file exceeds the 256 KiB limit", Code: evidence.ResourceLimitExceeded}
	}
	policy, err := trust.Load(data)
	if err != nil {
		var refusal *trust.Error
		if errors.As(err, &refusal) {
			return nil, &evidence.InputError{Message: "malformed " + kind + ": " + refusal.Message, Code: refusal.Code}
		}
		return nil, err
	}
	return policy, nil
}

// VerifyBytes verifies an offline package file against a trust policy file and earlier versions
// of it, as evidence.VerifyBytes verifies a bundle file: each trust policy holds at most 256 KiB
// (TP1-007), and the package is verified with Verify under options (its Limits, DefaultLimits
// when nil). Input that cannot be verified at all, such as a malformed trust policy or an invalid
// evaluation time, option, register or limit, is an *evidence.InputError; the package itself is
// always reported.
func VerifyBytes(archive, policy []byte, history [][]byte, options Options) (*evidence.Report, *trust.Policy, error) {
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
	report, err := Verify(archive, current, options)
	if err != nil {
		if errors.Is(err, evidence.ErrInvalidNow) || errors.Is(err, evidence.ErrNegativeSkew) || errors.Is(err, ErrInvalidLimits) {
			return nil, nil, &evidence.InputError{Message: fmt.Sprintf("invalid evaluation time or option: %v", err)}
		}
		if errors.Is(err, evidence.ErrInvalidRegister) {
			return nil, nil, &evidence.InputError{Message: "malformed register: " + err.Error()}
		}
		return nil, nil, err
	}
	return report, current, nil
}
