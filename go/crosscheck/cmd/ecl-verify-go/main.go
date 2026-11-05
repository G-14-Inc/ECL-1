// Command ecl-verify-go verifies a signed ECL evidence bundle or an offline package offline, with
// the interface of the reference's ecl-verify:
//
//	ecl-verify-go BUNDLE --trust-policy FILE [--trust-policy-history FILE]... [--now RFC3339]
//	              [--accept-current-trust-failure] [--require-trusted-time] [--register FILE] [--json]
//
// A decision response without ecl.ext.decision-basis.v1 makes the bundle invalid (DCMP2-053);
// --register checks each decision basis against a Consequential Action Register.
//
// A file that begins with the bytes PK is verified as an offline package (OFFLINE-VERIFICATION-1,
// IE1-022) of at most 1 GiB, the declared archive limit, under the same inputs; any other file is
// a JSON evidence bundle of at most 1 MiB.
//
// An input that cannot be verified at all is a usage error, reported on standard error in one line,
// "error: CODE: MESSAGE" when the refusal has a registered code (every refusal of a declared limit
// is ecl.error.resource-limit-exceeded.v1) and "error: MESSAGE" otherwise.
//
// The exit status is 0 for verified, 1 for invalid, 2 for a usage error, 3 for incomplete and 4
// for current-trust-failed (EBMP2-060).
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/offline"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

const usage = "usage: ecl-verify-go BUNDLE --trust-policy FILE [--trust-policy-history FILE]... [--now RFC3339] [--accept-current-trust-failure] [--require-trusted-time] [--register FILE] [--json]\n"

var exits = map[string]int{evidence.Verified: 0, evidence.Invalid: 1, evidence.Incomplete: 3, evidence.CurrentTrustFailed: 4}

func readLimited(path string, limit int, kind, label string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, &evidence.InputError{Message: "cannot read " + kind + " file"}
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, &evidence.InputError{Message: "cannot read " + kind + " file"}
	}
	if len(data) > limit {
		return nil, &evidence.InputError{Message: kind + " file exceeds the " + label + " limit", Code: evidence.ResourceLimitExceeded}
	}
	return data, nil
}

// isPackage reports whether the evidence file is an offline package: an archive begins with PK.
func isPackage(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, &evidence.InputError{Message: "cannot read bundle file"}
	}
	defer file.Close()
	head := make([]byte, 2)
	read, _ := io.ReadFull(file, head)
	return read == 2 && head[0] == 'P' && head[1] == 'K', nil
}

// readPackage reads an offline package file, refused unread above the declared archive limit.
func readPackage(path string) ([]byte, error) {
	limit := offline.DefaultLimits.MaxArchiveBytes
	info, err := os.Stat(path)
	if err != nil {
		return nil, &evidence.InputError{Message: "cannot read offline package file"}
	}
	if info.Size() > limit {
		return nil, &evidence.InputError{Message: "offline package file exceeds the 1 GiB limit", Code: evidence.ResourceLimitExceeded}
	}
	return readLimited(path, int(limit), "offline package", "1 GiB")
}

func orDash(value *string) string {
	if value == nil {
		return "-"
	}
	return *value
}

func human(report *evidence.Report, currentVersion string) string {
	// EBMP2-076: what the verdict does not establish comes with the verdict, then what it does.
	lines := []string{"verdict: " + report.Verdict}
	// EBMP2-060: the primary finding of a verdict other than verified, the failing current status
	// of a trust dependency for current-trust-failed among them.
	if primary := evidence.PrimaryFinding(report); primary != nil {
		lines = append(lines, "primary: "+*primary)
	}
	for _, item := range report.Scope.NotEstablished {
		line := "not-established: " + item + ": " + evidence.ScopeText[item]
		if reason, stated := report.Scope.Reasons[item]; stated {
			line += " (reason: " + reason + ")"
		}
		lines = append(lines, line)
	}
	for _, item := range report.Scope.Established {
		lines = append(lines, "established: "+item+": "+evidence.ScopeText[item])
	}
	// EBMP2-076: the checks that ran for each established item and the objects they covered.
	for _, item := range report.Scope.Established {
		entry := report.Scope.Checks[item]
		objects := make([]string, len(entry.Objects))
		for index, value := range entry.Objects {
			objects[index] = fmt.Sprint(value)
		}
		listed := strings.Join(objects, ",")
		if listed == "" {
			listed = "-"
		}
		lines = append(lines, "checks "+item+": "+strings.Join(entry.Checks, ",")+" objects="+listed)
	}
	lines = append(lines, "verification-profile: "+report.VerificationProfile)
	evaluationTime := report.EvaluationTime
	if evaluationTime == "" {
		evaluationTime = "-"
	}
	lines = append(lines, "evaluation-time: "+evaluationTime)
	if report.AcceptedCurrentTrustFailure {
		lines = append(lines, "accepted: current trust failure, by --accept-current-trust-failure")
	}
	if report.Register != nil {
		digest, _ := report.Register["digest"].(map[string]any)
		lines = append(lines, fmt.Sprintf("decision-basis register: %v sha256:%v", report.Register["uri"], digest["value"]))
	} else {
		lines = append(lines, "decision-basis register: none; declared classes not checked against a register")
	}
	for _, check := range report.EnvelopeChecks {
		signers := strings.Join(check.SignerKeyIDs, ",")
		if signers == "" {
			signers = "-"
		}
		lines = append(lines, fmt.Sprintf("envelope %d: kind=%s signers=%s historical=%s current=%s historical-policy=%s current-policy=%s trusted-time=%s",
			check.Index, check.Kind, signers, check.Historical, check.Current, orDash(check.HistoricalPolicyVersion), currentVersion, orDash(check.TrustedTime)))
	}
	// TP1-006: each trust dependency, with the policy versions and the revocation it used.
	for _, item := range report.TrustDependencies {
		lines = append(lines, fmt.Sprintf("dependency %d: role=%s key=%s counter=%s at=%s historical-policy=%s historical=%s current-policy=%s revoked-effective-at=%s current=%s",
			item.Index, item.Role, item.KeyID, orDash(item.CounterID), orDash(item.At), orDash(item.HistoricalPolicyVersion), item.Historical, item.CurrentPolicyVersion, orDash(item.RevokedEffectiveAt), item.Current))
	}
	for _, check := range report.BindingChecks {
		outcome := "pass"
		if !check.Passed {
			outcome = "fail"
			if check.Code != nil {
				outcome = *check.Code
			}
		}
		lines = append(lines, "binding "+check.Name+": "+outcome)
	}
	lines = append(lines, "causal: "+report.CausalStatus)
	for _, identifier := range report.UnresolvedPredecessorIDs {
		lines = append(lines, "unresolved-predecessor: "+identifier)
	}
	// EBMP2-072: a server answer that arrived after the authorization's window is information.
	lines = append(lines, fmt.Sprintf("completion-after-window: %t", report.CompletionAfterWindow))
	for _, effect := range report.Effects {
		lines = append(lines, fmt.Sprintf("effect %s: state=%s level=%s authority=%s reason=%s", effect.ActionID, effect.State, effect.Level, effect.Authority, orDash(effect.Reason)))
	}
	for _, finding := range report.Findings {
		lines = append(lines, "finding: "+finding.Code+": "+finding.Message)
	}
	return strings.Join(lines, "\n") + "\n"
}

func run(arguments []string, stdout, stderr io.Writer) int {
	var bundlePath, policyPath, now, registerPath string
	var historyPaths []string
	var nowSpecified bool
	accept, requireTrustedTime, asJSON := false, false, false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		next := func() (string, bool) {
			if index+1 >= len(arguments) {
				return "", false
			}
			index++
			return arguments[index], true
		}
		var ok = true
		switch {
		case argument == "--trust-policy":
			policyPath, ok = next()
		case argument == "--trust-policy-history":
			var path string
			if path, ok = next(); ok {
				historyPaths = append(historyPaths, path)
			}
		case argument == "--now":
			now, ok = next()
			nowSpecified = true
		case argument == "--accept-current-trust-failure":
			accept = true
		case argument == "--require-trusted-time":
			requireTrustedTime = true
		case argument == "--register":
			registerPath, ok = next()
		case argument == "--json":
			asJSON = true
		case argument == "-h" || argument == "--help":
			fmt.Fprint(stdout, usage)
			return 0
		case bundlePath == "" && !strings.HasPrefix(argument, "-"):
			bundlePath = argument
		default:
			ok = false
		}
		if !ok {
			fmt.Fprint(stderr, usage)
			return 2
		}
	}
	if bundlePath == "" || policyPath == "" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if !nowSpecified {
		now = time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	}
	report, policy, err := func() (*evidence.Report, *trust.Policy, error) {
		policy, err := readLimited(policyPath, trust.MaxPolicyBytes, "trust policy", "256 KiB")
		if err != nil {
			return nil, nil, err
		}
		var history [][]byte
		for _, path := range historyPaths {
			data, err := readLimited(path, trust.MaxPolicyBytes, "trust policy history", "256 KiB")
			if err != nil {
				return nil, nil, err
			}
			history = append(history, data)
		}
		options := evidence.Options{Now: now, AcceptCurrentTrustFailure: accept, RequireTrustedTime: requireTrustedTime}
		if registerPath != "" {
			data, err := readLimited(registerPath, evidence.MaxRegisterBytes, "register", "1 MiB")
			if err != nil {
				return nil, nil, err
			}
			register, err := evidence.LoadRegister(data)
			if err != nil {
				return nil, nil, err
			}
			options.Register = register
		}
		packaged, err := isPackage(bundlePath)
		if err != nil {
			return nil, nil, err
		}
		if packaged {
			// An offline package (IE1-022) is verified under the same inputs as a bundle.
			archive, err := readPackage(bundlePath)
			if err != nil {
				return nil, nil, err
			}
			return offline.VerifyBytes(archive, policy, history, offline.Options{Options: options})
		}
		bundle, err := readLimited(bundlePath, evidence.MaxBundleBytes, "bundle", "1 MiB")
		if err != nil {
			return nil, nil, err
		}
		return evidence.VerifyBytes(bundle, policy, history, options)
	}()
	var input *evidence.InputError
	if errors.As(err, &input) {
		// The registered code of the refusal comes first when there is one (F06, TP1-007).
		if input.Code != "" {
			fmt.Fprintln(stderr, "error: "+input.Code+": "+input.Message)
		} else {
			fmt.Fprintln(stderr, "error: "+input.Message)
		}
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error: "+err.Error())
		return 2
	}
	if asJSON {
		encoded, err := canon.Marshal(report.JSON())
		if err != nil {
			fmt.Fprintln(stderr, "error: "+err.Error())
			return 2
		}
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprint(stdout, human(report, policy.Version))
	}
	return exits[report.Verdict]
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
