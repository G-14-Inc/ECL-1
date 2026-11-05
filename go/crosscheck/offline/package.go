// Package offline verifies ECL offline packages (OFFLINE-VERIFICATION-1) as the evidence bundle
// each carries (IE1-021, IE1-022), with the reference's verdicts and findings
// (ecl_reference.package_verification.verify_offline_package).
//
// A package is an ecl.zip.store.v1 archive: manifest.json and the artifacts it names, each bound
// by role, size and SHA-256 digest. Its envelope and observation artifacts are the envelopes and
// observations of one evidence bundle, its payload artifacts are their canonical payloads, and the
// rest is material the producer used: evidence, never a trust anchor. The bundle is verified under
// the trust policy, earlier policy versions and evaluation time that the caller supplies, exactly
// as evidence.Verify verifies any bundle; the caller's evidence.Options are passed to it
// unchanged, so an option that the bundle verifier gains reaches the package's bundle without a
// change here.
//
// Verify makes the checks of IE1-022 in order and reports the verdict of EBMP2-060 and the error
// code of the first that fails:
//
//  1. the archive is in ecl.zip.store.v1 form (ReadArchive), or invalid, semantic-invalid;
//  2. it holds manifest.json, or incomplete, causal-closure-incomplete;
//  3. the manifest is strict JSON that satisfies its schema, with valid created_at and expires_at
//     instants and a SHA-256 digest in every artifact entry and reference, or invalid,
//     schema-invalid;
//  4. its artifact paths could be the entry names of one such archive together with
//     manifest.json, and it names every other member, or invalid, semantic-invalid;
//  5. expires_at is later than created_at, or invalid, expired;
//  6. every artifact the archive holds has its manifest size and digest, or invalid,
//     integrity-invalid;
//  7. every envelope and observation artifact is a strict JSON object, or invalid,
//     schema-invalid;
//  8. every payload artifact is the payload of one of them, or invalid, integrity-invalid;
//  9. when the package carries an envelope, the bundle is not invalid, or invalid with the
//     bundle's findings;
//  10. every artifact the manifest names or IE1-021 requires, and the payload of every packaged
//     envelope and observation, is present, and there is an envelope, or incomplete,
//     causal-closure-incomplete;
//  11. the bundle is not incomplete, or incomplete with the bundle's findings.
//
// Otherwise the package has its bundle's verdict, except that a package whose expires_at is not
// later than the evaluation time is current-trust-failed, with the expired code, where its bundle
// is verified. Times are compared to the microsecond, as the reference compares them. A package
// that exceeds a declared limit of the verifier (IE1-028) is invalid with
// ecl.error.resource-limit-exceeded.v1 at the check that meets the limit: the archive's limits at
// check 1, the artifact count and path bytes at check 4, and at checks 3 and 7 a strict JSON
// refusal that the parser reports as that error (other refusals are schema-invalid).
package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// Names, schemas and codes of a package.
const (
	ManifestName   = "manifest.json"
	ManifestSchema = "https://externalcontrollayer.ai/ns/schema/offline-verification-package/1"
	// MediaType is the media type of an offline package (OFFLINE-VERIFICATION-1).
	MediaType = "application/vnd.ecl.bundle+zip"
	// ResourceLimitExceeded is the error of a declared limit (IE1-028), which IE1-022 gives a
	// package over a limit.
	ResourceLimitExceeded = "ecl.error.resource-limit-exceeded.v1"
)

const (
	schemaInvalid    = "ecl.error.schema-invalid.v1"
	semanticInvalid  = "ecl.error.semantic-invalid.v1"
	integrityInvalid = "ecl.error.integrity-invalid.v1"
	expiredCode      = "ecl.error.expired.v1"
	sha256Algorithm  = "ecl.digest.sha-256.v1"
)

// The roles of which IE1-021 requires at least one artifact, in sorted order.
var requiredRoles = []string{"envelope", "payload", "registry_snapshot", "revocation_snapshot", "time_evidence", "trust_policy", "verification_key"}

// The artifact roles whose envelopes form the package's bundle, and the member each fills.
var evidenceRoles = map[string]string{"envelope": "envelopes", "observation": "observations"}

// The manifest references whose artifacts IE1-021 requires, with the role of each artifact.
var referenceRoles = [][2]string{
	{"trust_policy", "trust_policy"},
	{"revocation_snapshot", "revocation_snapshot"},
	{"registry_snapshots", "registry_snapshot"},
	{"time_evidence", "time_evidence"},
}

// Options are the caller's inputs: the bundle verifier's options, passed to it unchanged, and the
// verifier's declared limits (DefaultLimits when Limits is nil).
type Options struct {
	evidence.Options
	Limits *Limits
}

func issue(code, message string) evidence.BundleFinding {
	return evidence.BundleFinding{Code: code, Message: message}
}

type reference struct {
	role  string
	value any
}

func references(manifest map[string]any) []reference {
	found := []reference{}
	for _, pair := range referenceRoles {
		value := manifest[pair[0]]
		if items, isList := value.([]any); isList {
			for _, item := range items {
				found = append(found, reference{pair[1], item})
			}
		} else {
			found = append(found, reference{pair[1], value})
		}
	}
	return found
}

func member(value any, key string) any {
	object, _ := value.(map[string]any)
	return object[key]
}

// strictJSON parses an artifact as strict JSON, or returns the finding of check 3 or 7.
func strictJSON(data []byte, name string) (any, *evidence.BundleFinding) {
	value, err := strict.Parse(data)
	if err != nil {
		code := schemaInvalid
		var refusal *strict.Error
		if errors.As(err, &refusal) && refusal.RuleID == ResourceLimitExceeded {
			code = ResourceLimitExceeded
		}
		finding := issue(code, name+" is not strict JSON: "+err.Error())
		return nil, &finding
	}
	return value, nil
}

// manifestProblem says why the manifest fails check 3, or "".
func manifestProblem(manifest any) (string, error) {
	object, isObject := manifest.(map[string]any)
	if !isObject {
		return ManifestName + " does not satisfy " + ManifestSchema, nil
	}
	valid, err := schema.ECL().Valid(ManifestSchema, object)
	if err != nil {
		return "", err
	}
	if !valid {
		return ManifestName + " does not satisfy " + ManifestSchema, nil
	}
	if !instant.Valid(object["created_at"]) || !instant.Valid(object["expires_at"]) {
		return "created_at or expires_at is not a valid instant", nil
	}
	artifacts, _ := object["artifacts"].([]any)
	for _, item := range artifacts {
		if member(member(item, "digest"), "algorithm") != sha256Algorithm {
			return fmt.Sprintf("artifact %v has no %s digest", member(item, "path"), sha256Algorithm), nil
		}
	}
	for _, found := range references(object) {
		if member(member(found.value, "digest"), "algorithm") != sha256Algorithm {
			return fmt.Sprintf("a %s reference has no %s digest", found.role, sha256Algorithm), nil
		}
	}
	return "", nil
}

// pathProblem is check 4 on the manifest's artifact paths: they must be entry names that one
// archive could hold together with manifest.json.
func pathProblem(artifacts []map[string]any, limits Limits) *evidence.BundleFinding {
	fail := func(code, message string) *evidence.BundleFinding {
		finding := issue(code, message)
		return &finding
	}
	if int64(len(artifacts)) > limits.MaxMemberCount {
		return fail(ResourceLimitExceeded, "offline package artifact count exceeds the verifier budget")
	}
	seen := map[string]bool{}
	aliases := map[string]bool{}
	for _, item := range artifacts {
		path, _ := item["path"].(string)
		if int64(len(path)) > limits.MaxPathBytes {
			return fail(ResourceLimitExceeded, "an artifact path exceeds the verifier budget")
		}
		if !IsEntryName(path) {
			return fail(semanticInvalid, fmt.Sprintf("unsafe package path: %q is not an ecl.zip.store.v1 entry name", path))
		}
		alias := FoldASCII(path)
		if alias == ManifestName {
			return fail(semanticInvalid, "the manifest names "+ManifestName+", or an alias of it, as an artifact")
		}
		if seen[path] || aliases[alias] {
			return fail(semanticInvalid, "duplicate package path: "+path)
		}
		seen[path] = true
		aliases[alias] = true
	}
	names := []string{ManifestName}
	for path := range seen {
		names = append(names, path)
	}
	sort.Strings(names)
	if conflict, found := fileAndDirectory(names); found {
		return fail(semanticInvalid, "package path is both a file and a directory: "+conflict)
	}
	return nil
}

func micro(value any) instant.Instant {
	parsed, _ := instant.Parse(value)
	return parsed.Micro()
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sizeOf(value any) (int64, bool) {
	number, isNumber := value.(json.Number)
	if !isNumber {
		return 0, false
	}
	size, err := strconv.ParseInt(number.String(), 10, 64)
	return size, err == nil
}

// Verify returns the verdict of an offline package (the archive's bytes) under policy, the
// caller's current trust policy, at options.Now. The policy and the options are the caller's inputs
// to evidence.Verify, which receives them unchanged; nothing the package carries replaces them.
// Package data is reported, never returned as an error. An invalid caller argument is an error
// before the package is read, whatever it holds: invalid limits (ErrInvalidLimits) and every
// option that evidence.Verify refuses; so is envelope.ErrUnsupportedSuite for an ML-DSA-65
// signature that would decide the verdict.
func Verify(data []byte, policy *trust.Policy, options Options) (*evidence.Report, error) {
	limits := DefaultLimits
	if options.Limits != nil {
		limits = *options.Limits
	}
	if err := limits.check(); err != nil {
		return nil, err
	}
	// The bundle verifier checks the caller's options itself, before it reads a bundle: it returns
	// an error for one it refuses, and otherwise reports this empty bundle as invalid. Its report
	// carries what the options give every report (the verification profile among them), so the
	// package's own refusals start from it.
	base, err := evidence.Verify(map[string]any{}, policy, options.Options)
	if err != nil {
		return nil, err
	}
	failed := func(verdict string, findings ...evidence.BundleFinding) (*evidence.Report, error) {
		report := *base
		report.Verdict = verdict
		report.Findings = findings
		// EBMP2-076: the scope follows the package's verdict.
		return evidence.WithScope(&report), nil
	}
	// 1. The container profile, within the verifier's limits.
	members, err := ReadArchive(data, limits)
	if err != nil {
		var refusal *ArchiveError
		if !errors.As(err, &refusal) {
			return nil, err
		}
		code := semanticInvalid
		if refusal.Limit {
			code = ResourceLimitExceeded
		}
		return failed(evidence.Invalid, issue(code, refusal.Message))
	}
	held := map[string][]byte{}
	for _, item := range members {
		held[item.Name] = item.Data
	}
	// 2. The manifest.
	manifestBytes, present := held[ManifestName]
	if !present {
		return failed(evidence.Incomplete, issue(evidence.CausalClosureIncomplete, "there is no "+ManifestName))
	}
	// 3. Strict JSON, its schema, its times and SHA-256 digests.
	parsed, finding := strictJSON(manifestBytes, ManifestName)
	if finding != nil {
		return failed(evidence.Invalid, *finding)
	}
	problem, err := manifestProblem(parsed)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		return failed(evidence.Invalid, issue(schemaInvalid, problem))
	}
	manifest := parsed.(map[string]any)
	listedArtifacts, _ := manifest["artifacts"].([]any)
	artifacts := make([]map[string]any, len(listedArtifacts))
	for index, item := range listedArtifacts {
		artifacts[index], _ = item.(map[string]any)
	}
	// 4. Entry names that one archive could hold with the manifest, naming exactly the other members.
	if unsafe := pathProblem(artifacts, limits); unsafe != nil {
		return failed(evidence.Invalid, *unsafe)
	}
	listed := map[string]bool{}
	for _, item := range artifacts {
		path, _ := item["path"].(string)
		listed[path] = true
	}
	unnamed := []string{}
	for name := range held {
		if name != ManifestName && !listed[name] {
			unnamed = append(unnamed, name)
		}
	}
	if len(unnamed) > 0 {
		sort.Strings(unnamed)
		return failed(evidence.Invalid, issue(semanticInvalid, "the archive holds a member the manifest does not name: "+unnamed[0]))
	}
	// 5. The package's validity interval, to the microsecond.
	createdAt, expiresAt := micro(manifest["created_at"]), micro(manifest["expires_at"])
	if instant.Compare(expiresAt, createdAt) <= 0 {
		return failed(evidence.Invalid, issue(expiredCode, "the package expires no later than it was created"))
	}
	expired := instant.Compare(micro(options.Now), expiresAt) >= 0
	// 6. Size and digest of every artifact the archive holds; check 1 bounded them by the limits.
	carried := map[string][]byte{}
	absent := []string{}
	for _, item := range artifacts {
		path, _ := item["path"].(string)
		content, present := held[path]
		if !present {
			absent = append(absent, path)
			continue
		}
		if size, ok := sizeOf(item["size_bytes"]); !ok || size != int64(len(content)) {
			return failed(evidence.Invalid, issue(integrityInvalid, "the size of "+path+" differs from its manifest entry"))
		}
		if member(item["digest"], "value") != digestHex(content) {
			return failed(evidence.Invalid, issue(integrityInvalid, "the digest of "+path+" differs from its manifest entry"))
		}
		carried[path] = content
	}
	// 7. The evidence bundle: the envelope and observation artifacts.
	bundle := map[string]any{"schema_version": "ecl_evidence_bundle_v1", "envelopes": []any{}}
	payloads := map[string]bool{}
	for _, item := range artifacts {
		role, _ := item["role"].(string)
		path, _ := item["path"].(string)
		target, isEvidence := evidenceRoles[role]
		content, isCarried := carried[path]
		if !isEvidence || !isCarried {
			continue
		}
		value, finding := strictJSON(content, path)
		if finding != nil {
			return failed(evidence.Invalid, *finding)
		}
		object, isObject := value.(map[string]any)
		if !isObject {
			return failed(evidence.Invalid, issue(schemaInvalid, path+" is not a JSON object"))
		}
		listed, _ := bundle[target].([]any)
		bundle[target] = append(listed, object)
		// The bundle verifier refuses an envelope whose payload does not decode (check 9).
		if payload, err := envelope.DecodePayload(object); err == nil {
			payloads[digestHex(payload)] = true
		}
	}
	// 8. Every payload artifact is the payload of a packaged envelope or observation.
	roles := map[string]map[string]bool{}
	for _, item := range artifacts {
		path, _ := item["path"].(string)
		if _, isCarried := carried[path]; !isCarried {
			continue
		}
		role, _ := item["role"].(string)
		if roles[role] == nil {
			roles[role] = map[string]bool{}
		}
		value, _ := member(item["digest"], "value").(string)
		roles[role][value] = true
	}
	stray := []string{}
	for digest := range roles["payload"] {
		if !payloads[digest] {
			stray = append(stray, digest)
		}
	}
	if len(stray) > 0 {
		sort.Strings(stray)
		return failed(evidence.Invalid, issue(integrityInvalid, "a payload artifact is no packaged envelope's payload: sha256 "+stray[0]))
	}
	// 9. The bundle, under the caller's trust policy, history and evaluation time.
	var report *evidence.Report
	if envelopes, _ := bundle["envelopes"].([]any); len(envelopes) > 0 {
		if report, err = evidence.Verify(bundle, policy, options.Options); err != nil {
			return nil, err
		}
		if report.Verdict == evidence.Invalid {
			return report, nil
		}
	}
	// 10. The material IE1-021 requires, every payload, and at least one envelope.
	missing := []string{}
	for _, path := range absent {
		missing = append(missing, "the archive lacks "+path+", which the manifest names")
	}
	for _, role := range requiredRoles {
		if roles[role] == nil {
			missing = append(missing, "no artifact has the required role "+role)
		}
	}
	for _, found := range references(manifest) {
		value, _ := member(member(found.value, "digest"), "value").(string)
		if !roles[found.role][value] {
			missing = append(missing, "the "+found.role+" artifact that the manifest references is not carried")
		}
	}
	uncarried := []string{}
	for digest := range payloads {
		if !roles["payload"][digest] {
			uncarried = append(uncarried, digest)
		}
	}
	sort.Strings(uncarried)
	for _, digest := range uncarried {
		missing = append(missing, "the payload of a packaged envelope is not carried: sha256 "+digest)
	}
	closure := func() []evidence.BundleFinding {
		findings := make([]evidence.BundleFinding, len(missing))
		for index, message := range missing {
			findings[index] = issue(evidence.CausalClosureIncomplete, message)
		}
		return findings
	}
	if report == nil {
		missing = append(missing, "the package carries no envelope")
		return failed(evidence.Incomplete, closure()...)
	}
	if len(missing) > 0 {
		incomplete := *report
		incomplete.Verdict = evidence.Incomplete
		incomplete.Findings = append(closure(), report.Findings...)
		return evidence.WithScope(&incomplete), nil
	}
	// 11. The bundle's own closure, then its verdict.
	if report.Verdict == evidence.Incomplete {
		return report, nil
	}
	if expired && report.Verdict == evidence.Verified {
		stale := *report
		stale.Verdict = evidence.CurrentTrustFailed
		stale.Findings = append(append([]evidence.BundleFinding{}, report.Findings...), issue(expiredCode, fmt.Sprintf("the package expired at %v", manifest["expires_at"])))
		return evidence.WithScope(&stale), nil
	}
	return report, nil
}

// Identifiers returns a package report's identifiers in order, each once, the primary first, as
// the runner's package stage reports them (IE1-022, EBMP2-068; the reference's
// reported_package_identifiers): the codes of its findings in the order of the checks that gave
// them; for a current-trust-failed package, after the expired code of a package that has
// expired, the current status of each envelope that is not valid, in the order of stage 4 of
// EBMP2-068; and for an incomplete package without findings the causal-closure code.
func Identifiers(report *evidence.Report) []string {
	codes := []string{}
	seen := map[string]bool{}
	for _, finding := range report.Findings {
		if !seen[finding.Code] {
			seen[finding.Code] = true
			codes = append(codes, finding.Code)
		}
	}
	if report.Verdict == evidence.CurrentTrustFailed {
		for _, code := range evidence.ReportedIdentifiers(report) {
			if !seen[code] {
				seen[code] = true
				codes = append(codes, code)
			}
		}
		return codes
	}
	if report.Verdict == evidence.Incomplete && len(codes) == 0 {
		return []string{evidence.CausalClosureIncomplete}
	}
	return codes
}
