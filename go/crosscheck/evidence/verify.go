// Package evidence verifies signed ECL evidence bundles offline (EBMP-2 section 11, EBMP2-057 to
// EBMP2-062) under the reference verification profile, ecl.verification-profile.reference.v1.
//
// Every envelope is evaluated twice (TRUST-POLICY-1): historical validity at the object's own
// time under the trust-policy version the object names, or at the earliest trusted time when the
// envelope carries valid trusted-time countersignatures (IE1-032 to IE1-035); and current status
// at the caller's evaluation time under the caller's current policy. Objects are paired by
// identity, never by an event's claimed decision URI; each pair is bound (DCMP-2 section 8,
// EBMP-2 section 10); the events' causal closure is analyzed with the bundle's DCMP-2 messages as
// permitted external predecessors; and each terminal effect gets its evidence level.
//
// The verdict is exactly one of invalid, incomplete, current-trust-failed and verified
// (EBMP2-060). A bundle that would otherwise verify but has a signer that is not acceptable now
// is current-trust-failed, unless the caller explicitly accepts that, and the report says so.
// Malformed bundle input gives an invalid report; only invalid options are an error.
//
// The decision basis (ECL1N-0181, DCMP2-053): every signed decision response is checked under the
// one-way rule as an object. A caller that requires the decision basis also refuses a decision
// response without ecl.ext.decision-basis.v1; a caller that supplies the Consequential Action
// Register also refuses a decision basis that disagrees with it (decision_basis.go).
//
// Pre-release obligations (DCMP2-017, EBMP2-070): an execution_released event whose signed
// response carries an obligation to be met before release, or a witness result required before
// release, records in ecl.ext.obligation-discharge.v1 a discharge of each one; the obligations come
// from the response as the bundle holds it, never from the producer's own list
// (ecl.rule.prerelease-obligations-discharged.v1). A terminal event that records, in
// ecl.ext.mcp-binding.v1, a forward that completed outside the authorization's window or a release
// after valid_until makes the bundle invalid with ecl.error.expired.v1 (EBMP2-072). The use counts
// of consumed authority stay within the authorization's use policy (EBMP2-073), a release of
// single-use authority has its consumption recorded (EBMP2-074), and an event that carries the MCP
// binding names the call that its request bound (EBMP2-075).
//
// Every report carries its scope (EBMP2-076): Established, the checks that the verifier made and
// that held, and NotEstablished, the checks that apply but did not hold or were not made and the
// statements that no verification establishes. ScopeOf computes it from the report.
package evidence

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// Schemas, limits and profiles of the verifier.
const (
	BundleSchema          = "https://externalcontrollayer.ai/ns/schema/evidence-bundle/1"
	TimeAttestationSchema = "https://externalcontrollayer.ai/ns/schema/time-attestation/1"
	MaxEnvelopes          = 256
	MaxObservations       = 256
	MaxTotalPayloadNodes  = 100_000
	ReferenceProfile      = "ecl.verification-profile.reference.v1"
	TrustedTimeProfile    = "ecl.verification-profile.reference-trusted-time.v1"
)

// The verdicts (EBMP2-060).
const (
	Verified           = "verified"
	Invalid            = "invalid"
	Incomplete         = "incomplete"
	CurrentTrustFailed = "current-trust-failed"
)

// The registered errors that a report names.
const (
	TrustedTimeRequired     = "ecl.error.trusted-time-required.v1"
	TrustedTimeInvalid      = "ecl.error.trusted-time-invalid.v1"
	SchemaInvalid           = "ecl.error.schema-invalid.v1"
	SemanticInvalid         = "ecl.error.semantic-invalid.v1"
	IntegrityInvalid        = "ecl.error.integrity-invalid.v1"
	PolicyInvalid           = "ecl.error.signature-policy-invalid.v1"
	Revoked                 = "ecl.error.revoked.v1"
	Expired                 = "ecl.error.expired.v1"
	ResourceLimitExceeded   = "ecl.error.resource-limit-exceeded.v1"
	ThresholdNotMet         = "ecl.error.threshold-not-met.v1"
	CausalClosureIncomplete = "ecl.error.causal-closure-incomplete.v1"
	// ClockRegressed is an object time, or an attested time, later than the evaluation time
	// (EBMP2-057).
	ClockRegressed = "ecl.error.clock-regressed.v1"
)

const outcomeReason = "ecl.ext.outcome-reason.v1"

// EBMP2-070: the record of the obligations that Enforcement proved before the release, the rule
// that checks it, and the names that a witness result required before release takes in it.
const (
	obligationDischarge    = "ecl.ext.obligation-discharge.v1"
	DischargeRule          = "ecl.rule.prerelease-obligations-discharged.v1"
	consequenceCoupling    = "ecl.ext.consequence-coupling.v1"
	witnessObligationType  = "ecl.obligation.verify-witness.v1"
	approvalObligationType = "ecl.obligation.approval-record.v1"
	// ObligationUnproven is the finding of a carried proof that fails one of its checks, or of a
	// stale proof (EBMP2-070).
	ObligationUnproven = "ecl.error.obligation-unproven.v1"
	// The items of the scope that a stated reason keeps out of Established, and the reasons
	// (EBMP2-076).
	ScopeRelease            = "release-within-authority"
	ScopeProofs             = "prerelease-obligations-proofs-verified"
	ReasonNoRelease         = "no-release-recorded"
	ReasonProofNotECLObject = "proof-not-ecl-object"
	ReasonIssuerNotNamed    = "issuer-not-named"
	// EBMP2-072 and EBMP2-075: the MCP binding of a request and of the events of its action.
	mcpBinding = "ecl.ext.mcp-binding.v1"
)

var (
	nowPattern        = regexp.MustCompile(`^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{3}|\.[0-9]{6})?Z$`)
	nonRelease        = map[string]bool{"denied": true, "held": true, "challenged": true, "expired_before_release": true}
	postRelease       = map[string]bool{"during_execution": true, "after_execution": true}
	mcpResponseStates = map[string]bool{"succeeded": true, "failed": true}
)

// EBMP2-076: the scope of a verdict. ScopeChecks are the checks a verifier makes, in the order of
// the table of EBMP2-076; ScopeNever are the statements that no verification establishes. Two
// checks and one statement apply only to some bundles (conditionalScope); the others apply to
// every report.
var (
	ScopeChecks = []string{
		"envelope-signatures",
		"current-trust",
		"trusted-time",
		"object-rules",
		"decision-basis-recorded",
		"decision-basis-register",
		"bindings",
		"release-within-authority",
		"causal-completeness",
		"prerelease-obligations-discharge-recorded",
		"prerelease-obligations-proofs-verified",
	}
	ScopeNever = []string{
		"prerelease-obligations-met",
		"post-release-obligations-met",
		"recorded-times-true",
		"effects-occurred",
		"deployment-assessed",
		"statements-true",
	}
	scopeDischarge   = []string{"prerelease-obligations-discharge-recorded", "prerelease-obligations-proofs-verified", "prerelease-obligations-met"}
	scopePostRelease = "post-release-obligations-met"
	conditionalScope = map[string]bool{scopeDischarge[0]: true, scopeDischarge[1]: true, scopeDischarge[2]: true, scopePostRelease: true}
	// ScopeText is the sentence for people that each item of the scope stands for (the table of
	// EBMP2-076).
	ScopeText = map[string]string{
		"envelope-signatures":                       "each envelope's and observation's payload digest and signatures verify under the trust-policy version its object names, at the object's own time or its trusted time, and the current trust policy revokes none of its trust dependencies at or before its time",
		"current-trust":                             "each trust dependency, each signing key of each envelope and observation and of each time attestation, is acceptable under the current trust policy at the evaluation time",
		"trusted-time":                              "a separate time authority attests a time for each signature of each envelope and observation, binding that signature, each signature was valid at that time, and each time authority's key was valid then and is not revoked by the current trust policy at or before it",
		"object-rules":                              "each signed object satisfies its schema and semantic rules, the one-way rule for a recorded decision basis among them",
		"decision-basis-recorded":                   "each decision response records its decision basis",
		"decision-basis-register":                   "each decision basis agrees with the Consequential Action Register supplied",
		"bindings":                                  "each response binds its request, each event binds its request, response and authority, with the digests and use counts they name, each continuation binds the request, challenge and approval it continues, and each terminal event carries the outcome reason its state and response require",
		"release-within-authority":                  "each recorded release time lies within the authorization's validity window",
		"causal-completeness":                       "over every object of the bundle, observations included, every causal predecessor is in the bundle with the digest that names it and in the workflow, trace and attempt that the rules allow, the graph is acyclic, identifiers are unique, and every request has a terminal event",
		"prerelease-obligations-discharge-recorded": "each release records a discharge of every obligation its decision left to Enforcement before the release, checked no later than the release was observed",
		"prerelease-obligations-proofs-verified":    "each pre-release discharge carries its proof, and each proof is a valid ECL object under the trust policy, signed by the issuer the obligation names, of a type the obligation admits, bound to this exchange and fresh at the release",
		"prerelease-obligations-met":                "that each pre-release obligation was met: the verifier checks a proof's signatures, issuer, type, binding and freshness, not what the proof shows",
		"post-release-obligations-met":              "that the obligations to be met during or after execution were met, which the verifier does not check",
		"recorded-times-true":                       "that each recorded time is the true time of its event: each producer states its own times",
		"effects-occurred":                          "that the effects happened: a terminal event is its producer's statement, and corroboration is another signed statement, an observation bound to that terminal event and its attempt",
		"deployment-assessed":                       "that the deployment that produced the evidence has been assessed or meets ECL-1",
		"statements-true":                           "that the statements in the bundle are true, among them the enforcement point's statements of what it checked and released",
	}
)

// EnvelopeCheck is one envelope's statuses: valid, or the registered error that makes it not so.
type EnvelopeCheck struct {
	Index        int
	ObjectID     *string
	Kind         string
	SignerKeyIDs []string
	Historical   string
	Current      string
	// HistoricalPolicyVersion is the version of the trust policy the object names, when found.
	HistoricalPolicyVersion *string
	// TrustedTime is the earliest valid trusted time, when the envelope carries one.
	TrustedTime *string
}

// TrustDependency is one trust dependency of a bundle (TP1-006): a signing key of an object
// (role signer) or of a time attestation that a trusted-time countersignature of the object
// carries (role time-authority, with the countersignature's counter_id). At is the time of its
// historical check (IE1-034), Historical its status under the policy version that its object or
// attestation names with the current policy's revocations applied, RevokedEffectiveAt the
// effective time of the current policy's revocation of its key identifier, and Current its
// status under the current policy at the evaluation time.
type TrustDependency struct {
	Index                   int
	Role                    string
	CounterID               *string
	KeyID                   string
	Suite                   string
	At                      *string
	HistoricalPolicyVersion *string
	Historical              string
	CurrentPolicyVersion    string
	RevokedEffectiveAt      *string
	Current                 string
}

// ScopeItemChecks are the checks of registries/scope-checks.json that ran for one scope item and
// held, in registry order, and the indexes of the objects they covered (EBMP2-076).
type ScopeItemChecks struct {
	Checks  []string
	Objects []int
}

// BindingCheck is one binding rule applied to a pair of objects.
type BindingCheck struct {
	Name   string
	Passed bool
	Code   *string
}

// EffectEvidence is the evidence level of one terminal effect (EBMP2-061).
type EffectEvidence struct {
	ActionID string
	State    string
	// Level is none, issuer-asserted or corroborated.
	Level string
	// Authority is consumed, issued-unused or none.
	Authority string
	Reason    *string
}

// BundleFinding is a rule that failed: the registered identifier, and a message for people.
type BundleFinding struct {
	Code    string
	Message string
}

// ReportScope is what a verdict establishes and what it does not (EBMP2-076), each in the order
// of the table of EBMP2-076, and the stated reason of each item that a reason keeps out of
// Established: release-within-authority is no-release-recorded when the bundle records no
// release, and prerelease-obligations-proofs-verified is proof-not-ecl-object when an entry's
// proof is not an object of the bundle, or issuer-not-named when every proof is carried and the
// decision names no issuer for an obligation.
type ReportScope struct {
	Established    []string
	NotEstablished []string
	Reasons        map[string]string
	// Checks holds, for each item in Established, the checks that ran for it and the objects
	// they covered (EBMP2-076).
	Checks map[string]ScopeItemChecks
}

// Report is the result of verifying a bundle.
type Report struct {
	Verdict                     string
	EnvelopeChecks              []EnvelopeCheck
	BindingChecks               []BindingCheck
	CausalStatus                string
	Effects                     []EffectEvidence
	Findings                    []BundleFinding
	VerificationProfile         string
	AcceptedCurrentTrustFailure bool
	// Register names the register version that the decision bases were checked against, if the
	// caller gave one: the register member a decision basis would carry for it.
	Register map[string]any
	// Scope is the scope of the verdict (EBMP2-076); ScopeOf computes it from the rest of the
	// report.
	Scope ReportScope
	// CompletionAfterWindow is whether a terminal event records, in the MCP binding, a server
	// answer that arrived at or after the authorization's valid_until (EBMP2-072). The release
	// itself was inside the window, or the bundle is invalid: information, not a finding.
	CompletionAfterWindow bool
	// TrustDependencies are every trust dependency of the bundle (TP1-006), in the order of the
	// objects' indexes, each object's signers before the signers of its time attestations.
	TrustDependencies []TrustDependency
	// EvaluationTime is the evaluation time the verification used, as the caller gave it
	// (EBMP2-057).
	EvaluationTime string
	// UnresolvedPredecessorIDs are the identifiers of the causal predecessors that the bundle does
	// not hold, in ascending code-point order, each once (EBMP-2 section 4).
	UnresolvedPredecessorIDs []string
}

// Options is what the caller supplies besides the bundle and its current trust policy.
type Options struct {
	// Now is the evaluation time: RFC 3339 UTC with 0, 3 or 6 fractional digits.
	Now string
	// History holds exact earlier versions of the same trust policy, which old evidence may name.
	History []*trust.Policy
	// ResponseClockSkewSeconds is the response clock-skew allowance (DCMP2-047); the reference
	// profile's is 0.
	ResponseClockSkewSeconds int64
	// AcceptCurrentTrustFailure reports verified, with the acceptance stated, when a signer is not
	// acceptable now.
	AcceptCurrentTrustFailure bool
	// RequireTrustedTime refuses an envelope without a valid trusted-time countersignature
	// (IE1-035), under ecl.verification-profile.reference-trusted-time.v1.
	RequireTrustedTime bool
	// Register is a Consequential Action Register document, nil for none; each decision basis is
	// checked against it. A value that does not satisfy the register schema or
	// ecl.rule.register-declarations-consistent.v1 is ErrInvalidRegister.
	Register any
}

type entry struct {
	index       int
	observation bool
	envelope    map[string]any
	payload     map[string]any
	check       EnvelopeCheck
	signingKeys map[string]bool
}

type pairs struct {
	requests      map[string]*entry
	requestOrder  []string
	responses     map[string]*entry
	responseOrder []string
	eventRequest  map[int]*entry
	eventResponse map[int]*entry
	consumed      map[string]bool
	released      map[string]bool
	terminal      map[string]bool
	// boundReleases holds the envelope indexes of the execution_released events that bind their
	// request and response.
	boundReleases map[int]bool
	// releaseRecorded is whether any envelope holds an execution_released event (EBMP2-076:
	// no-release-recorded).
	releaseRecorded bool
	// completionAfterWindow is whether a bound terminal records a server answer at or after
	// valid_until (EBMP2-072).
	completionAfterWindow bool
}

// instantPanic is a time the verifier cannot read where the reference fails on it.
type instantPanic struct{ value string }

func nanos(value string) instant.Instant {
	parsed, err := instant.Parse(value)
	if err != nil {
		panic(instantPanic{value})
	}
	return parsed
}

func issue(code, message string) BundleFinding { return BundleFinding{Code: code, Message: message} }

func text(value string) *string { return &value }

// The stages of verification (EBMP2-068), in order.
const (
	stagePayloads = 2
	stageObjects  = 3
	stageSigners  = 4
	stagePairing  = 5
	stageRequests = 6
	stageEvents   = 7
	stageCausal   = 8
	stageReasons  = 9
	stageCount    = 10
)

// rulesSlot stands, in a stage's order, for the registered rules, which rank by their registry
// precedence.
const rulesSlot = "registered rules"

// SignerOrder is the order of stage 4 of EBMP2-068, which also orders the current statuses of a
// bundle whose trust has failed now (EBMP2-060).
var SignerOrder = []string{ClockRegressed, PolicyInvalid, TrustedTimeInvalid, TrustedTimeRequired, Revoked, Expired, ResourceLimitExceeded, IntegrityInvalid, ThresholdNotMet}

// stageOrders gives, within each stage, the order of its findings.
var stageOrders = map[int][]string{
	stagePayloads: {ResourceLimitExceeded, IntegrityInvalid},
	stageObjects:  {SchemaInvalid, rulesSlot, SemanticInvalid},
	stageSigners:  SignerOrder,
	stagePairing:  {SchemaInvalid, DecisionBindingInvalid},
	stageRequests: {RequestBindingInvalid, DigestMismatch, AudienceMismatch, ScopeMismatch},
	stageEvents:   {DecisionBindingInvalid, DigestMismatch, Expired},
	stageCausal:   {ResourceLimitExceeded, rulesSlot, DecisionBindingInvalid, ObligationUnproven},
	stageReasons:  {SemanticInvalid},
}

// stagedFindings holds the findings of one verification by the stage that found them.
type stagedFindings struct {
	stages [stageCount][]BundleFinding
}

func (s *stagedFindings) at(stage int) *[]BundleFinding { return &s.stages[stage] }

func (s *stagedFindings) count() int {
	total := 0
	for _, found := range s.stages {
		total += len(found)
	}
	return total
}

// ordered returns the findings in the order of EBMP2-068: by stage, within a stage by the order
// the stage gives, rules by precedence, and findings that rank alike in the order found. A bundle
// rule ranks in the stage that its registry entry names (stage), by precedence.
func (s *stagedFindings) ordered() []BundleFinding {
	precedence := registry.Precedence()
	stages := registry.Stages()
	var placed [stageCount][]BundleFinding
	for foundAt, found := range s.stages {
		for _, item := range found {
			stage := foundAt
			if named, isBundleRule := stages[item.Code]; isBundleRule && named > 0 && named < stageCount {
				stage = named
			}
			placed[stage] = append(placed[stage], item)
		}
	}
	out := []BundleFinding{}
	for stage, found := range placed {
		order := stageOrders[stage]
		rank := func(code string) (int, int64) {
			for slot, item := range order {
				if item == code {
					return slot, 0
				}
			}
			for slot, item := range order {
				if value, isRule := precedence[code]; item == rulesSlot && isRule {
					return slot, value
				}
			}
			return len(order), 0
		}
		sorted := append([]BundleFinding{}, found...)
		sort.SliceStable(sorted, func(i, j int) bool {
			leftSlot, leftValue := rank(sorted[i].Code)
			rightSlot, rightValue := rank(sorted[j].Code)
			if leftSlot != rightSlot {
				return leftSlot < rightSlot
			}
			return leftValue < rightValue
		})
		out = append(out, sorted...)
	}
	return out
}

func emptyScope() ReportScope {
	return ReportScope{Established: []string{}, NotEstablished: []string{}, Reasons: map[string]string{}, Checks: map[string]ScopeItemChecks{}}
}

func invalidReport(findings ...BundleFinding) *Report {
	return &Report{Verdict: Invalid, EnvelopeChecks: []EnvelopeCheck{}, BindingChecks: []BindingCheck{}, CausalStatus: "not-analyzed", Effects: []EffectEvidence{}, Findings: findings, VerificationProfile: ReferenceProfile, Scope: emptyScope(), TrustDependencies: []TrustDependency{}, UnresolvedPredecessorIDs: []string{}}
}

func countNodes(value any, budget int) int {
	count := 0
	stack := []any{value}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		count++
		if count > budget {
			return count
		}
		switch container := item.(type) {
		case map[string]any:
			for _, child := range container {
				stack = append(stack, child)
			}
		case []any:
			stack = append(stack, container...)
		}
	}
	return count
}

// identifierOf is message_id when it is a non-empty string, else object_id when it is a string.
func identifierOf(payload map[string]any) *string {
	if messageID, ok := pyjson.Text(payload["message_id"]); ok && messageID != "" {
		return &messageID
	}
	if objectID, ok := pyjson.Text(payload["object_id"]); ok {
		return &objectID
	}
	return nil
}

func kindOf(payload map[string]any) string {
	for _, member := range []string{"message_type", "event_type"} {
		if value, ok := pyjson.Text(payload[member]); ok && value != "" {
			return value
		}
	}
	return "unknown"
}

func purposeOf(payload map[string]any, observation bool) string {
	protocol, _ := pyjson.Text(payload["protocol"])
	switch protocol {
	case "DCMP-2":
		switch kind, _ := pyjson.Text(payload["message_type"]); kind {
		case "decision_request":
			return trust.PurposeDecisionRequest
		case "decision_response":
			return trust.PurposeDecisionResponse
		}
	case "EBMP-2":
		if observation {
			return trust.PurposeObservation
		}
		return trust.PurposeEvidenceEvent
	}
	return ""
}

func objectTime(payload map[string]any) (string, bool) {
	switch protocol, _ := pyjson.Text(payload["protocol"]); protocol {
	case "DCMP-2":
		return pyjson.Text(payload["issued_at"])
	case "EBMP-2":
		return pyjson.Text(payload["observed_at"])
	}
	return "", false
}

func principalOf(payload any) (string, bool) {
	member := "producer"
	if protocol, _ := pyjson.Text(pyjson.Get(payload, "protocol")); protocol == "DCMP-2" {
		member = "issuer"
	}
	return pyjson.TextAt(payload, member, "id")
}

func signatureIDs(envelopeValue any) []string {
	signatures, _ := pyjson.Array(pyjson.Get(envelopeValue, "signatures"))
	ids := []string{}
	for _, signature := range signatures {
		if _, isObject := pyjson.Object(signature); !isObject {
			continue
		}
		if keyID, ok := pyjson.Text(pyjson.Get(signature, "key_id")); ok {
			ids = append(ids, keyID)
		}
	}
	return ids
}

func referenceValue(policy *trust.Policy) map[string]any {
	return map[string]any{
		"id": policy.ID, "version": policy.Version, "epoch": policy.Epoch,
		"digest": map[string]any{"algorithm": canon.DigestAlgorithm, "value": policy.Digest},
	}
}

func referenceMatches(policy *trust.Policy, reference any) bool {
	return pyjson.Equal(referenceValue(policy), reference)
}

func findVersion(versions []*trust.Policy, reference any) *trust.Policy {
	for _, version := range versions {
		if referenceMatches(version, reference) {
			return version
		}
	}
	return nil
}

func historyProblem(policy *trust.Policy, history []*trust.Policy) *BundleFinding {
	seen := map[string]bool{policy.Digest: true}
	for _, older := range history {
		if older == nil || older.ID != policy.ID || older.Epoch >= policy.Epoch || seen[older.Digest] {
			problem := issue(PolicyInvalid, "history must hold distinct earlier versions of this policy")
			return &problem
		}
		seen[older.Digest] = true
	}
	return nil
}

// currentRevocation returns the earliest effective time among the current policy's revocations
// that reach a dependency (TP1-006): a revocation of its key identifier, whatever key material the
// current policy holds under it, or of a key that the current policy lists with the dependency's
// public key (publicKey, nil when unknown) under another identifier.
func currentRevocation(current *trust.Policy, keyID string, publicKey []byte) (string, bool) {
	found, earliest := false, ""
	for _, revocation := range current.Revocations {
		matches := revocation.KeyID == keyID
		if !matches && publicKey != nil {
			if listed, held := current.Key(revocation.KeyID); held && hex.EncodeToString(listed.PublicKey) == hex.EncodeToString(publicKey) {
				matches = true
			}
		}
		if matches && (!found || instant.Compare(nanos(revocation.EffectiveAt), nanos(earliest)) < 0) {
			found, earliest = true, revocation.EffectiveAt
		}
	}
	return earliest, found
}

// material returns the public key that policy lists under keyID, or nil.
func material(policy *trust.Policy, keyID string) []byte {
	if policy == nil {
		return nil
	}
	if key, held := policy.Key(keyID); held {
		return key.PublicKey
	}
	return nil
}

// keyTimeStatus is a key's status at `at` under policy: revoked, then outside its validity
// interval. With current, a revocation in the caller's current policy effective at or before at
// also revokes it (TP1-006, ECL1N-0159).
func keyTimeStatus(key trust.Key, policy *trust.Policy, at string, current *trust.Policy) string {
	moment := nanos(at)
	for _, revocation := range policy.Revocations {
		if revocation.KeyID == key.KeyID && instant.Compare(moment, nanos(revocation.EffectiveAt)) >= 0 {
			return Revoked
		}
	}
	if current != nil {
		if revoked, found := currentRevocation(current, key.KeyID, key.PublicKey); found && instant.Compare(moment, nanos(revoked)) >= 0 {
			return Revoked
		}
	}
	if instant.Compare(moment, nanos(key.ValidFrom)) < 0 {
		return Expired
	}
	if key.ValidUntil != "" && instant.Compare(moment, nanos(key.ValidUntil)) >= 0 {
		return Expired
	}
	return "valid"
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

// keyAcceptable is TP1-004, TP1-005 and IE1-040 step 6 (a): the key is the policy's, for the
// entry's suite, with the object's purpose and principal, and, for current status, the same
// public key as the historical check used.
func keyAcceptable(key trust.Key, signature map[string]any, purpose, owner string, hasOwner bool, original *trust.Policy) bool {
	if original != nil {
		old, known := original.Key(key.KeyID)
		if !known || hex.EncodeToString(old.PublicKey) != hex.EncodeToString(key.PublicKey) {
			return false
		}
	}
	return pyjson.Equal(signature["suite_id"], key.SuiteID) && contains(key.Purposes, purpose) && hasOwner && key.Principal == owner
}

// signerStatus checks every signer, counted or not (TP1-004, TP1-005), in the order of IE1-040,
// step 6: every key acceptable for the object's suite, purpose and principal, and for current
// status the same public key as at signing; then no key revoked at its time; then every key
// within its validity interval at its time. A key's time is times[key_id] when given (IE1-034),
// else at; with current, the current policy's revocations apply too (TP1-006).
func signerStatus(envelopeValue, payload map[string]any, policy *trust.Policy, purpose, at string, original *trust.Policy, times map[string]string, current *trust.Policy) string {
	signatures, _ := pyjson.Array(envelopeValue["signatures"])
	owner, hasOwner := principalOf(payload)
	keys := make([]trust.Key, 0, len(signatures))
	for _, item := range signatures {
		signature, _ := pyjson.Object(item)
		keyID, _ := pyjson.Text(signature["key_id"])
		key, known := policy.Key(keyID)
		if !known || !keyAcceptable(key, signature, purpose, owner, hasOwner, original) {
			return PolicyInvalid
		}
		keys = append(keys, key)
	}
	statuses := map[string]bool{}
	for _, key := range keys {
		moment := at
		if own, present := times[key.KeyID]; present {
			moment = own
		}
		statuses[keyTimeStatus(key, policy, moment, current)] = true
	}
	for _, status := range []string{Revoked, Expired} {
		if statuses[status] {
			return status
		}
	}
	return "valid"
}

func checkSignature(envelopeValue, payload map[string]any, policy *trust.Policy, at string, signed *trust.Policy, times map[string]string, current *trust.Policy) (string, map[string]bool, error) {
	timePolicy, _ := pyjson.TextAt(payload, "integrity_policy", "verification_time_policy")
	expected := "ecl.time.observed-at.v1"
	if protocol, _ := pyjson.Text(payload["protocol"]); protocol == "DCMP-2" {
		expected = "ecl.time.issued-at.v1"
	}
	if timePolicy != expected {
		return PolicyInvalid, map[string]bool{}, nil
	}
	context, err := policy.VerificationContext(at, timePolicy)
	if err == nil {
		if signed != nil {
			context.TrustPolicyID, context.TrustPolicyVersion = signed.ID, signed.Version
			context.TrustPolicyDigest, context.TrustPolicyEpoch = signed.Digest, signed.Epoch
		}
		if current != nil {
			// TP1-006: the current policy's revocations reach the historical check.
			context.Revocations = append(append([]envelope.Revocation{}, context.Revocations...), current.Revocations...)
		}
		context.KeyTimes = times
		var result *envelope.Result
		result, err = envelope.Verify(envelopeValue, policy.Keyring(), context)
		if err == nil {
			valid := map[string]bool{}
			for _, keyID := range result.ValidKeyIDs {
				valid[keyID] = true
			}
			return "valid", valid, nil
		}
	}
	// The error code of INTEGRITY-ENVELOPE-1, IE1-040.
	var integrity *envelope.Error
	if errors.As(err, &integrity) {
		return integrity.Code, map[string]bool{}, nil
	}
	var policyFailure *trust.Error
	if errors.As(err, &policyFailure) {
		return IntegrityInvalid, map[string]bool{}, nil
	}
	return "", nil, err
}

// attestation is one valid trusted-time countersignature: its id, attested time and the indexes
// of the envelope's signature entries that it covers.
type attestation struct {
	counterID string
	attested  string
	covered   []int
}

// statementOf returns the decoded time-attestation statement of a countersignature entry.
func statementOf(entry any) (map[string]any, bool) {
	object, isObject := pyjson.Object(entry)
	if !isObject {
		return nil, false
	}
	signedAttestation, isObject := pyjson.Object(object["attestation"])
	if !isObject || !pyjson.Equal(signedAttestation["payload_type"], envelope.TimeAttestationType) {
		return nil, false
	}
	statement, err := envelope.DecodeCanonicalJSONPayload(signedAttestation)
	if err != nil {
		return nil, false
	}
	return pyjson.Object(statement)
}

// coveredIndexes returns the indexes of the envelope's signature entries that covered.signatures
// names, each with its key_id, suite and signature digest, in envelope order and each once
// (IE1-033, IE1-034); false when an entry names no such signature or the order fails.
func coveredIndexes(statement, envelopeValue map[string]any) ([]int, bool) {
	listedValue, _ := pyjson.Path(statement, "covered", "signatures")
	listed, isList := pyjson.Array(listedValue)
	signatures, signaturesOK := pyjson.Array(envelopeValue["signatures"])
	if !isList || len(listed) == 0 || !signaturesOK {
		return nil, false
	}
	digests := make([]map[string]any, len(signatures))
	for position, item := range signatures {
		if digest, err := envelope.SignatureDigest(item); err == nil {
			digests[position] = digest
		}
	}
	var indexes []int
	for _, value := range listed {
		named, isObject := pyjson.Object(value)
		found := -1
		for position, item := range signatures {
			entry, entryIsObject := pyjson.Object(item)
			if isObject && entryIsObject && digests[position] != nil &&
				pyjson.Equal(named["key_id"], entry["key_id"]) && pyjson.Equal(named["suite"], entry["suite_id"]) &&
				pyjson.Equal(named["signature_digest"], digests[position]) {
				found = position
				break
			}
		}
		if found < 0 || (len(indexes) > 0 && found <= indexes[len(indexes)-1]) {
			return nil, false
		}
		indexes = append(indexes, found)
	}
	return indexes, true
}

// attestedTime returns the time one trusted-time countersignature attests and the indexes of the
// signature entries it covers, or ok false when it is not valid (IE1-033, IE1-034, TP1-006).
func attestedTime(countersignature, envelopeValue, payload map[string]any, versions []*trust.Policy, current *trust.Policy) (string, []int, bool, error) {
	signedAttestation, ok := pyjson.Object(countersignature["attestation"])
	if !ok || !pyjson.Equal(signedAttestation["payload_type"], envelope.TimeAttestationType) {
		return "", nil, false, nil
	}
	statementValue, err := envelope.DecodeCanonicalJSONPayload(signedAttestation)
	if err != nil {
		var integrity *envelope.Error
		if errors.As(err, &integrity) {
			return "", nil, false, nil
		}
		return "", nil, false, err
	}
	statement, isObject := pyjson.Object(statementValue)
	if !isObject {
		return "", nil, false, nil
	}
	if valid, err := schema.ECL().Valid(TimeAttestationSchema, statement); err != nil || !valid {
		return "", nil, false, err
	}
	listed, _ := pyjson.Path(statement, "covered", "signatures")
	covered := map[string]any{"media_type": envelopeValue["payload_type"], "digest": envelopeValue["payload_digest"], "signatures": listed}
	indexes, indexesOK := coveredIndexes(statement, envelopeValue)
	issuer, hasIssuer := pyjson.TextAt(statement, "issuer", "id")
	attested, hasAttested := pyjson.TextAt(statement, "issued_at")
	own, hasOwn := objectTime(payload)
	principal, hasPrincipal := principalOf(payload)
	if !pyjson.Equal(pyjson.Get(statement, "attestation_id"), countersignature["counter_id"]) ||
		!pyjson.Equal(pyjson.Get(statement, "claim"), countersignature["claim"]) ||
		!pyjson.Equal(pyjson.Get(statement, "covered"), covered) || !indexesOK ||
		!hasIssuer || (hasPrincipal && issuer == principal) || !hasAttested || !hasOwn ||
		instant.Compare(nanos(own), nanos(attested)) > 0 {
		return "", nil, false, nil
	}
	if timePolicy, _ := pyjson.TextAt(statement, "integrity_policy", "verification_time_policy"); timePolicy != "ecl.time.issued-at.v1" {
		return "", nil, false, nil
	}
	version := attestationVersion(statement, versions)
	if version == nil {
		return "", nil, false, nil
	}
	signatures, _ := pyjson.Array(signedAttestation["signatures"])
	for _, item := range signatures {
		keyID, _ := pyjson.TextAt(item, "key_id")
		key, known := version.Key(keyID)
		// TP1-006: the named version's and the current policy's revocations at the attested time.
		if !known || !pyjson.Equal(pyjson.Get(item, "suite_id"), key.SuiteID) || !contains(key.Purposes, trust.PurposeTrustedTime) || key.Principal != issuer || keyTimeStatus(key, version, attested, current) != "valid" {
			return "", nil, false, nil
		}
	}
	context, err := version.VerificationContext(attested, "ecl.time.issued-at.v1")
	if err == nil {
		context.Revocations = append(append([]envelope.Revocation{}, context.Revocations...), current.Revocations...)
		_, err = envelope.Verify(signedAttestation, version.Keyring(), context)
	}
	if err != nil {
		var integrity *envelope.Error
		var policyFailure *trust.Error
		if errors.As(err, &integrity) || errors.As(err, &policyFailure) {
			return "", nil, false, nil
		}
		return "", nil, false, err
	}
	return attested, indexes, true, nil
}

func attestationVersion(statement map[string]any, versions []*trust.Policy) *trust.Policy {
	reference, _ := pyjson.Path(statement, "integrity_policy", "trust_policy")
	if _, isObject := pyjson.Object(reference); !isObject {
		reference = nil
	}
	return findVersion(versions, reference)
}

func optionalText(value string, present bool) *string {
	if !present {
		return nil
	}
	return text(value)
}

// authorityDependencies returns the trust dependencies of the signers of one time attestation:
// each one's current status under the current policy at now (TP1-006), the same public key as
// the historical check used, the trusted-time purpose and the issuer's principal, then not
// revoked and within its validity interval.
func authorityDependencies(index int, counterID *string, statement map[string]any, signedAttestation map[string]any, valid bool, attested string, versions []*trust.Policy, current *trust.Policy, now string) []TrustDependency {
	var result []TrustDependency
	issuer, hasIssuer := "", false
	var version *trust.Policy
	attestedAt := (*string)(nil)
	if statement != nil {
		issuer, hasIssuer = pyjson.TextAt(statement, "issuer", "id")
		version = attestationVersion(statement, versions)
	}
	if valid {
		attestedAt = text(attested)
	}
	var versionName *string
	if version != nil {
		versionName = text(version.Version)
	}
	signatures, _ := pyjson.Array(signedAttestation["signatures"])
	for _, item := range signatures {
		signature, isObject := pyjson.Object(item)
		if !isObject {
			continue
		}
		keyID, _ := pyjson.Text(signature["key_id"])
		suite, _ := pyjson.Text(signature["suite_id"])
		status := PolicyInvalid
		if key, known := current.Key(keyID); known && version != nil && keyAcceptable(key, signature, trust.PurposeTrustedTime, issuer, hasIssuer, version) {
			status = keyTimeStatus(key, current, now, nil)
		}
		// A signer of a valid attestation whose signature does not verify is not historically valid
		// (decision "A signature that does not verify"); the attestation's validity is unchanged.
		historical := TrustedTimeInvalid
		if valid {
			historical = IntegrityInvalid
			if keyMaterial, held := version.Keyring()[keyID]; held && envelope.SignatureVerifies(signedAttestation, signature, keyMaterial) {
				historical = "valid"
			}
		}
		revoked, found := currentRevocation(current, keyID, material(version, keyID))
		result = append(result, TrustDependency{
			Index: index, Role: "time-authority", CounterID: counterID, KeyID: keyID, Suite: suite, At: attestedAt,
			HistoricalPolicyVersion: versionName, Historical: historical, CurrentPolicyVersion: current.Version,
			RevokedEffectiveAt: optionalText(revoked, found), Current: status,
		})
	}
	return result
}

// countersignaturesOf returns each trusted-time countersignature of the envelope, valid, and the
// trust dependencies of the time authorities' signers; failed is true when one of them is not
// valid.
func countersignaturesOf(envelopeValue, payload map[string]any, index int, versions []*trust.Policy, current *trust.Policy, now string) ([]attestation, bool, []TrustDependency, error) {
	entries, present := envelopeValue["countersignatures"]
	if !present || entries == nil {
		return nil, false, nil, nil
	}
	list, _ := pyjson.Array(entries)
	var valid []attestation
	var dependencies []TrustDependency
	failed := false
	for _, item := range list {
		countersignature, isObject := pyjson.Object(item)
		ok, attested, covered := false, "", []int(nil)
		if isObject && pyjson.Equal(countersignature["claim"], envelope.TrustedTimeClaim) {
			var err error
			if attested, covered, ok, err = attestedTime(countersignature, envelopeValue, payload, versions, current); err != nil {
				return nil, false, nil, err
			}
		}
		var counterID *string
		var signedAttestation map[string]any
		if isObject {
			if identifier, isText := pyjson.Text(countersignature["counter_id"]); isText {
				counterID = text(identifier)
			}
			signedAttestation, _ = pyjson.Object(countersignature["attestation"])
		}
		statement, _ := statementOf(item)
		if signedAttestation != nil {
			dependencies = append(dependencies, authorityDependencies(index, counterID, statement, signedAttestation, ok, attested, versions, current, now)...)
		}
		if !ok {
			failed = true
			continue
		}
		identifier := ""
		if counterID != nil {
			identifier = *counterID
		}
		valid = append(valid, attestation{counterID: identifier, attested: attested, covered: covered})
	}
	return valid, failed, dependencies, nil
}

// laterThanNow reports whether the object's own time, or the attested time of one of its
// trusted-time countersignatures, is later than the evaluation time (EBMP2-057, F08).
func laterThanNow(envelopeValue, payload map[string]any, now string) bool {
	limit := nanos(now)
	var times []any
	if own, hasOwn := objectTime(payload); hasOwn {
		times = append(times, own)
	}
	entries, _ := pyjson.Array(envelopeValue["countersignatures"])
	for _, item := range entries {
		if statement, ok := statementOf(item); ok {
			times = append(times, statement["issued_at"])
		}
	}
	for _, value := range times {
		if moment, ok := instantOrNone(value); ok && instant.Compare(moment, limit) > 0 {
			return true
		}
	}
	return false
}

// envelopeWide are the statuses of an envelope that are not any one signer's: each of its
// signers takes it.
var envelopeWide = map[string]bool{ClockRegressed: true, TrustedTimeInvalid: true, TrustedTimeRequired: true}

// signerDependencies returns each signer of the envelope as a trust dependency (TP1-006), with
// the time of its historical check, its historical status under the named version and the
// current policy's revocations, and its current status under the current policy at now.
func signerDependencies(envelopeValue, payload map[string]any, index int, purpose string, version, current *trust.Policy, now string, times map[string]string, at string, envelopeStatus string) []TrustDependency {
	owner, hasOwner := principalOf(payload)
	var result []TrustDependency
	signatures, _ := pyjson.Array(envelopeValue["signatures"])
	for _, item := range signatures {
		signature, isObject := pyjson.Object(item)
		if !isObject {
			continue
		}
		keyID, _ := pyjson.Text(signature["key_id"])
		suite, _ := pyjson.Text(signature["suite_id"])
		own := at
		if moment, present := times[keyID]; present {
			own = moment
		}
		historical := PolicyInvalid
		key, known := version.Key(keyID)
		switch {
		case envelopeWide[envelopeStatus]:
			historical = envelopeStatus
		case !known || !keyAcceptable(key, signature, purpose, owner, hasOwner, nil):
			historical = PolicyInvalid
		default:
			historical = keyTimeStatus(key, version, own, current)
			if historical == "valid" {
				if material, present := version.Keyring()[keyID]; !present || !envelope.SignatureVerifies(envelopeValue, signature, material) {
					historical = IntegrityInvalid
				}
			}
		}
		status := PolicyInvalid
		if present, inCurrent := current.Key(keyID); inCurrent && keyAcceptable(present, signature, purpose, owner, hasOwner, version) {
			status = keyTimeStatus(present, current, now, nil)
		}
		revoked, found := currentRevocation(current, keyID, material(version, keyID))
		// A dependency not evaluated, because the envelope's status was decided for the whole
		// envelope, has no time of its own.
		at := text(own)
		if envelopeWide[envelopeStatus] {
			at = nil
		}
		result = append(result, TrustDependency{
			Index: index, Role: "signer", KeyID: keyID, Suite: suite, At: at,
			HistoricalPolicyVersion: text(version.Version), Historical: historical, CurrentPolicyVersion: current.Version,
			RevokedEffectiveAt: optionalText(revoked, found), Current: status,
		})
	}
	return result
}

// plainDependencies returns each signer of an envelope that was not evaluated, with status.
func plainDependencies(envelopeValue any, index int, status string, version, current *trust.Policy) []TrustDependency {
	var result []TrustDependency
	signatures, _ := pyjson.Array(pyjson.Get(envelopeValue, "signatures"))
	var versionName *string
	if version != nil {
		versionName = text(version.Version)
	}
	for _, item := range signatures {
		if _, isObject := pyjson.Object(item); !isObject {
			continue
		}
		keyID, _ := pyjson.TextAt(item, "key_id")
		suite, _ := pyjson.TextAt(item, "suite_id")
		revoked, found := currentRevocation(current, keyID, material(version, keyID))
		result = append(result, TrustDependency{
			Index: index, Role: "signer", KeyID: keyID, Suite: suite, HistoricalPolicyVersion: versionName,
			Historical: status, CurrentPolicyVersion: current.Version, RevokedEffectiveAt: optionalText(revoked, found), Current: status,
		})
	}
	return result
}

func evaluateEnvelope(envelopeValue, payload map[string]any, index int, observation bool, current *trust.Policy, versions []*trust.Policy, now string, findings *[]BundleFinding, requireTrustedTime bool) (EnvelopeCheck, map[string]bool, []TrustDependency, bool, error) {
	check := EnvelopeCheck{Index: index, ObjectID: identifierOf(payload), Kind: kindOf(payload), SignerKeyIDs: signatureIDs(envelopeValue)}
	invalid, err := objectFindings(payload)
	if err != nil {
		return check, nil, nil, false, err
	}
	if len(invalid) > 0 {
		// EBMP2-068, stage 3: an object that fails its schema is schema-invalid; one that satisfies
		// it but fails a semantic rule is semantic-invalid, which ranks after the rules, so that
		// the object's own primary finding (DCMP2-043) leads.
		status := SemanticInvalid
		for _, item := range invalid {
			*findings = append(*findings, issue(item.RuleID, fmt.Sprintf("object %d: %s: %s", index, item.Path, item.Detail)))
			if item.RuleID == SchemaInvalid {
				status = SchemaInvalid
			}
		}
		check.Historical, check.Current = status, status
		return check, map[string]bool{}, plainDependencies(envelopeValue, index, status, nil, current), false, nil
	}
	purpose := purposeOf(payload, observation)
	at, hasTime := objectTime(payload)
	reference, _ := pyjson.Path(payload, "integrity_policy", "trust_policy")
	if _, isObject := pyjson.Object(reference); !isObject {
		reference = nil
	}
	version := findVersion(versions, reference)
	if purpose == "" || !hasTime || version == nil {
		check.Historical, check.Current = PolicyInvalid, PolicyInvalid
		return check, map[string]bool{}, plainDependencies(envelopeValue, index, PolicyInvalid, version, current), false, nil
	}
	attestations, failed, authorities, err := countersignaturesOf(envelopeValue, payload, index, versions, current, now)
	if err != nil {
		return check, nil, nil, false, err
	}
	// IE1-034: a covered signature is evaluated at the earliest attested time among the valid
	// countersignatures that cover it, every other one at the object's own time.
	entries := signatureEntries(envelopeValue)
	times := map[string]string{}
	coveredAll := false
	trusted := ""
	if !failed && len(attestations) > 0 {
		for _, item := range attestations {
			for _, position := range item.covered {
				keyID := entries[position]
				if previous, present := times[keyID]; !present || instant.Compare(nanos(item.attested), nanos(previous)) < 0 {
					times[keyID] = item.attested
				}
			}
			if trusted == "" || instant.Compare(nanos(item.attested), nanos(trusted)) < 0 {
				trusted = item.attested
			}
		}
		coveredAll = true
		for position := range entries {
			covered := false
			for _, item := range attestations {
				for _, index := range item.covered {
					covered = covered || index == position
				}
			}
			coveredAll = coveredAll && covered
		}
	}
	signed := map[string]bool{}
	var dependencies []TrustDependency
	historical, currentStatus, err := func() (historical, currentStatus string, err error) {
		// The reference reports a time it cannot read here as schema-invalid for both statuses.
		defer func() {
			if recovered := recover(); recovered != nil {
				if _, isInstant := recovered.(instantPanic); !isInstant {
					panic(recovered)
				}
				historical, currentStatus, err = SchemaInvalid, SchemaInvalid, nil
				dependencies = plainDependencies(envelopeValue, index, SchemaInvalid, version, current)
				coveredAll = false
			}
		}()
		switch {
		case laterThanNow(envelopeValue, payload, now):
			historical = ClockRegressed
		case failed:
			historical = TrustedTimeInvalid
		case requireTrustedTime && !coveredAll:
			historical = TrustedTimeRequired
		default:
			historical = signerStatus(envelopeValue, payload, version, purpose, at, nil, times, current)
			if historical == "valid" {
				if historical, signed, err = checkSignature(envelopeValue, payload, version, at, nil, times, current); err != nil {
					return "", "", err
				}
			}
		}
		currentStatus = signerStatus(envelopeValue, payload, current, purpose, now, version, nil, nil)
		if currentStatus == "valid" {
			if currentStatus, _, err = checkSignature(envelopeValue, payload, current, now, version, nil, nil); err != nil {
				return "", "", err
			}
		}
		dependencies = signerDependencies(envelopeValue, payload, index, purpose, version, current, now, times, at, historical)
		return historical, currentStatus, nil
	}()
	if err != nil {
		return check, nil, nil, false, err
	}
	check.Historical, check.Current = historical, currentStatus
	signingKeys := map[string]bool{}
	for keyID := range signed {
		if key, known := version.Key(keyID); known {
			signingKeys[key.SuiteID+":"+hex.EncodeToString(key.PublicKey)] = true
		}
	}
	check.HistoricalPolicyVersion = text(version.Version)
	if trusted != "" {
		check.TrustedTime = text(trusted)
	}
	return check, signingKeys, append(dependencies, authorities...), coveredAll, nil
}

// signatureEntries returns the key_id of each signature entry, in envelope order.
func signatureEntries(envelopeValue map[string]any) []string {
	signatures, _ := pyjson.Array(envelopeValue["signatures"])
	result := make([]string, 0, len(signatures))
	for _, item := range signatures {
		if _, isObject := pyjson.Object(item); !isObject {
			continue
		}
		keyID, _ := pyjson.TextAt(item, "key_id")
		result = append(result, keyID)
	}
	return result
}

func attemptKey(payload map[string]any, event bool) (string, bool) {
	container := "action"
	if event {
		container = "event"
	}
	actionID, hasAction := pyjson.TextAt(payload, container, "action_id")
	workflowID, hasWorkflow := pyjson.TextAt(payload, "workflow", "workflow_id")
	attemptValue, _ := pyjson.Path(payload, "workflow", "attempt")
	attempt, isInt := pyjson.Int(attemptValue)
	if !hasAction || !hasWorkflow || !isInt {
		return "", false
	}
	encoded, _ := json.Marshal([]any{actionID, workflowID, attempt})
	return string(encoded), true
}

func runBinding(name string, check func() error, checks *[]BindingCheck, findings *[]BundleFinding) (bool, error) {
	err := check()
	var binding *BindingError
	switch {
	case errors.As(err, &binding):
		*checks = append(*checks, BindingCheck{Name: name, Passed: false, Code: text(binding.Code)})
		*findings = append(*findings, issue(binding.Code, name+" does not bind"))
		return false, nil
	case err != nil:
		return false, err
	}
	*checks = append(*checks, BindingCheck{Name: name, Passed: true})
	return true, nil
}

func referenceDigestMatches(reference map[string]any, value any) bool {
	digest, err := canon.Reference(value)
	return err == nil && pyjson.Equal(reference["digest"], digest)
}

func checkAuthorityDigest(event, response *entry, findings *[]BundleFinding) {
	reference, ok := pyjson.ObjectAt(event.payload, "event", "authority")
	if !ok {
		return
	}
	authorization, ok := pyjson.ObjectAt(response.payload, "authorization")
	if !ok || !referenceDigestMatches(reference, authorization) {
		*findings = append(*findings, issue(DigestMismatch, "event authority digest does not match the grant"))
	}
}

func checkEventMessageReferences(entries []*entry, found *pairs, checks *[]BindingCheck, findings *[]BundleFinding) {
	responses := map[string]*entry{}
	for _, key := range found.responseOrder {
		response := found.responses[key]
		if identifier := identifierOf(response.payload); identifier != nil {
			responses[*identifier] = response
		}
	}
	for _, item := range entries {
		if protocol, _ := pyjson.Text(item.payload["protocol"]); item.observation || protocol != "EBMP-2" {
			continue
		}
		for _, field := range []string{"request", "decision"} {
			targets := found.requests
			if field == "decision" {
				targets = responses
			}
			reference, ok := pyjson.ObjectAt(item.payload, "event", field)
			if !ok {
				continue
			}
			uri, isText := pyjson.Text(reference["uri"])
			target := targets[uri]
			name := fmt.Sprintf("%s-reference:%d", field, item.index)
			if !isText || target == nil {
				*checks = append(*checks, BindingCheck{Name: name, Code: text(DecisionBindingInvalid)})
				*findings = append(*findings, issue(DecisionBindingInvalid, "event "+field+" has no message"))
				continue
			}
			eventWorkflow, _ := pyjson.ObjectAt(item.payload, "workflow")
			targetWorkflow, _ := pyjson.ObjectAt(target.payload, "workflow")
			mismatch := false
			for _, member := range []string{"workflow_id", "root_trace_id", "attempt"} {
				if !pyjson.Equal(eventWorkflow[member], targetWorkflow[member]) {
					mismatch = true
				}
			}
			if mismatch {
				*checks = append(*checks, BindingCheck{Name: name, Code: text(DecisionBindingInvalid)})
				*findings = append(*findings, issue(DecisionBindingInvalid, "event "+field+" belongs to another workflow"))
				continue
			}
			if _, present := reference["digest"]; present && !referenceDigestMatches(reference, target.payload) {
				*checks = append(*checks, BindingCheck{Name: name, Code: text(DigestMismatch)})
				*findings = append(*findings, issue(DigestMismatch, "event "+field+" digest does not match"))
				continue
			}
			*checks = append(*checks, BindingCheck{Name: name, Passed: true})
			if field == "decision" && item.check.Kind == "decision_recorded" {
				event, _ := pyjson.ObjectAt(item.payload, "event")
				contentName := fmt.Sprintf("decision-content:%d", item.index)
				if !pyjson.Equal(event["outcome"], target.payload["outcome"]) || !pyjson.Equal(event["policy"], target.payload["policy"]) {
					*checks = append(*checks, BindingCheck{Name: contentName, Code: text(DecisionBindingInvalid)})
					*findings = append(*findings, issue(DecisionBindingInvalid, "decision event contradicts its response"))
				} else {
					*checks = append(*checks, BindingCheck{Name: contentName, Passed: true})
				}
			}
		}
	}
}

// checkAttemptIdentity applies EBMP2-066: the execution events of one action attempt
// (event.action_id, workflow.workflow_id, workflow.attempt) carry one event.attempt_id, and one
// attempt identifier names one such attempt. One finding reports the first conflict.
func checkAttemptIdentity(main []*entry, findings *[]BundleFinding) {
	byKey := map[string]string{}
	byAttempt := map[string]string{}
	for _, item := range main {
		payload := item.payload
		protocol, _ := pyjson.Text(payload["protocol"])
		kind, _ := pyjson.TextAt(payload, "event", "kind")
		if protocol != "EBMP-2" || kind != "execution" {
			continue
		}
		key, hasKey := attemptKey(payload, true)
		attemptID, hasAttempt := pyjson.TextAt(payload, "event", "attempt_id")
		if !hasKey || !hasAttempt {
			continue
		}
		if _, seen := byKey[key]; !seen {
			byKey[key] = attemptID
		}
		if _, seen := byAttempt[attemptID]; !seen {
			byAttempt[attemptID] = key
		}
		if byKey[key] != attemptID || byAttempt[attemptID] != key {
			*findings = append(*findings, issue(DecisionBindingInvalid, "execution events of one attempt carry different attempt identifiers"))
			return
		}
	}
}

// instantOrNone reads an ECL instant, and reports none for a value that is not one, so that a
// check that needs a time leaves a malformed value to the schema rules.
func instantOrNone(value any) (instant.Instant, bool) {
	parsed, err := instant.Parse(value)
	return parsed, err == nil
}

// extensionValues returns the value of each occurrence of one extension whose value is an object,
// in order.
func extensionValues(value map[string]any, identifier string) []map[string]any {
	extensions, _ := pyjson.Array(value["extensions"])
	var found []map[string]any
	for _, item := range extensions {
		extension, isObject := pyjson.Object(item)
		if !isObject {
			continue
		}
		id, isText := pyjson.Text(extension["id"])
		inner, innerIsObject := pyjson.Object(extension["value"])
		if isText && id == identifier && innerIsObject {
			found = append(found, inner)
		}
	}
	return found
}

// useLimit gives the uses that an authorization allows (EBMP2-073): 1 when it is single_use,
// otherwise its max_uses when it has one, and no limit otherwise.
func useLimit(response map[string]any) (int64, bool) {
	authorization, ok := pyjson.ObjectAt(response, "authorization")
	if !ok {
		return 0, false
	}
	if policy, _ := pyjson.Text(authorization["use_policy"]); policy == "single_use" {
		return 1, true
	}
	return pyjson.Int(authorization["max_uses"])
}

// authorityUse is an authority_consumed event in state consumed that binds its response.
type authorityUse struct {
	event    *entry
	response *entry
}

// checkUseCounts applies EBMP2-073: for each authorization, the authority_consumed events in state
// consumed that bind its response give use counts from 1 to the uses it allows, no two alike, and
// are no more than it allows. Findings of stage 7 of EBMP2-068.
func checkUseCounts(consumed []authorityUse, findings *[]BundleFinding) {
	byAuthorization := map[string][]authorityUse{}
	var order []string
	for _, item := range consumed {
		identifier, ok := pyjson.TextAt(item.event.payload, "event", "authorization_id")
		if !ok {
			continue
		}
		if _, seen := byAuthorization[identifier]; !seen {
			order = append(order, identifier)
		}
		byAuthorization[identifier] = append(byAuthorization[identifier], item)
	}
	for _, identifier := range order {
		uses := byAuthorization[identifier]
		limit, limited := useLimit(uses[0].response.payload)
		counts := map[int64]bool{}
		repeated := false
		for _, item := range uses {
			event, _ := pyjson.ObjectAt(item.event.payload, "event")
			count, isInt := pyjson.Int(event["use_count"])
			if !isInt {
				continue
			}
			if count < 1 || (limited && count > limit) {
				*findings = append(*findings, issue(DecisionBindingInvalid, fmt.Sprintf("envelope %d: the use count is outside the authorization's use policy", item.event.index)))
			}
			repeated = repeated || counts[count]
			counts[count] = true
		}
		if repeated {
			*findings = append(*findings, issue(DecisionBindingInvalid, "two consumptions of one authorization record one use"))
		}
		if limited && int64(len(uses)) > limit {
			*findings = append(*findings, issue(DecisionBindingInvalid, "an authorization is consumed more often than its use policy allows"))
		}
	}
}

// releasedAfterValidUntil reports whether a terminal event records, in the MCP binding, that the
// gateway observed after its write that the authorization's valid_until had passed (EBMP2-072).
func releasedAfterValidUntil(terminal map[string]any) bool {
	for _, value := range extensionValues(terminal, mcpBinding) {
		if late, isBool := value["released_after_valid_until"].(bool); isBool && late {
			return true
		}
	}
	return false
}

// completedAfterWindow reports whether a terminal event records, in the MCP binding, a
// forward_completed_at at or after the authorization's valid_until: the server's answer came
// late, which is not a finding about the release (EBMP2-072).
func completedAfterWindow(terminal, response map[string]any) bool {
	authorization, _ := pyjson.ObjectAt(response, "authorization")
	end, hasEnd := instantOrNone(authorization["valid_until"])
	if !hasEnd {
		return false
	}
	for _, value := range extensionValues(terminal, mcpBinding) {
		if completed, hasCompleted := instantOrNone(value["forward_completed_at"]); hasCompleted && instant.Compare(completed, end) >= 0 {
			return true
		}
	}
	return false
}

// releaseGuardNs returns the release guard an execution_released event declares, in nanoseconds,
// or false when the event does not carry it as an integer (its schema then refuses it) (EBMP2-071).
func releaseGuardNs(event map[string]any) (int64, bool) {
	body, _ := pyjson.ObjectAt(event, "event")
	milliseconds, isInt := pyjson.Int(body["release_guard_ms"])
	if !isInt {
		return 0, false
	}
	return milliseconds * 1_000_000, true
}

// mcpBindingProblem applies EBMP2-075: when the request carries the MCP binding, each occurrence of
// it in an execution event carries every member of the request's value with the same value, and a
// succeeded or failed terminal event binds the server's response by its digest. It returns the
// problem, or "" for none.
func mcpBindingProblem(event, request map[string]any) string {
	decided := extensionValues(request, mcpBinding)
	if len(decided) == 0 {
		return ""
	}
	call := decided[0]
	recorded := extensionValues(event, mcpBinding)
	for _, value := range recorded {
		for member, expected := range call {
			if got, present := value[member]; !present || !pyjson.Equal(got, expected) {
				return "the event's MCP binding names another call than its request"
			}
		}
	}
	eventType, _ := pyjson.Text(event["event_type"])
	state, _ := pyjson.TextAt(event, "event", "state")
	if eventType != "execution_terminal" || !mcpResponseStates[state] {
		return ""
	}
	for _, value := range recorded {
		if _, present := value["response_digest"]; present {
			return ""
		}
	}
	return "the terminal event binds no server response"
}

// pairMain pairs objects and checks their bindings: stages 5 to 7 of EBMP2-068.
func pairMain(entries []*entry, checks *[]BindingCheck, staged *stagedFindings, skew int64) (*pairs, error) {
	pairing, requestsBinding, events := staged.at(stagePairing), staged.at(stageRequests), staged.at(stageEvents)
	var main []*entry
	for _, item := range entries {
		if !item.observation {
			main = append(main, item)
		}
	}
	found := &pairs{requests: map[string]*entry{}, responses: map[string]*entry{}, eventRequest: map[int]*entry{}, eventResponse: map[int]*entry{}, consumed: map[string]bool{}, released: map[string]bool{}, terminal: map[string]bool{}, boundReleases: map[int]bool{}}
	byAction := map[string]*entry{}
	// EBMP2-073: each authority_consumed event in state consumed that binds its response.
	var uses []authorityUse
	for _, item := range main {
		if item.check.Kind != "decision_request" {
			continue
		}
		identifier := identifierOf(item.payload)
		key, ok := attemptKey(item.payload, false)
		if identifier == nil || !ok {
			*pairing = append(*pairing, issue(SchemaInvalid, "a request lacks an identity or action"))
			continue
		}
		if _, repeated := found.requests[*identifier]; repeated {
			*pairing = append(*pairing, issue(DecisionBindingInvalid, "requests repeat an identity or action"))
			continue
		}
		if _, repeated := byAction[key]; repeated {
			*pairing = append(*pairing, issue(DecisionBindingInvalid, "requests repeat an identity or action"))
			continue
		}
		found.requests[*identifier] = item
		found.requestOrder = append(found.requestOrder, *identifier)
		byAction[key] = item
	}
	for _, item := range main {
		if item.check.Kind != "decision_response" {
			continue
		}
		requestID, ok := pyjson.Text(item.payload["request_id"])
		request := found.requests[requestID]
		if !ok || request == nil {
			*pairing = append(*pairing, issue(DecisionBindingInvalid, "a response has no request"))
			continue
		}
		if _, repeated := found.responses[requestID]; repeated {
			*pairing = append(*pairing, issue(DecisionBindingInvalid, "a request has multiple responses"))
			continue
		}
		found.responses[requestID] = item
		found.responseOrder = append(found.responseOrder, requestID)
		response := item
		if _, err := runBinding(fmt.Sprintf("response:%d", item.index), func() error {
			return CheckResponseBinding(request.payload, response.payload, skew)
		}, checks, requestsBinding); err != nil {
			return nil, err
		}
	}
	checkAttemptIdentity(main, pairing)
	for _, item := range main {
		payload := item.payload
		if protocol, _ := pyjson.Text(payload["protocol"]); protocol != "EBMP-2" {
			continue
		}
		kind := item.check.Kind
		if kind == "authority_issued" || kind == "authority_consumed" {
			authorizationID, hasID := pyjson.TextAt(payload, "event", "authorization_id")
			var matches []*entry
			for _, key := range found.responseOrder {
				candidate := found.responses[key]
				granted, grantedOK := pyjson.TextAt(candidate.payload, "authorization", "authorization_id")
				if grantedOK == hasID && granted == authorizationID {
					matches = append(matches, candidate)
				}
			}
			if len(matches) != 1 {
				*pairing = append(*pairing, issue(DecisionBindingInvalid, "an authority event has no unique response"))
				continue
			}
			response := matches[0]
			requestID, _ := pyjson.Text(response.payload["request_id"])
			request := found.requests[requestID]
			if request == nil {
				*pairing = append(*pairing, issue(DecisionBindingInvalid, "an authority event has no request"))
				continue
			}
			found.eventRequest[item.index] = request
			found.eventResponse[item.index] = response
			event := item
			passed, err := runBinding(fmt.Sprintf("authority:%d", item.index), func() error {
				return CheckAuthorityEventBinding(event.payload, response.payload)
			}, checks, events)
			if err != nil {
				return nil, err
			}
			checkAuthorityDigest(item, response, events)
			state, _ := pyjson.TextAt(payload, "event", "state")
			if key, ok := attemptKey(request.payload, false); passed && ok && item.check.Historical == "valid" && state == "consumed" {
				found.consumed[key] = true
			}
			if passed && kind == "authority_consumed" && state == "consumed" {
				uses = append(uses, authorityUse{item, response})
			}
			continue
		}
		if kind != "execution_released" && kind != "execution_terminal" {
			continue
		}
		found.releaseRecorded = found.releaseRecorded || kind == "execution_released"
		key, hasKey := attemptKey(payload, true)
		var request *entry
		if hasKey {
			request = byAction[key]
		}
		if request == nil {
			*pairing = append(*pairing, issue(DecisionBindingInvalid, "an execution event has no request"))
			continue
		}
		var paired *entry
		if requestID := identifierOf(request.payload); requestID != nil {
			paired = found.responses[*requestID]
		}
		found.eventRequest[item.index] = request
		found.eventResponse[item.index] = paired
		event := item
		passed, err := runBinding(fmt.Sprintf("execution:%d", item.index), func() error {
			var response any
			if paired != nil {
				response = paired.payload
			}
			return CheckEventBinding(event.payload, request.payload, response)
		}, checks, events)
		if err != nil {
			return nil, err
		}
		if paired != nil {
			checkAuthorityDigest(item, paired, events)
		}
		if passed {
			// EBMP2-075: an event that carries the MCP binding names the call its request bound.
			if problem := mcpBindingProblem(payload, request.payload); problem != "" {
				*events = append(*events, issue(DecisionBindingInvalid, fmt.Sprintf("envelope %d: %s", item.index, problem)))
			}
		}
		if kind == "execution_terminal" {
			found.terminal[key] = true
			if passed && paired != nil {
				// EBMP2-072: a terminal event that records that the release completed after the
				// authorization's valid_until; a late answer from the server is information.
				if releasedAfterValidUntil(payload) {
					*events = append(*events, issue(Expired, fmt.Sprintf("envelope %d: the terminal event records that the release completed after the authorization's valid_until", item.index)))
				}
				if completedAfterWindow(payload, paired.payload) {
					found.completionAfterWindow = true
				}
			}
		}
		if passed && kind == "execution_released" {
			found.released[key] = true
			found.boundReleases[item.index] = true
			var start, end string
			var hasStart, hasEnd bool
			if paired != nil {
				if authorization, ok := pyjson.ObjectAt(paired.payload, "authorization"); ok {
					start, hasStart = pyjson.Text(authorization["valid_from"])
					end, hasEnd = pyjson.Text(authorization["valid_until"])
				}
			}
			observed, hasObserved := pyjson.Text(payload["observed_at"])
			guard, hasGuard := releaseGuardNs(payload)
			// EBMP2-050 and EBMP2-071: the release is observed no earlier than valid_from, and the
			// observation plus the declared release guard is earlier than valid_until.
			if !hasStart || !hasEnd || !hasObserved || !hasGuard || instant.Compare(nanos(start), nanos(observed)) > 0 || instant.Compare(nanos(observed).AddNanoseconds(guard), nanos(end)) >= 0 {
				*events = append(*events, issue(Expired, "the release, with its declared release guard, lies outside the authorization's validity window"))
			}
		}
	}
	checkUseCounts(uses, events)
	for _, item := range main {
		if item.check.Kind != "execution_terminal" {
			continue
		}
		key, ok := attemptKey(item.payload, true)
		state, hasState := pyjson.TextAt(item.payload, "event", "state")
		if !ok || !hasState || !nonRelease[state] {
			continue
		}
		event, _ := pyjson.ObjectAt(item.payload, "event")
		_, carriesAuthority := event["authority"]
		if found.consumed[key] || found.released[key] || carriesAuthority || pyjson.Truthy(event["side_effects"]) {
			*events = append(*events, issue(DecisionBindingInvalid, "a non-release terminal contradicts authority use or release"))
		}
	}
	return found, nil
}

// obligationKey names an obligation by its obligation_id and type.
type obligationKey struct{ id, kind string }

// obligationKeys applies EBMP2-070 to one decision response. It returns the obligations the
// response leaves to Enforcement before the release, in order and each once: each obligation whose
// satisfaction is before_release, and a witness result whose outcome is required_before_release,
// named by the uri of its reference and the type ecl.obligation.verify-witness.v1; every
// obligation it carries, the witness result included; whether it carries an obligation to be met
// during or after execution (EBMP2-076); and the value of each obligation it carries, the
// witness's URI for the witness result.
func obligationKeys(response map[string]any) ([]obligationKey, map[obligationKey]bool, bool, map[obligationKey]any) {
	var required []obligationKey
	carried := map[obligationKey]bool{}
	values := map[obligationKey]any{}
	post := false
	require := func(key obligationKey) {
		for _, item := range required {
			if item == key {
				return
			}
		}
		required = append(required, key)
	}
	obligations, _ := pyjson.Array(response["obligations"])
	for _, value := range obligations {
		item, isObject := pyjson.Object(value)
		if !isObject {
			continue
		}
		identifier, hasID := pyjson.Text(item["id"])
		kind, hasKind := pyjson.Text(item["type"])
		if !hasID || !hasKind {
			continue
		}
		key := obligationKey{identifier, kind}
		carried[key] = true
		if _, known := values[key]; !known {
			values[key] = item["value"]
		}
		satisfaction, isText := pyjson.Text(item["satisfaction"])
		if isText && satisfaction == "before_release" {
			require(key)
		} else if isText && postRelease[satisfaction] {
			post = true
		}
	}
	for _, value := range extensionValues(response, consequenceCoupling) {
		witness, isObject := pyjson.Object(value["witness_result"])
		if !isObject {
			continue
		}
		uri, hasURI := pyjson.TextAt(witness, "reference", "uri")
		if outcome, _ := pyjson.Text(witness["outcome"]); outcome == "required_before_release" && hasURI {
			key := obligationKey{uri, witnessObligationType}
			carried[key] = true
			if _, known := values[key]; !known {
				values[key] = uri
			}
			require(key)
		}
	}
	return required, carried, post, values
}

// witnessSource returns the source that the response's witness result names for witness, if it
// names one: the issuer that a verify-witness obligation names (EBMP2-070, condition b).
func witnessSource(response map[string]any, witness string) (string, bool) {
	for _, value := range extensionValues(response, consequenceCoupling) {
		result, isObject := pyjson.Object(value["witness_result"])
		if !isObject {
			continue
		}
		uri, _ := pyjson.TextAt(result, "reference", "uri")
		if source, isText := pyjson.Text(result["source"]); isText && uri == witness {
			return source, true
		}
	}
	return "", false
}

// dischargeEntry is an entry of ecl.ext.obligation-discharge.v1 that is an object, with the index
// of its extension and its position in obligations.
type dischargeEntry struct {
	extension, position int
	item                map[string]any
}

// discharges reports whether an event carries ecl.ext.obligation-discharge.v1, and returns each
// entry of it that is an object.
func discharges(event map[string]any) (bool, []dischargeEntry) {
	extensions, _ := pyjson.Array(event["extensions"])
	present := false
	var found []dischargeEntry
	for index, value := range extensions {
		extension, isObject := pyjson.Object(value)
		if !isObject {
			continue
		}
		if id, _ := pyjson.Text(extension["id"]); id != obligationDischarge {
			continue
		}
		present = true
		listed, _ := pyjson.Array(pyjson.Get(extension["value"], "obligations"))
		for position, item := range listed {
			if object, isObject := pyjson.Object(item); isObject {
				found = append(found, dischargeEntry{index, position, object})
			}
		}
	}
	return present, found
}

// release is what the conditions of EBMP2-070 compare an entry with: the bound release's request
// and response, the release's observation and declared guard, the response's issue time, the
// response clock-skew allowance and the request's actor.
type release struct {
	request, response map[string]any
	observed          instant.Instant
	hasObserved       bool
	guard             int64
	hasGuard          bool
	issued            instant.Instant
	hasIssued         bool
	skew              int64
	actor             string
	hasActor          bool
}

// deadline is the release plus its declared release guard, before which every proof must be fresh.
func (r release) deadline() (instant.Instant, bool) {
	if !r.hasObserved || !r.hasGuard {
		return instant.Instant{}, false
	}
	return r.observed.AddNanoseconds(r.guard), true
}

// dischargeProblem is a condition that an entry fails: the finding code, the path below the entry
// and a message.
type dischargeProblem struct{ code, suffix, message string }

// dischargeProblems applies conditions 2 to 4 of EBMP2-070 and the freshness of a recorded
// fresh_until to one entry that names an obligation of the response, each checked on members
// present with the types the value schema gives them, as the reference's _discharge_problems.
func dischargeProblems(item map[string]any, rel release) []dischargeProblem {
	var problems []dischargeProblem
	if result, isText := pyjson.Text(item["result"]); isText && result != "satisfied" {
		problems = append(problems, dischargeProblem{DischargeRule, "/result", "records an obligation that was not met"})
	}
	checked, hasChecked := instantOrNone(item["checked_at"])
	if hasChecked && rel.hasObserved && instant.Compare(checked, rel.observed) > 0 {
		problems = append(problems, dischargeProblem{DischargeRule, "/checked_at", "was checked after the release was observed"})
	}
	skew := rel.skew
	if skew < 0 {
		skew = 0
	}
	if hasChecked && rel.hasIssued && instant.Compare(checked, rel.issued.AddSeconds(-skew)) < 0 {
		problems = append(problems, dischargeProblem{DischargeRule, "/checked_at", "was checked before the decision was issued"})
	}
	if proof, isObject := pyjson.Object(item["proof"]); isObject {
		obtained, hasObtained := instantOrNone(proof["obtained_at"])
		if hasObtained && hasChecked && instant.Compare(obtained, checked) > 0 {
			problems = append(problems, dischargeProblem{DischargeRule, "/proof/obtained_at", "has a proof obtained after it was checked"})
		}
	}
	// EBMP2-070, freshness: the release plus its declared guard comes before fresh_until.
	fresh, hasFresh := instantOrNone(item["fresh_until"])
	if deadline, hasDeadline := rel.deadline(); hasFresh && hasDeadline && instant.Compare(deadline, fresh) >= 0 {
		problems = append(problems, dischargeProblem{ObligationUnproven, "/fresh_until", "is not later than the release plus its declared release guard"})
	}
	return problems
}

// signerPrincipals returns the principals that the trust-policy version an object names binds to
// the keys that signed its envelope (EBMP2-070, condition b).
func signerKeys(item *entry, versions []*trust.Policy) []trust.Key {
	keys := []trust.Key{}
	reference, _ := pyjson.Path(item.payload, "integrity_policy", "trust_policy")
	version := findVersion(versions, reference)
	if version == nil {
		return keys
	}
	for _, keyID := range signatureIDs(item.envelope) {
		if key, found := version.Key(keyID); found {
			keys = append(keys, key)
		}
	}
	return keys
}

func principalsOf(keys []trust.Key) map[string]bool {
	principals := map[string]bool{}
	for _, key := range keys {
		principals[key.Principal] = true
	}
	return principals
}

// allHoldPurpose reports whether there is at least one key and every key holds purpose.
func allHoldPurpose(keys []trust.Key, purpose string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, key := range keys {
		if !slices.Contains(key.Purposes, purpose) {
			return false
		}
	}
	return true
}

// issuerNamed reports whether the decision names an issuer for the obligation (EBMP2-070,
// condition b): a verify-witness obligation names the source of its witness result, when the
// response gives one; an approval obligation's issuer is the approval service, which the trust
// policy marks with the approval purpose; an obligation of any other type names none. When none
// is named, the issuer test is not made and the scope item is not established (EBMP2-076,
// issuer-not-named).
func issuerNamed(key obligationKey, value any, response map[string]any) bool {
	switch key.kind {
	case approvalObligationType:
		return true
	case witnessObligationType:
		witness, isText := pyjson.Text(value)
		if !isText {
			return false
		}
		_, named := witnessSource(response, witness)
		return named
	}
	return false
}

// namesTheRequest reports whether a causal predecessor of the proof names the decision request by
// its message_id and its digest (EBMP2-070, condition d).
func namesTheRequest(proof, request map[string]any) bool {
	predecessors, _ := pyjson.Path(proof, "workflow", "causal_predecessors")
	listed, _ := pyjson.Array(predecessors)
	identifier, hasID := pyjson.Text(request["message_id"])
	for _, value := range listed {
		predecessor, isObject := pyjson.Object(value)
		if !isObject {
			continue
		}
		if id, isText := pyjson.Text(predecessor["id"]); isText && hasID && id == identifier && referenceDigestMatches(predecessor, request) {
			return true
		}
	}
	return false
}

// proofProblems applies conditions a to e of EBMP2-070 to a carried proof: the object of the
// bundle that the entry names by reference, whose digest the entry records, as the reference's
// _proof_problems: (a) the object is a valid envelope under the trust policy; (b) the trust policy
// binds its signing keys to the issuer the obligation names, when it names one, and never to the
// requesting actor; (c) the object is of a type the obligation admits, and never a decision
// message; (d) a causal predecessor names the decision request with its digest, and an approval's
// target_id is the request; (e) the object is fresh at the release plus its declared guard, by the
// bound the object declares, and the recorded fresh_until is not later than that bound.
// For an approval obligation the issuer test of (b) is that every signing key holds the
// approval purpose.
func proofProblems(item map[string]any, key obligationKey, value any, proof *entry, rel release, versions []*trust.Policy) []dischargeProblem {
	const path = "/proof/reference"
	if proof.check.Historical != "valid" {
		return []dischargeProblem{{ObligationUnproven, path, "names a proof whose envelope is not valid under the trust policy"}}
	}
	var problems []dischargeProblem
	payload := proof.payload
	witness, isWitness := "", false
	if key.kind == witnessObligationType {
		witness, isWitness = pyjson.Text(value)
	}
	// (b) The signers, as the trust policy binds the keys.
	keys := signerKeys(proof, versions)
	principals := principalsOf(keys)
	if isWitness {
		if issuer, named := witnessSource(rel.response, witness); named && !(len(principals) == 1 && principals[issuer]) {
			problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a proof not signed by the issuer the obligation names"})
		}
	}
	if rel.hasActor && principals[rel.actor] {
		problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a proof that the requesting actor signed"})
	}
	if proofType, _ := pyjson.Text(payload["event_type"]); key.kind == approvalObligationType && proofType == "human_intervention" && !allHoldPurpose(keys, trust.PurposeApproval) {
		// The approval service's keys hold the approval purpose (MG1-013): any other trusted
		// producer of evidence events, the enforcement point itself among them, could otherwise
		// sign an approval of its own request.
		problems = append(problems, dischargeProblem{ObligationUnproven, path, "names an approval record signed by a key without the approval purpose"})
	}
	// (c) The type the obligation admits.
	if protocol, _ := pyjson.Text(payload["protocol"]); protocol != "EBMP-2" {
		problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a decision message as a proof"})
		return problems
	}
	eventType, _ := pyjson.Text(payload["event_type"])
	event, _ := pyjson.ObjectAt(payload, "event")
	switch key.kind {
	case witnessObligationType:
		if eventType != "verification" {
			problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a proof of a type the obligation does not admit"})
		} else {
			if subject, _ := pyjson.TextAt(event, "subject", "uri"); !isWitness || subject != witness {
				problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a witness result of another witness"})
			}
			if decision, _ := pyjson.Text(event["decision"]); decision != "pass" {
				problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a witness result that did not pass"})
			}
		}
	case approvalObligationType:
		if eventType != "human_intervention" {
			problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a proof of a type the obligation does not admit"})
		} else {
			approver, hasApprover := pyjson.Text(pyjson.Get(value, "approver"))
			if operation, _ := pyjson.Text(event["operation"]); operation != "approve" {
				problems = append(problems, dischargeProblem{ObligationUnproven, path, "names an intervention that does not approve"})
			}
			if actor, _ := pyjson.TextAt(event, "actor", "id"); !hasApprover || actor != approver {
				problems = append(problems, dischargeProblem{ObligationUnproven, path, "names an approval by an approver other than the one the obligation names"})
			}
		}
	}
	// (d) The binding to this exchange.
	if eventType == "human_intervention" {
		requestID, hasRequestID := pyjson.Text(rel.request["message_id"])
		if target, isText := pyjson.Text(event["target_id"]); !isText || !hasRequestID || target != requestID {
			problems = append(problems, dischargeProblem{ObligationUnproven, path, "names an approval of another request"})
		}
	}
	if !namesTheRequest(payload, rel.request) {
		problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a proof whose causal predecessors do not name this request with its digest"})
	}
	// (e) Freshness by the bound the proof declares: an intervention expires at expires_at.
	if eventType == "human_intervention" {
		bound, hasBound := instantOrNone(event["expires_at"])
		if deadline, hasDeadline := rel.deadline(); hasBound && hasDeadline {
			if instant.Compare(deadline, bound) >= 0 {
				problems = append(problems, dischargeProblem{ObligationUnproven, path, "names a proof that expired before the release plus its declared release guard"})
			}
			if fresh, hasFresh := instantOrNone(item["fresh_until"]); hasFresh && instant.Compare(fresh, bound) > 0 {
				problems = append(problems, dischargeProblem{ObligationUnproven, "/fresh_until", "is later than the bound the proof declares"})
			}
		}
	}
	return problems
}

// checkObligationDischarge applies EBMP2-070 to each execution_released event that binds its
// request and response: the obligations its response leaves to Enforcement before the release
// each have a consistent discharge, no entry names an obligation the response does not carry
// or names one twice, and each proof that the bundle carries passes conditions a to e. The
// obligations come from the signed response that the bundle holds. Findings belong to stage 8 of
// EBMP2-068, the stage of ecl.rule.prerelease-obligations-discharged.v1.
//
// It returns whether the rule applied to a release whose response leaves an obligation to
// Enforcement, whether a response that a release records carries an obligation to be met during
// or after execution, whether an entry's proof is not an object of the bundle, and whether the
// decision names no issuer for an obligation whose proof is carried: the conditional items and the
// reason of the report's scope (EBMP2-076); and the indexes of the carried proofs that the entries
// name (the discharge-entries object set).
func checkObligationDischarge(entries []*entry, found *pairs, findings *[]BundleFinding, versions []*trust.Policy, skew int64) (bool, bool, bool, bool, map[int]bool) {
	proofs := map[int]bool{}
	objects := map[string]*entry{}
	for _, item := range entries {
		if identifier := identifierOf(item.payload); identifier != nil {
			objects[*identifier] = item
		}
	}
	applied, post, uncarried, unnamed := false, false, false, false
	for _, item := range entries {
		if item.observation || !found.boundReleases[item.index] {
			continue
		}
		response, request := found.eventResponse[item.index], found.eventRequest[item.index]
		if response == nil || request == nil {
			continue
		}
		required, carried, carriesPost, values := obligationKeys(response.payload)
		post = post || carriesPost
		applied = applied || len(required) > 0
		present, listed := discharges(item.payload)
		if len(listed) > 0 {
			// discharge-entries: each release that carries entries, with the proofs they name.
			proofs[item.index] = true
		}
		if len(required) > 0 && !present {
			*findings = append(*findings, issue(DischargeRule, fmt.Sprintf("object %d: the release rests on obligations left to Enforcement and records no discharge", item.index)))
			continue
		}
		rel := release{request: request.payload, response: response.payload, skew: skew}
		rel.observed, rel.hasObserved = instantOrNone(item.payload["observed_at"])
		rel.guard, rel.hasGuard = releaseGuardNs(item.payload)
		rel.issued, rel.hasIssued = instantOrNone(response.payload["issued_at"])
		rel.actor, rel.hasActor = pyjson.TextAt(request.payload, "actor", "id")
		named := map[obligationKey]bool{}
		for _, discharged := range listed {
			path := fmt.Sprintf("object %d: /extensions/%d/value/obligations/%d", item.index, discharged.extension, discharged.position)
			identifier, hasID := pyjson.Text(discharged.item["obligation_id"])
			kind, hasKind := pyjson.Text(discharged.item["type"])
			if !hasID || !hasKind {
				continue
			}
			key := obligationKey{identifier, kind}
			if !carried[key] {
				*findings = append(*findings, issue(DischargeRule, path+": names an obligation the response does not carry"))
				continue
			}
			if named[key] {
				*findings = append(*findings, issue(DischargeRule, path+": names an obligation that another entry names"))
				continue
			}
			named[key] = true
			problems := dischargeProblems(discharged.item, rel)
			proof, proofIsObject := pyjson.Object(discharged.item["proof"])
			var carriedProof *entry
			if proofIsObject {
				if reference, isText := pyjson.Text(proof["reference"]); isText {
					carriedProof = objects[reference]
				}
			}
			if carriedProof != nil {
				proofs[carriedProof.index] = true
			}
			digest, digestIsObject := pyjson.Object(pyjson.Get(discharged.item["proof"], "digest"))
			switch {
			case carriedProof == nil:
				// The proof is not an object of the bundle: not an ECL object that the verifier
				// can check (EBMP2-076, proof-not-ecl-object).
				uncarried = true
			case digestIsObject && !referenceDigestMatches(map[string]any{"digest": digest}, carriedProof.payload):
				problems = append(problems, dischargeProblem{DischargeRule, "/proof/digest", "names an object of the bundle by another digest"})
			default:
				if !issuerNamed(key, values[key], rel.response) {
					// The decision names no issuer, so the issuer test of condition b is not made
					// and the proofs are not reported verified (EBMP2-076, issuer-not-named).
					unnamed = true
				}
				problems = append(problems, proofProblems(discharged.item, key, values[key], carriedProof, rel, versions)...)
			}
			for _, problem := range problems {
				*findings = append(*findings, issue(problem.code, path+problem.suffix+": "+problem.message))
			}
		}
		for _, key := range required {
			if !named[key] {
				*findings = append(*findings, issue(DischargeRule, fmt.Sprintf("object %d: an obligation left to Enforcement has no discharge", item.index)))
			}
		}
	}
	return applied, post, uncarried, unnamed, proofs
}

func reasonOf(item *entry, response *entry, findings *[]BundleFinding) *string {
	state, hasState := pyjson.TextAt(item.payload, "event", "state")
	extensions, _ := pyjson.Array(item.payload["extensions"])
	var matching []map[string]any
	for _, extension := range extensions {
		if object, isObject := pyjson.Object(extension); isObject && pyjson.Equal(object["id"], outcomeReason) {
			matching = append(matching, object)
		}
	}
	if len(matching) > 1 {
		*findings = append(*findings, issue(SemanticInvalid, "a terminal has multiple outcome reasons"))
	}
	if len(matching) > 0 {
		value, isObject := pyjson.Object(matching[0]["value"])
		code, isText := pyjson.Text(pyjson.Get(value, "code"))
		_, hasCode := value["code"]
		if !isObject || len(value) != 1 || !hasCode || !isText || !registry.ActiveIDs("error-codes", "", "")[code] {
			*findings = append(*findings, issue(SemanticInvalid, "a terminal has an invalid outcome reason"))
			return nil
		}
		if hasState && state == "succeeded" {
			*findings = append(*findings, issue(SemanticInvalid, "a succeeded terminal has an outcome reason"))
		}
		return text(code)
	}
	outcome, hasOutcome := "", false
	if response != nil {
		outcome, hasOutcome = pyjson.Text(response.payload["outcome"])
	}
	if hasState && (state == "expired_before_release" || (state == "denied" && (!hasOutcome || outcome == "admit"))) {
		*findings = append(*findings, issue(SemanticInvalid, "a terminal is missing its required outcome reason"))
	}
	if hasState && nonRelease[state] && response != nil {
		if reasons, isList := pyjson.Array(response.payload["reasons"]); isList && len(reasons) > 0 {
			if first, isObject := pyjson.Object(reasons[0]); isObject {
				if code, isText := pyjson.Text(first["code"]); isText {
					return text(code)
				}
				return nil
			}
		}
	}
	return nil
}

func disjoint(left, right map[string]bool) bool {
	for item := range left {
		if right[item] {
			return false
		}
	}
	return true
}

func corroborated(terminal *entry, observations []*entry) bool {
	event, _ := pyjson.ObjectAt(terminal.payload, "event")
	effects, isList := pyjson.Array(event["side_effects"])
	if !isList || len(effects) == 0 || len(terminal.signingKeys) == 0 {
		return false
	}
	terminalAt, hasTime := pyjson.Text(terminal.payload["observed_at"])
	producer, hasProducer := principalOf(terminal.payload)
	workflow, hasWorkflow := pyjson.TextAt(terminal.payload, "workflow", "workflow_id")
	context, _ := pyjson.ObjectAt(terminal.payload, "workflow")
	if !hasTime || !hasProducer || !hasWorkflow {
		return false
	}
	for _, effect := range effects {
		object, isObject := pyjson.Object(effect)
		if !isObject {
			return false
		}
		if _, digestIsObject := pyjson.Object(object["digest"]); !digestIsObject {
			return false
		}
		matched := false
		for _, observation := range observations {
			payload := observation.payload
			subject, hasSubject := pyjson.ObjectAt(payload, "event", "subject")
			observedAt, hasObserved := pyjson.Text(payload["observed_at"])
			decision, _ := pyjson.TextAt(payload, "event", "decision")
			principal, hasPrincipal := principalOf(payload)
			observedWorkflow, hasObservedWorkflow := pyjson.TextAt(payload, "workflow", "workflow_id")
			if observation.check.Historical == "valid" &&
				len(observation.signingKeys) > 0 &&
				disjoint(terminal.signingKeys, observation.signingKeys) &&
				observation.check.Kind == "verification" &&
				decision == "pass" &&
				hasSubject &&
				pyjson.Equal(subject["uri"], object["uri"]) &&
				pyjson.Equal(subject["digest"], object["digest"]) &&
				(!hasPrincipal || principal != producer) &&
				hasObservedWorkflow && observedWorkflow == workflow &&
				sameObservedAttempt(payload, context) && namesTheTerminal(payload, terminal.payload) &&
				hasObserved &&
				instant.Compare(nanos(observedAt), nanos(terminalAt)) >= 0 {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// effectsOf returns each terminal's evidence level (EBMP2-061); corroborated only when the
// bundle's causal closure is complete.
// sameObservedAttempt reports whether an observation has the terminal's root trace and attempt.
func sameObservedAttempt(observation, terminalWorkflow map[string]any) bool {
	workflow, _ := pyjson.ObjectAt(observation, "workflow")
	attempt, isInt := pyjson.Int(workflow["attempt"])
	terminalAttempt, terminalIsInt := pyjson.Int(terminalWorkflow["attempt"])
	return pyjson.Equal(workflow["root_trace_id"], terminalWorkflow["root_trace_id"]) && isInt && terminalIsInt && attempt == terminalAttempt
}

func effectsOf(entries []*entry, found *pairs, findings *[]BundleFinding, closureComplete bool) []EffectEvidence {
	var observations []*entry
	for _, item := range entries {
		if item.observation {
			observations = append(observations, item)
		}
	}
	result := []EffectEvidence{}
	for _, item := range entries {
		if item.observation || item.check.Kind != "execution_terminal" {
			continue
		}
		payload := item.payload
		actionID, _ := pyjson.TextAt(payload, "event", "action_id")
		state, _ := pyjson.TextAt(payload, "event", "state")
		if state == "" {
			state = "unknown"
		}
		key, hasKey := attemptKey(payload, true)
		response := found.eventResponse[item.index]
		authority := "none"
		if hasKey && found.consumed[key] {
			authority = "consumed"
		} else if response != nil {
			if outcome, _ := pyjson.Text(response.payload["outcome"]); outcome == "admit" {
				authority = "issued-unused"
			}
		}
		level := "issuer-asserted"
		if item.check.Historical != "valid" {
			level = "none"
		}
		if level == "issuer-asserted" && state == "succeeded" && closureComplete && corroborated(item, observations) {
			level = "corroborated"
		}
		reason := reasonOf(item, response, findings)
		result = append(result, EffectEvidence{ActionID: actionID, State: state, Level: level, Authority: authority, Reason: reason})
	}
	return result
}

func verifyChecked(source any, policy *trust.Policy, now string, history []*trust.Policy, skew int64, accept, requireTrustedTime bool, register map[string]any) (*Report, error) {
	if policy == nil {
		return invalidReport(issue(PolicyInvalid, "the current trust policy is not loaded")), nil
	}
	if problem := historyProblem(policy, history); problem != nil {
		return invalidReport(*problem), nil
	}
	bundle, ok := pyjson.Object(source)
	if !ok {
		return invalidReport(issue(SchemaInvalid, "the evidence bundle is not a JSON object")), nil
	}
	envelopes, envelopesOK := pyjson.Array(bundle["envelopes"])
	var observations []any
	observationsOK := true
	if listed, present := bundle["observations"]; present {
		observations, observationsOK = pyjson.Array(listed)
	}
	if !envelopesOK || !observationsOK {
		return invalidReport(issue(SchemaInvalid, "envelopes and observations must be arrays")), nil
	}
	if len(envelopes) > MaxEnvelopes {
		return invalidReport(issue(ResourceLimitExceeded, fmt.Sprintf("envelopes exceed the %d entry limit", MaxEnvelopes))), nil
	}
	if len(observations) > MaxObservations {
		return invalidReport(issue(ResourceLimitExceeded, fmt.Sprintf("observations exceed the %d entry limit", MaxObservations))), nil
	}
	if valid, err := schema.ECL().Valid(BundleSchema, bundle); err != nil {
		return nil, err
	} else if !valid {
		return invalidReport(issue(SchemaInvalid, "the evidence bundle does not satisfy its schema")), nil
	}
	staged := &stagedFindings{}
	checks := []EnvelopeCheck{}
	bindings := []BindingCheck{}
	type decodedEnvelope struct {
		index       int
		observation bool
		envelope    map[string]any
		payload     map[string]any
	}
	var decoded []decodedEnvelope
	nodeCount := 0
	budgetExceeded := func() *Report {
		*staged.at(stagePayloads) = append(*staged.at(stagePayloads), issue(ResourceLimitExceeded, fmt.Sprintf("decoded payloads exceed the %d node budget", MaxTotalPayloadNodes)))
		report := invalidReport(staged.ordered()...)
		report.EnvelopeChecks = checks
		return report
	}
	all := append(append([]any{}, envelopes...), observations...)
	for index, value := range all {
		observation := index >= len(envelopes)
		// EBMP2-062: each payload is parsed with the nodes that remain of the bundle's budget as
		// its value limit, so that no payload is built beyond the budget (IE1-029; EBMP2-068,
		// stage 2).
		payloadValue, err := envelope.DecodeCanonicalJSONPayloadWithin(value, max(MaxTotalPayloadNodes-nodeCount, 1))
		payload, isObject := pyjson.Object(payloadValue)
		if err == nil && !isObject {
			err = &envelope.Error{Code: IntegrityInvalid, Message: "signed payload is not an object"}
		}
		if err != nil {
			var integrity *envelope.Error
			if !errors.As(err, &integrity) {
				return nil, err
			}
			if integrity.NodeBudget {
				return budgetExceeded(), nil
			}
			// A declared limit that the strict parse of the payload reaches is a resource limit;
			// any other failure leaves it outside canonical strict JSON (IE1-040, step 3).
			code := IntegrityInvalid
			if integrity.Code == ResourceLimitExceeded {
				code = ResourceLimitExceeded
			}
			checks = append(checks, EnvelopeCheck{Index: index, Kind: "unknown", SignerKeyIDs: signatureIDs(value), Historical: code, Current: code})
			*staged.at(stagePayloads) = append(*staged.at(stagePayloads), issue(code, fmt.Sprintf("envelope %d has an invalid payload", index)))
			continue
		}
		nodeCount += countNodes(payload, MaxTotalPayloadNodes-nodeCount)
		if nodeCount > MaxTotalPayloadNodes {
			return budgetExceeded(), nil
		}
		envelopeObject, _ := pyjson.Object(value)
		decoded = append(decoded, decodedEnvelope{index, observation, envelopeObject, payload})
	}
	versions := append([]*trust.Policy{policy}, history...)
	var entries []*entry
	seenIDs := map[string]bool{}
	dependencies := []TrustDependency{}
	covered := map[int]bool{}
	for _, item := range decoded {
		check, signingKeys, depends, coveredAll, err := evaluateEnvelope(item.envelope, item.payload, item.index, item.observation, policy, versions, now, staged.at(stageObjects), requireTrustedTime)
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
		dependencies = append(dependencies, depends...)
		covered[item.index] = coveredAll
		entries = append(entries, &entry{index: item.index, observation: item.observation, envelope: item.envelope, payload: item.payload, check: check, signingKeys: signingKeys})
		if check.Historical == SchemaInvalid || check.Historical == SemanticInvalid {
			// The object's own schema or semantic rules refuse it, and their findings are listed;
			// its signatures were not evaluated, so this is a finding of stage 3, not one about the
			// signers.
			*staged.at(stageObjects) = append(*staged.at(stageObjects), issue(check.Historical, fmt.Sprintf("envelope %d holds an object that fails its schema or semantic rules", item.index)))
		} else if check.Historical != "valid" {
			// Any other status is the signers', a finding of stage 4.
			*staged.at(stageSigners) = append(*staged.at(stageSigners), issue(check.Historical, fmt.Sprintf("envelope %d is not historically valid", item.index)))
		}
		if check.ObjectID != nil {
			if seenIDs[*check.ObjectID] {
				*staged.at(stageObjects) = append(*staged.at(stageObjects), issue("ecl.rule.bundle-object-identifiers-unique.v1", "message or object identifier is duplicated"))
			}
			seenIDs[*check.ObjectID] = true
		}
		if protocol, _ := pyjson.Text(item.payload["protocol"]); item.observation && (protocol != "EBMP-2" || check.Kind != "verification") {
			*staged.at(stageObjects) = append(*staged.at(stageObjects), issue(SemanticInvalid, "an observation is not a verification event"))
		}
	}
	// The decision-basis rules are findings of stage 3, ranked by their precedence (EBMP2-068).
	if err := checkDecisionBases(entries, staged.at(stageObjects), register, skew); err != nil {
		return nil, err
	}
	found, err := pairMain(entries, &bindings, staged, skew)
	if err != nil {
		return nil, err
	}
	continuationMissing, continuationNamed := checkContinuations(entries, staged.at(stagePairing), versions)
	checkEventMessageReferences(entries, found, &bindings, staged.at(stageEvents))
	dischargeApplied, carriesPost, uncarried, unnamed, proofs := checkObligationDischarge(entries, found, staged.at(stageCausal), versions, skew)
	// EBMP2-059: one causal graph over every object of the bundle, DCMP-2 messages (by
	// message_id) and observations included, with no external predecessor, and EBMP2-077.
	records := make([]any, 0, len(entries))
	for _, item := range entries {
		records = append(records, item.payload)
	}
	analysis, err := AnalyzeGraph(records, map[string]bool{}, MaxRecords, MaxPredecessors, []string{"object_id", "message_id"}, true)
	if err != nil {
		return nil, err
	}
	for _, item := range analysis.Findings {
		*staged.at(stageCausal) = append(*staged.at(stageCausal), issue(item.RuleID, "causal graph: "+item.Path+": "+item.Detail))
	}
	// EBMP2-055 and EBMP2-074 run for every attempt whose own objects the bundle holds, whatever the
	// closure; they stay silent only for an attempt whose own objects name an unresolved
	// predecessor, which could be the consumption or the release they look for.
	unresolved := map[string]bool{}
	for _, identifier := range analysis.UnresolvedPredecessorIDs {
		unresolved[identifier] = true
	}
	for _, item := range entries {
		if item.observation || item.check.Kind != "execution_terminal" {
			continue
		}
		if state, _ := pyjson.TextAt(item.payload, "event", "state"); state != "succeeded" {
			continue
		}
		key, ok := attemptKey(item.payload, true)
		if ok && attemptNamesUnresolved(key, entries, found, unresolved) {
			continue
		}
		if !ok || !found.consumed[key] || !found.released[key] {
			*staged.at(stageCausal) = append(*staged.at(stageCausal), issue(DecisionBindingInvalid, "a succeeded attempt lacks consumed authority or release evidence"))
		}
	}
	// EBMP2-074: a release of single-use authority has its consumption recorded, whatever the
	// terminal state of its attempt.
	for _, item := range entries {
		if item.observation || !found.boundReleases[item.index] {
			continue
		}
		key, hasKey := attemptKey(item.payload, true)
		response := found.eventResponse[item.index]
		if !hasKey || found.consumed[key] || response == nil || attemptNamesUnresolved(key, entries, found, unresolved) {
			continue
		}
		if policy, _ := pyjson.TextAt(response.payload, "authorization", "use_policy"); policy == "single_use" {
			*staged.at(stageCausal) = append(*staged.at(stageCausal), issue(DecisionBindingInvalid, fmt.Sprintf("envelope %d: a release of single-use authority has no recorded consumption", item.index)))
		}
	}
	missingTerminal := false
	for _, identifier := range found.requestOrder {
		if key, ok := attemptKey(found.requests[identifier].payload, false); ok && !found.terminal[key] {
			missingTerminal = true
			break
		}
	}
	causalStatus := analysis.Status
	if (missingTerminal || continuationMissing) && analysis.Status == "complete" {
		causalStatus = "incomplete"
	}
	effects := effectsOf(entries, found, staged.at(stageReasons), causalStatus == "complete")
	verdict := Verified
	switch {
	case staged.count() > 0 || causalStatus == "indeterminate":
		verdict = Invalid
	case causalStatus != "complete":
		verdict = Incomplete
	}
	accepted := false
	if verdict == Verified {
		// EBMP2-060: every trust dependency, a time authority's key included, is acceptable now.
		failing := false
		for _, check := range checks {
			failing = failing || check.Current != "valid"
		}
		for _, item := range dependencies {
			failing = failing || item.Current != "valid"
		}
		if failing {
			if accept {
				accepted = true
			} else {
				verdict = CurrentTrustFailed
			}
		}
	}
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Index < checks[j].Index })
	findings := staged.ordered()
	// The conditional items of the scope that apply to this bundle; ScopeOf places them.
	conditional := []string{}
	if dischargeApplied {
		conditional = append(conditional, scopeDischarge...)
	}
	if carriesPost {
		conditional = append(conditional, scopePostRelease)
	}
	// The stated reasons that keep an item out of Established (EBMP2-076).
	reasons := map[string]string{}
	if !found.releaseRecorded {
		reasons[ScopeRelease] = ReasonNoRelease
	}
	if dischargeApplied && uncarried {
		reasons[ScopeProofs] = ReasonProofNotECLObject
	} else if dischargeApplied && unnamed {
		// Both reasons true, the report gives proof-not-ecl-object: a proof that is not carried
		// was not checked at all.
		reasons[ScopeProofs] = ReasonIssuerNotNamed
	}
	// Non-empty only for an incomplete verdict (EBMP2-076).
	unresolvedIDs := []string{}
	if verdict == Incomplete {
		unresolvedIDs = append(unresolvedIDs, analysis.UnresolvedPredecessorIDs...)
	}
	held := checksThatHeld(heldInputs{
		checks: checks, entries: entries, dependencies: dependencies, covered: covered, staged: staged,
		analysis: analysis, missingTerminal: missingTerminal, continuationMissing: continuationMissing,
		continuationNamed: continuationNamed, proofs: proofs, found: found, register: register != nil,
	})
	sort.SliceStable(dependencies, func(i, j int) bool { return dependencies[i].Index < dependencies[j].Index })
	return &Report{
		Verdict: verdict, EnvelopeChecks: checks, BindingChecks: bindings, CausalStatus: causalStatus,
		Effects: effects, Findings: findings, VerificationProfile: ReferenceProfile,
		AcceptedCurrentTrustFailure: accepted,
		Scope:                       ReportScope{Established: []string{}, NotEstablished: conditional, Reasons: reasons, Checks: held},
		CompletionAfterWindow:       found.completionAfterWindow,
		TrustDependencies:           dependencies,
		UnresolvedPredecessorIDs:    unresolvedIDs,
	}, nil
}

// decisionBasisOneWay is the one-way rule of DCMP2-053.
const decisionBasisOneWay = "ecl.rule.decision-basis-one-way.v1"

// continuedMembers are the members of a continuation that equal those of the request it
// continues (DCMP2-056).
var continuedMembers = []string{"action", "actor", "subject", "authority_request"}

// attemptNamesUnresolved reports whether an attempt's own objects (its request, the response paired
// with it, and the authority and execution events of the attempt) name a causal predecessor that
// the bundle does not hold (EBMP2-059).
func attemptNamesUnresolved(key string, entries []*entry, found *pairs, unresolved map[string]bool) bool {
	if len(unresolved) == 0 {
		return false
	}
	var request *entry
	for _, identifier := range found.requestOrder {
		if candidate := found.requests[identifier]; candidate != nil {
			if requestKey, ok := attemptKey(candidate.payload, false); ok && requestKey == key {
				request = candidate
				break
			}
		}
	}
	var own []*entry
	if request != nil {
		own = append(own, request)
		if identifier := identifierOf(request.payload); identifier != nil {
			if response := found.responses[*identifier]; response != nil {
				own = append(own, response)
			}
		}
		for _, item := range entries {
			if found.eventRequest[item.index] == request {
				own = append(own, item)
			}
		}
	}
	for _, item := range entries {
		if kind, _ := pyjson.TextAt(item.payload, "event", "kind"); !item.observation && kind == "execution" {
			if eventKey, ok := attemptKey(item.payload, true); ok && eventKey == key {
				own = append(own, item)
			}
		}
	}
	for _, item := range own {
		listed, _ := pyjson.Path(item.payload, "workflow", "causal_predecessors")
		predecessors, _ := pyjson.Array(listed)
		for _, value := range predecessors {
			if identifier, isText := pyjson.TextAt(value, "id"); isText && unresolved[identifier] {
				return true
			}
		}
	}
	return false
}

// answerPayload returns the payload of a response, or nil.
func answerPayload(answer *entry) any {
	if answer == nil {
		return nil
	}
	return answer.payload
}

// checkContinuations is EBMP2-078: each decision request that carries continues names, among the
// bundle's objects, the request it continues, that request's challenge response and the approve
// intervention event on that request; it keeps the continued request's workflow and root trace
// with a greater attempt and the same action, actor, subject and requested authority; it lists the
// response and the approval among its causal predecessors by identifier and digest; when the
// continuation's response is an admit, every key that signed the approval holds
// ecl.purpose.approval.v1 in the version the approval names and none is bound to the request's
// actor, and the approval's expires_at, when present, is later than that response's
// evaluated_at; and no two requests continue one response. Each failure is a finding of stage 5 with
// ecl.error.decision-binding-invalid.v1.
//
// Every check whose objects the bundle holds is made: a named object that the bundle does not hold
// exempts no other check (EBMP2-059). It returns whether a named object is not in the bundle, which
// leaves the causal closure incomplete and keeps bindings, whose object set names it, out of
// Established (EBMP2-076), and the indexes of the named objects that the bundle holds (part of the
// request-response-pairs object set).
func checkContinuations(entries []*entry, findings *[]BundleFinding, versions []*trust.Policy) (bool, map[int]bool) {
	byID := map[string]*entry{}
	for _, item := range entries {
		if identifier := identifierOf(item.payload); identifier != nil {
			if _, seen := byID[*identifier]; !seen {
				byID[*identifier] = item
			}
		}
	}
	missing := false
	named := map[int]bool{}
	continued := map[string]bool{}
	for _, item := range entries {
		if item.observation || item.check.Kind != "decision_request" {
			continue
		}
		link, isObject := pyjson.ObjectAt(item.payload, "continues")
		if !isObject {
			continue
		}
		fail := func(message string) {
			*findings = append(*findings, issue(DecisionBindingInvalid, fmt.Sprintf("envelope %d: the continuation %s", item.index, message)))
		}
		requestID, hasRequestID := pyjson.Text(link["request_id"])
		responseID, hasResponseID := pyjson.Text(link["response_id"])
		approvalID, hasApprovalID := pyjson.Text(link["approval_id"])
		var prior, response, approval *entry
		if hasRequestID {
			prior = byID[requestID]
		}
		if hasResponseID {
			response = byID[responseID]
		}
		if hasApprovalID {
			approval = byID[approvalID]
		}
		if prior == nil || response == nil || approval == nil {
			missing = true
		}
		for _, held := range []*entry{prior, response, approval} {
			if held != nil {
				named[held.index] = true
			}
		}
		if hasResponseID {
			if continued[responseID] {
				fail("continues a response that another request continues")
			}
			continued[responseID] = true
		}
		if prior != nil {
			if prior.observation || prior.check.Kind != "decision_request" {
				fail("names as its continued request an object that is not a decision request")
			} else {
				workflow, _ := pyjson.ObjectAt(item.payload, "workflow")
				before, _ := pyjson.ObjectAt(prior.payload, "workflow")
				if !pyjson.Equal(workflow["workflow_id"], before["workflow_id"]) || !pyjson.Equal(workflow["root_trace_id"], before["root_trace_id"]) {
					fail("is not in the continued request's workflow and root trace")
				}
				attempt, attemptOK := pyjson.Int(workflow["attempt"])
				priorAttempt, priorOK := pyjson.Int(before["attempt"])
				if !attemptOK || !priorOK || attempt <= priorAttempt {
					fail("does not have a greater attempt than the continued request")
				}
				for _, member := range continuedMembers {
					if !pyjson.Equal(item.payload[member], prior.payload[member]) {
						fail("changes the continued request's " + member)
					}
				}
			}
		}
		if response != nil {
			answers, _ := pyjson.Text(response.payload["request_id"])
			outcome, _ := pyjson.Text(response.payload["outcome"])
			if response.observation || response.check.Kind != "decision_response" || !hasRequestID || answers != requestID || outcome != "challenge" {
				fail("names as its challenge an object that is not the challenge response to the continued request")
			}
		}
		if approval != nil {
			event, _ := pyjson.ObjectAt(approval.payload, "event")
			protocol, _ := pyjson.Text(approval.payload["protocol"])
			if protocol != "EBMP-2" || !pyjson.Equal(event["kind"], "intervention") || !pyjson.Equal(event["operation"], "approve") || !hasRequestID || !pyjson.Equal(event["target_id"], requestID) {
				fail("names as its approval an object that is not an approval of the continued request")
			}
			own, hasOwn := pyjson.Text(item.payload["message_id"])
			var answer *entry
			for _, other := range entries {
				if answers, _ := pyjson.Text(other.payload["request_id"]); !other.observation && other.check.Kind == "decision_response" && hasOwn && answers == own {
					answer = other
					break
				}
			}
			// The approval's keys and expiry bear on the continuation only when its response admits
			// it: a deny or a new challenge is the right answer to an approval that has expired or
			// is not acceptable (DCMP2-057).
			if outcome, _ := pyjson.Text(pyjson.Get(answerPayload(answer), "outcome")); answer != nil && outcome == "admit" {
				// As EBMP2-070 condition 5 asks of an approval record: the approval service's keys,
				// none of them bound to the request's actor.
				keys := signerKeys(approval, versions)
				if len(keys) == 0 || !allHoldPurpose(keys, trust.PurposeApproval) {
					fail("names an approval signed by a key without the approval purpose")
				}
				actor, hasActor := pyjson.TextAt(item.payload, "actor", "id")
				for _, key := range keys {
					if hasActor && key.Principal == actor {
						fail("names an approval signed by a key of the request's actor")
						break
					}
				}
				// The approval is still in force when the continuation's response is evaluated.
				expiresValue, hasExpires := event["expires_at"]
				expires, expiresOK := instantOrNone(expiresValue)
				if hasExpires && expiresOK {
					if evaluated, evaluatedOK := instantOrNone(answer.payload["evaluated_at"]); evaluatedOK && instant.Compare(expires, evaluated) <= 0 {
						fail("rests on an approval that expired before its response was evaluated")
					}
				}
			}
		}
		// DCMP2-056: the response and the approval are causal predecessors, by identifier and
		// digest.
		listed, _ := pyjson.Path(item.payload, "workflow", "causal_predecessors")
		references, _ := pyjson.Array(listed)
		for _, target := range []struct {
			name       string
			identifier string
			present    bool
			held       *entry
		}{{"challenge response", responseID, hasResponseID, response}, {"approval", approvalID, hasApprovalID, approval}} {
			var reference map[string]any
			for _, value := range references {
				if candidate, isObject := pyjson.Object(value); isObject && target.present && pyjson.Equal(candidate["id"], target.identifier) {
					reference = candidate
					break
				}
			}
			if reference == nil || (target.held != nil && !referenceDigestMatches(reference, target.held.payload)) {
				fail("does not list its " + target.name + " among its causal predecessors with its digest")
			}
		}
	}
	return missing, named
}

// EBMP2-076 and registries/scope-checks.json: the checks of the claim-to-check map, in registry
// order, and for each item of the scope the object set and the checks that must run over it and
// hold before the item is established.
var (
	ScopeCheckIDs = []string{
		"envelope-integrity", "time-not-after-evaluation", "historical-signers", "current-compromise-knowledge",
		"trusted-time-countersignatures", "trusted-time-coverage", "current-status", "object-schema",
		"object-semantics", "observation-kind", "identifiers-unique", "decision-basis-present",
		"decision-basis-one-way", "decision-basis-register", "pairing", "continuation-history",
		"response-binding", "event-binding", "release-window", "predecessors-resolved",
		"predecessor-digests", "graph-acyclic", "causal-context", "sequence-monotonic",
		"state-transitions", "terminal-per-request", "attempt-authority-consumed",
		"obligation-discharge", "obligation-proofs", "outcome-reasons", "corroborating-observation",
	}
	ScopeObjectSets = map[string]string{
		"envelope-signatures":                       "trust-dependencies",
		"current-trust":                             "trust-dependencies",
		"trusted-time":                              "object-signatures",
		"object-rules":                              "bundle-objects",
		"decision-basis-recorded":                   "decision-responses",
		"decision-basis-register":                   "decision-responses",
		"bindings":                                  "request-response-pairs",
		"release-within-authority":                  "released-attempts",
		"causal-completeness":                       "bundle-objects",
		"prerelease-obligations-discharge-recorded": "released-attempts",
		"prerelease-obligations-proofs-verified":    "discharge-entries",
	}
	ScopeRequiredChecks = map[string][]string{
		"envelope-signatures":                       {"envelope-integrity", "time-not-after-evaluation", "historical-signers", "current-compromise-knowledge", "trusted-time-countersignatures"},
		"current-trust":                             {"current-status"},
		"trusted-time":                              {"historical-signers", "current-compromise-knowledge", "trusted-time-countersignatures", "trusted-time-coverage"},
		"object-rules":                              {"object-schema", "object-semantics", "observation-kind", "identifiers-unique", "decision-basis-one-way"},
		"decision-basis-recorded":                   {"decision-basis-present"},
		"decision-basis-register":                   {"decision-basis-register"},
		"bindings":                                  {"pairing", "continuation-history", "response-binding", "event-binding", "outcome-reasons"},
		"release-within-authority":                  {"release-window"},
		"causal-completeness":                       {"identifiers-unique", "predecessors-resolved", "predecessor-digests", "graph-acyclic", "causal-context", "sequence-monotonic", "state-transitions", "terminal-per-request", "attempt-authority-consumed"},
		"prerelease-obligations-discharge-recorded": {"obligation-discharge"},
		"prerelease-obligations-proofs-verified":    {"obligation-proofs"},
	}
	// wholeBundleSets are the object sets that a report's envelope checks determine, which ScopeOf
	// requires an item's objects to cover.
	wholeBundleSets = map[string]bool{"bundle-objects": true, "trust-dependencies": true, "object-signatures": true}
)

func (s *stagedFindings) codes(stage int) map[string]bool {
	set := map[string]bool{}
	for _, finding := range s.stages[stage] {
		set[finding.Code] = true
	}
	return set
}

func sortedInts(set map[int]bool) []int {
	result := make([]int, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

type heldInputs struct {
	checks              []EnvelopeCheck
	entries             []*entry
	dependencies        []TrustDependency
	covered             map[int]bool
	staged              *stagedFindings
	analysis            *Analysis
	missingTerminal     bool
	continuationMissing bool
	continuationNamed   map[int]bool
	proofs              map[int]bool
	found               *pairs
	register            bool
}

// checksThatHeld returns, for each item of the scope, the checks of ScopeRequiredChecks that ran
// over the item's object set and held, and the indexes of the objects they covered (EBMP2-076).
// An item whose checks did not all hold has no entry; ScopeOf lists an item in Established only
// when its entry names every required check and covers the item's object set.
func checksThatHeld(in heldInputs) map[string]ScopeItemChecks {
	everySet := map[int]bool{}
	historical := map[string]bool{}
	allCurrent := true
	for _, check := range in.checks {
		everySet[check.Index] = true
		historical[check.Historical] = true
		allCurrent = allCurrent && check.Current == "valid"
	}
	every := sortedInts(everySet)
	// envelope-signatures rests on the signers of envelopes and observations; trusted-time also on
	// the time authorities' signers (decision "A signature that does not verify").
	signersValid, dependenciesValid, dependenciesCurrent := true, true, true
	for _, item := range in.dependencies {
		if item.Role == "signer" {
			signersValid = signersValid && item.Historical == "valid"
		}
		dependenciesValid = dependenciesValid && item.Historical == "valid"
		dependenciesCurrent = dependenciesCurrent && item.Current == "valid"
	}
	rules := map[string]bool{}
	for _, item := range in.analysis.Findings {
		rules[item.RuleID] = true
	}
	objects := in.staged.codes(stageObjects)
	causalCodes := in.staged.codes(stageCausal)
	otherObjectCodes := false
	for code := range objects {
		switch code {
		case SchemaInvalid, DecisionBasisRequired, DecisionBasisMatchesRegister, "ecl.rule.bundle-object-identifiers-unique.v1":
		default:
			otherObjectCodes = true
		}
	}
	coveredAll := len(every) > 0
	for _, index := range every {
		coveredAll = coveredAll && in.covered[index]
	}
	holds := map[string]bool{
		"envelope-integrity":             len(in.staged.stages[stagePayloads]) == 0 && !historical[IntegrityInvalid] && !historical[ResourceLimitExceeded] && !historical[PolicyInvalid],
		"time-not-after-evaluation":      !historical[ClockRegressed],
		"historical-signers":             len(historical) == 1 && historical["valid"] && signersValid,
		"current-compromise-knowledge":   !historical[Revoked] && signersValid,
		"trusted-time-countersignatures": !historical[TrustedTimeInvalid],
		"trusted-time-coverage":          coveredAll,
		"current-status":                 allCurrent && dependenciesCurrent,
		"object-schema":                  !objects[SchemaInvalid],
		"object-semantics":               !otherObjectCodes,
		"observation-kind":               !objects[SemanticInvalid],
		"identifiers-unique":             !objects["ecl.rule.bundle-object-identifiers-unique.v1"] && !rules["ecl.rule.bundle-object-identifiers-unique.v1"],
		"decision-basis-present":         !objects[DecisionBasisRequired],
		"decision-basis-one-way":         !objects[decisionBasisOneWay],
		"decision-basis-register":        in.register && !objects[DecisionBasisMatchesRegister],
		"pairing":                        len(in.staged.stages[stagePairing]) == 0,
		"continuation-history":           len(in.staged.stages[stagePairing]) == 0 && !in.continuationMissing,
		"response-binding":               len(in.staged.stages[stageRequests]) == 0,
		"event-binding":                  len(in.staged.stages[stageEvents]) == 0,
		"release-window":                 !in.staged.codes(stageEvents)[Expired],
		"predecessors-resolved":          len(in.analysis.UnresolvedPredecessorIDs) == 0 && !in.continuationMissing,
		"predecessor-digests":            !rules["ecl.rule.bundle-predecessor-digest-valid.v1"],
		"graph-acyclic":                  !rules["ecl.rule.bundle-causal-graph-acyclic.v1"],
		"causal-context":                 !rules[ContextRule],
		"sequence-monotonic":             !rules["ecl.rule.bundle-causal-sequence-monotonic.v1"],
		"state-transitions":              !rules["ecl.rule.execution-state-transition-valid.v1"] && len(in.analysis.OpenActionIDs) == 0,
		"terminal-per-request":           !in.missingTerminal,
		"attempt-authority-consumed":     !causalCodes[DecisionBindingInvalid],
		"obligation-discharge":           !causalCodes[DischargeRule],
		"obligation-proofs":              !causalCodes[DischargeRule] && !causalCodes[ObligationUnproven],
		"outcome-reasons":                len(in.staged.stages[stageReasons]) == 0,
	}
	if causalCodes[ResourceLimitExceeded] {
		// A declared limit stopped the analysis: no causal check ran over the whole graph.
		for _, check := range ScopeRequiredChecks["causal-completeness"] {
			holds[check] = false
		}
	}
	responses, paired, released, dependencyIndexes := map[int]bool{}, map[int]bool{}, map[int]bool{}, map[int]bool{}
	for _, item := range in.entries {
		if item.check.Kind == "decision_response" {
			responses[item.index] = true
		}
	}
	for _, item := range in.found.requests {
		paired[item.index] = true
	}
	for _, item := range in.found.responses {
		paired[item.index] = true
	}
	for index := range in.found.eventRequest {
		paired[index] = true
	}
	for index := range in.continuationNamed {
		paired[index] = true
	}
	discharge := map[int]bool{}
	for index := range in.proofs {
		discharge[index] = true
	}
	releasedKeys := map[string]bool{}
	for _, item := range in.entries {
		if in.found.boundReleases[item.index] {
			if key, ok := attemptKey(item.payload, true); ok {
				releasedKeys[key] = true
			}
		}
	}
	for _, item := range in.entries {
		// The terminal events of each released attempt (released-attempts).
		if key, ok := attemptKey(item.payload, true); ok && !item.observation && item.check.Kind == "execution_terminal" && releasedKeys[key] {
			released[item.index] = true
		}
	}
	for index := range in.found.boundReleases {
		released[index] = true
		if request := in.found.eventRequest[index]; request != nil {
			released[request.index] = true
		}
		if response := in.found.eventResponse[index]; response != nil {
			released[response.index] = true
		}
	}
	for _, item := range in.dependencies {
		dependencyIndexes[item.Index] = true
	}
	sets := map[string][]int{
		"trust-dependencies":     sortedInts(dependencyIndexes),
		"object-signatures":      every,
		"bundle-objects":         every,
		"decision-responses":     sortedInts(responses),
		"request-response-pairs": sortedInts(paired),
		"released-attempts":      sortedInts(released),
		"discharge-entries":      sortedInts(discharge),
	}
	result := map[string]ScopeItemChecks{}
	for item, required := range ScopeRequiredChecks {
		if item == "trusted-time" && !dependenciesValid {
			continue
		}
		all := true
		for _, check := range required {
			all = all && holds[check]
		}
		if all {
			result[item] = ScopeItemChecks{Checks: append([]string{}, required...), Objects: append([]int{}, sets[ScopeObjectSets[item]]...)}
		}
	}
	return result
}

// expectedObjects returns the indexes that an item's objects must cover, for the object sets
// that the report's envelope checks determine; ok false for another set, whose objects the
// verification recorded.
func expectedObjects(item string, report *Report) (map[int]bool, bool) {
	set := map[int]bool{}
	kind := ScopeObjectSets[item]
	for _, check := range report.EnvelopeChecks {
		if wholeBundleSets[kind] || (kind == "decision-responses" && check.Kind == "decision_response") {
			set[check.Index] = true
		}
	}
	return set, wholeBundleSets[kind] || kind == "decision-responses"
}

// ranInFull reports whether the report records, for item, every check that the claim-to-check
// map requires, held over the item's whole object set (EBMP2-076).
func ranInFull(item string, report *Report) bool {
	entry, present := report.Scope.Checks[item]
	required := ScopeRequiredChecks[item]
	if !present || len(entry.Checks) != len(required) {
		return false
	}
	for index, check := range required {
		if entry.Checks[index] != check {
			return false
		}
	}
	if expected, determined := expectedObjects(item, report); determined {
		listed := map[int]bool{}
		for _, index := range entry.Objects {
			listed[index] = true
		}
		for index := range expected {
			if !listed[index] {
				return false
			}
		}
	}
	if ScopeObjectSets[item] == "trust-dependencies" {
		signed := map[int]bool{}
		for _, dependency := range report.TrustDependencies {
			signed[dependency.Index] = true
		}
		for _, check := range report.EnvelopeChecks {
			if !signed[check.Index] {
				return false
			}
		}
	}
	if item == "current-trust" {
		for _, dependency := range report.TrustDependencies {
			if dependency.Current != "valid" {
				return false
			}
		}
	}
	return true
}

// namesTheTerminal reports whether an observation names the terminal event among its causal
// predecessors by object_id and digest (EBMP2-061).
func namesTheTerminal(observation, terminal map[string]any) bool {
	listed, _ := pyjson.Path(observation, "workflow", "causal_predecessors")
	predecessors, isList := pyjson.Array(listed)
	identifier, isText := pyjson.Text(terminal["object_id"])
	if !isList || !isText {
		return false
	}
	for _, value := range predecessors {
		predecessor, isObject := pyjson.Object(value)
		if isObject && pyjson.Equal(predecessor["id"], identifier) && referenceDigestMatches(predecessor, terminal) {
			return true
		}
	}
	return false
}

// ScopeOf returns the scope of a report's verdict (EBMP2-076), from the report alone.
//
// Established holds the checks that the verifier made and that held: none for an invalid report
// or one without an evaluated envelope; otherwise the signatures, object rules, bindings and
// recorded release times, current trust when the verdict is verified or incomplete and every
// envelope is valid now, trusted time when every envelope carries it, the decision basis and the
// register when the caller required them, causal completeness unless the verdict is incomplete,
// and the recorded discharge of pre-release obligations when that rule applied. NotEstablished
// holds the other items that apply and the statements that no verification establishes. Both are
// in the order of the table of EBMP2-076. The conditional items that apply are those already in
// the report's scope, so the function gives the same scope again for a report whose verdict
// another check has changed, as for an offline package (IE1-022).
func ScopeOf(report *Report) ReportScope {
	applies := map[string]bool{}
	for _, item := range report.Scope.Established {
		applies[item] = true
	}
	for _, item := range report.Scope.NotEstablished {
		applies[item] = true
	}
	reasons := map[string]string{}
	for item, reason := range report.Scope.Reasons {
		reasons[item] = reason
	}
	discharge, post := applies[scopeDischarge[0]], applies[scopePostRelease]
	checks := report.EnvelopeChecks
	established := map[string]bool{}
	if len(checks) > 0 && (report.Verdict == Verified || report.Verdict == CurrentTrustFailed || report.Verdict == Incomplete) {
		for _, item := range []string{"envelope-signatures", "object-rules", "bindings"} {
			established[item] = true
		}
		if _, stated := reasons[ScopeRelease]; !stated {
			established[ScopeRelease] = true
		}
		allCurrent := true
		for _, check := range checks {
			allCurrent = allCurrent && check.Current == "valid"
		}
		established["current-trust"] = (report.Verdict == Verified || report.Verdict == Incomplete) && allCurrent
		established["trusted-time"] = true
		established["decision-basis-recorded"] = true
		established["decision-basis-register"] = report.Register != nil
		established["causal-completeness"] = report.Verdict != Incomplete
		established[scopeDischarge[0]] = discharge
		if discharge {
			if _, stated := reasons[ScopeProofs]; !stated {
				established[ScopeProofs] = true
			}
		}
		// The claim-to-check map: an item is established only when every check that it requires
		// ran over its whole object set and held.
		for item := range established {
			established[item] = established[item] && ranInFull(item, report)
		}
	}
	scope := emptyScope()
	for _, item := range append(append([]string{}, ScopeChecks...), ScopeNever...) {
		isDischarge := false
		for _, candidate := range scopeDischarge {
			isDischarge = isDischarge || item == candidate
		}
		if conditionalScope[item] && !(isDischarge && discharge) && !(item == scopePostRelease && post) {
			continue
		}
		// decision-basis-register applies only when the caller supplies a register
		// (registries/scope-checks.json).
		if item == "decision-basis-register" && report.Register == nil {
			continue
		}
		if established[item] {
			scope.Established = append(scope.Established, item)
			entry := report.Scope.Checks[item]
			objects := append([]int{}, entry.Objects...)
			sort.Ints(objects)
			scope.Checks[item] = ScopeItemChecks{Checks: append([]string{}, entry.Checks...), Objects: objects}
		} else {
			scope.NotEstablished = append(scope.NotEstablished, item)
			if reason, stated := reasons[item]; stated {
				scope.Reasons[item] = reason
			}
		}
	}
	return scope
}

// CorroborationItems are the items that a report must establish for an effect to be corroborated
// (registries/scope-checks.json, evidence_levels; EBMP2-061).
var CorroborationItems = []string{"envelope-signatures", "causal-completeness"}

// WithScope sets the scope of a report's verdict (EBMP2-076) and decides its evidence levels after
// the scope: corroborated only when the scope establishes CorroborationItems, else
// issuer-asserted (an invalid report establishes nothing, so it never reports corroborated). It
// returns the report.
func WithScope(report *Report) *Report {
	report.Scope = ScopeOf(report)
	for _, item := range CorroborationItems {
		if !slices.Contains(report.Scope.Established, item) {
			for index := range report.Effects {
				if report.Effects[index].Level == "corroborated" {
					report.Effects[index].Level = "issuer-asserted"
				}
			}
			break
		}
	}
	return report
}

// ErrInvalidNow is an evaluation time that is not RFC 3339 UTC with 0, 3 or 6 fractional
// digits on a calendar day that exists.
var ErrInvalidNow = errors.New("now must be RFC 3339 UTC with 0, 3 or 6 fractional digits, on a calendar date that exists")

// Verify checks the signatures, bindings, causality and effects of a signed evidence bundle (a
// parsed value) under the reference verification profile, against policy, the caller's current
// trust policy. Invalid bundle data is reported, never returned as an error; an invalid option is
// an error, and so is envelope.ErrUnsupportedSuite for an ML-DSA-65 signature that would decide
// the verdict.
func Verify(bundle any, policy *trust.Policy, options Options) (report *Report, err error) {
	if !nowPattern.MatchString(options.Now) || !instant.Valid(options.Now) {
		return nil, ErrInvalidNow
	}
	if options.ResponseClockSkewSeconds < 0 {
		return nil, ErrNegativeSkew
	}
	profile := ReferenceProfile
	if options.RequireTrustedTime {
		profile = TrustedTimeProfile
	}
	var register, registerReference map[string]any
	if options.Register != nil {
		problems, err := RegisterUsageProblems(options.Register)
		if err != nil {
			return nil, err
		}
		if len(problems) > 0 {
			return nil, ErrInvalidRegister
		}
		register, _ = pyjson.Object(options.Register)
		if registerReference, err = RegisterReference(register); err != nil {
			return nil, err
		}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			name := "Error"
			switch recovered.(type) {
			case instantPanic:
				name = "ValueError"
			case *pyjson.TypeError:
				name = "TypeError"
			default:
				panic(recovered)
			}
			report, err = invalidReport(issue(SemanticInvalid, "bundle verification could not be completed: "+name)), nil
			report.VerificationProfile = profile
			report.Register = registerReference
			report.EvaluationTime = options.Now
			WithScope(report)
		}
	}()
	report, err = verifyChecked(bundle, policy, options.Now, options.History, options.ResponseClockSkewSeconds, options.AcceptCurrentTrustFailure, options.RequireTrustedTime, register)
	if err != nil {
		if errors.Is(err, envelope.ErrUnsupportedSuite) {
			return nil, err
		}
		report = invalidReport(issue(SemanticInvalid, "bundle verification could not be completed: Error"))
	}
	report.VerificationProfile = profile
	report.Register = registerReference
	// Every report states the evaluation time it used, an invalid one included.
	report.EvaluationTime = options.Now
	// The scope of the verdict (EBMP2-076).
	return WithScope(report), nil
}

// FindingCodes returns the distinct finding codes of a report, sorted.
func FindingCodes(report *Report) []string {
	set := map[string]bool{}
	for _, finding := range report.Findings {
		set[finding.Code] = true
	}
	return sortedKeys(set)
}

// ReportedIdentifiers returns the identifiers of a report in the order of EBMP2-068, each once,
// the primary first: for an invalid bundle the codes of its findings; for an incomplete bundle
// without findings the causal-closure code; for a bundle whose trust has failed now, the current
// statuses that are not valid, in the order of stage 4 (EBMP2-060).
func ReportedIdentifiers(report *Report) []string {
	if report.Verdict == CurrentTrustFailed {
		set := map[string]bool{}
		for _, check := range report.EnvelopeChecks {
			if check.Current != "valid" {
				set[check.Current] = true
			}
		}
		for _, dependency := range report.TrustDependencies {
			if dependency.Current != "valid" {
				set[dependency.Current] = true
			}
		}
		statuses := sortedKeys(set)
		rank := func(code string) int {
			for index, item := range SignerOrder {
				if item == code {
					return index
				}
			}
			return len(SignerOrder)
		}
		sort.SliceStable(statuses, func(i, j int) bool { return rank(statuses[i]) < rank(statuses[j]) })
		return statuses
	}
	codes := []string{}
	seen := map[string]bool{}
	for _, finding := range report.Findings {
		if !seen[finding.Code] {
			seen[finding.Code] = true
			codes = append(codes, finding.Code)
		}
	}
	if report.Verdict == Incomplete && len(codes) == 0 {
		return []string{CausalClosureIncomplete}
	}
	return codes
}

// PrimaryFinding returns the primary finding (EBMP2-060, EBMP2-068, IE1-022), or nil when verified.
func PrimaryFinding(report *Report) *string {
	// An expired offline package has its own finding before any bundle current statuses.
	if report.Verdict == CurrentTrustFailed && len(report.Findings) > 0 {
		return &report.Findings[0].Code
	}
	identifiers := ReportedIdentifiers(report)
	if len(identifiers) == 0 {
		return nil
	}
	return &identifiers[0]
}

// JSON returns the report in the JSON shape of the reference's ecl-verify --json.
func (r *Report) JSON() map[string]any {
	optional := func(value *string) any {
		if value == nil {
			return nil
		}
		return *value
	}
	checks := make([]any, len(r.EnvelopeChecks))
	for index, check := range r.EnvelopeChecks {
		signers := make([]any, len(check.SignerKeyIDs))
		for position, keyID := range check.SignerKeyIDs {
			signers[position] = keyID
		}
		checks[index] = map[string]any{
			"index": check.Index, "object_id": optional(check.ObjectID), "kind": check.Kind,
			"signer_key_ids": signers, "historical": check.Historical, "current": check.Current,
			"historical_policy_version": optional(check.HistoricalPolicyVersion), "trusted_time": optional(check.TrustedTime),
		}
	}
	bindings := make([]any, len(r.BindingChecks))
	for index, check := range r.BindingChecks {
		bindings[index] = map[string]any{"name": check.Name, "passed": check.Passed, "code": optional(check.Code)}
	}
	effects := make([]any, len(r.Effects))
	for index, effect := range r.Effects {
		effects[index] = map[string]any{"action_id": effect.ActionID, "state": effect.State, "level": effect.Level, "authority": effect.Authority, "reason": optional(effect.Reason)}
	}
	findings := make([]any, len(r.Findings))
	for index, finding := range r.Findings {
		findings[index] = finding.Code + ": " + finding.Message
	}
	var register any
	if r.Register != nil {
		register = r.Register
	}
	items := func(values []string) []any {
		listed := make([]any, len(values))
		for index, value := range values {
			listed[index] = value
		}
		return listed
	}
	reasons := map[string]any{}
	for item, reason := range r.Scope.Reasons {
		reasons[item] = reason
	}
	scopeChecks := map[string]any{}
	for item, entry := range r.Scope.Checks {
		objects := make([]any, len(entry.Objects))
		for index, value := range entry.Objects {
			objects[index] = value
		}
		scopeChecks[item] = map[string]any{"checks": items(entry.Checks), "objects": objects}
	}
	dependencies := make([]any, len(r.TrustDependencies))
	for index, item := range r.TrustDependencies {
		dependencies[index] = map[string]any{
			"index": item.Index, "role": item.Role, "counter_id": optional(item.CounterID), "key_id": item.KeyID,
			"suite": item.Suite, "at": optional(item.At), "historical_policy_version": optional(item.HistoricalPolicyVersion),
			"historical": item.Historical, "current_policy_version": item.CurrentPolicyVersion,
			"revoked_effective_at": optional(item.RevokedEffectiveAt), "current": item.Current,
		}
	}
	return map[string]any{
		"verdict": r.Verdict, "envelope_checks": checks, "binding_checks": bindings,
		"primary":       optional(PrimaryFinding(r)),
		"causal_status": r.CausalStatus, "effects": effects, "findings": findings,
		"verification_profile": r.VerificationProfile, "accepted_current_trust_failure": r.AcceptedCurrentTrustFailure,
		"register":                   register,
		"scope":                      map[string]any{"established": items(r.Scope.Established), "not_established": items(r.Scope.NotEstablished), "reasons": reasons, "checks": scopeChecks},
		"completion_after_window":    r.CompletionAfterWindow,
		"trust_dependencies":         dependencies,
		"evaluation_time":            optional(optionalText(r.EvaluationTime, r.EvaluationTime != "")),
		"unresolved_predecessor_ids": items(append([]string{}, r.UnresolvedPredecessorIDs...)),
	}
}
