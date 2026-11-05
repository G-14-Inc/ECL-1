package evidence_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/corpus"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

const now = "2026-10-01T00:00:00Z"

func load(t *testing.T, path string) *trust.Policy {
	t.Helper()
	policy, err := trust.Load(vectors.Read(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func verify(t *testing.T, vector vectors.Vector, options evidence.Options) *evidence.Report {
	t.Helper()
	bundle, err := strict.Parse(vectors.Read(t, vector.Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range vector.TrustPolicyHistory {
		options.History = append(options.History, load(t, path))
	}
	options.Now = vector.EvaluatedAt
	options.RequireTrustedTime = vector.RequireTrustedTime
	options.AcceptCurrentTrustFailure = options.AcceptCurrentTrustFailure || vector.AcceptCurrentTrustFailure
	if vector.RegisterPath != "" {
		register, err := evidence.LoadRegister(vectors.Read(t, vector.RegisterPath))
		if err != nil {
			t.Fatal(err)
		}
		options.Register = register
	}
	report, err := evidence.Verify(bundle, load(t, vector.TrustPolicyPath), options)
	if err != nil {
		t.Fatalf("%s: %v", vector.ID, err)
	}
	return report
}

// Every evidence-bundle vector gets the reference verdict, and the identifiers it reports hold
// the expected primary and secondary ones.
func TestEvidenceBundleSuite(t *testing.T) {
	verdicts := map[string]int{}
	for _, vector := range vectors.Suite(t, "evidence-bundle").Vectors {
		report := verify(t, vector, evidence.Options{})
		if report.Verdict != vector.ExpectedVerdict {
			t.Errorf("%s: %s, not %s", vector.ID, report.Verdict, vector.ExpectedVerdict)
		}
		reported := strings.Join(evidence.ReportedIdentifiers(report), " ")
		for _, identifier := range append([]string{vector.Primary}, vector.Secondary...) {
			if identifier != "" && !strings.Contains(reported, identifier) {
				t.Errorf("%s: %s lacks %s", vector.ID, reported, identifier)
			}
		}
		// EBMP2-076 and EBMP2-061: the scope, levels and unresolved predecessors the row names.
		var scope *corpus.ExpectedScope
		if vector.ExpectedScope != nil {
			scope = &corpus.ExpectedScope{Established: vector.ExpectedScope.Established, NotEstablished: vector.ExpectedScope.NotEstablished, Reasons: vector.ExpectedScope.Reasons}
		}
		var effects []corpus.ExpectedEffect
		for _, item := range vector.ExpectedEffects {
			effects = append(effects, corpus.ExpectedEffect{ActionID: item.ActionID, Level: item.Level})
		}
		if vector.ExpectedEffects != nil && effects == nil {
			effects = []corpus.ExpectedEffect{}
		}
		if !corpus.ReportMatches(report, scope, effects, vector.ExpectedUnresolved) {
			t.Errorf("%s: scope %v, effects %v or unresolved %v differ from the row", vector.ID, report.Scope, report.Effects, report.UnresolvedPredecessorIDs)
		}
		verdicts[report.Verdict]++
	}
	if len(verdicts) != 4 {
		t.Fatalf("verdicts %v", verdicts)
	}
}

// The signed fixtures of the reference tests: verdicts and evidence levels.
func TestFixtures(t *testing.T) {
	policy := vectors.Read(t, "conformance/fixtures/evidence/trust-policy.json")
	for name, expected := range map[string][2]string{
		"succeeded":    {evidence.Verified, "issuer-asserted"},
		"denied":       {evidence.Verified, "issuer-asserted"},
		"tampered":     {evidence.Invalid, "none"},
		"corroborated": {evidence.Verified, "corroborated"},
	} {
		report, _, err := evidence.VerifyBytes(vectors.Read(t, "conformance/fixtures/evidence/"+name+".json"), policy, nil, evidence.Options{Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if report.Verdict != expected[0] || len(report.Effects) == 0 || report.Effects[0].Level != expected[1] {
			t.Errorf("%s: %s %+v", name, report.Verdict, report.Effects)
		}
	}
}

func TestCurrentTrustFailureIsAcceptedOnlyOnRequest(t *testing.T) {
	var vector vectors.Vector
	for _, item := range vectors.Suite(t, "evidence-bundle").Vectors {
		if item.ID == "bundle-current-trust-failed-revoked-after-use" {
			vector = item
		}
	}
	report := verify(t, vector, evidence.Options{})
	if report.Verdict != evidence.CurrentTrustFailed || strings.Join(evidence.ReportedIdentifiers(report), " ") != evidence.Revoked {
		t.Fatalf("%s %v", report.Verdict, evidence.ReportedIdentifiers(report))
	}
	accepted := verify(t, vector, evidence.Options{AcceptCurrentTrustFailure: true})
	if accepted.Verdict != evidence.Verified || !accepted.AcceptedCurrentTrustFailure {
		t.Fatalf("%s %v", accepted.Verdict, accepted.AcceptedCurrentTrustFailure)
	}
	vector.TrustPolicyHistory = nil
	if report := verify(t, vector, evidence.Options{}); report.Verdict != evidence.Invalid {
		t.Fatalf("without the earlier version: %s", report.Verdict)
	}
}

func TestTrustedTimeProfile(t *testing.T) {
	bundle, _ := strict.Parse(vectors.Read(t, "conformance/suites/evidence-bundle/bundle-valid-succeeded.json"))
	report, err := evidence.Verify(bundle, load(t, "conformance/suites/evidence-bundle/trust-policy.json"), evidence.Options{Now: now, RequireTrustedTime: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.VerificationProfile != evidence.TrustedTimeProfile || report.Verdict != evidence.Invalid {
		t.Fatalf("%s %s", report.VerificationProfile, report.Verdict)
	}
	for _, check := range report.EnvelopeChecks {
		if check.Historical != evidence.TrustedTimeRequired {
			t.Fatalf("%+v", check)
		}
	}
}

func TestInputsAndOptions(t *testing.T) {
	policyData := vectors.Read(t, "conformance/fixtures/evidence/trust-policy.json")
	policy := load(t, "conformance/fixtures/evidence/trust-policy.json")
	for _, moment := range []string{"2026-10-01T00:00:00.1Z", "2026-02-30T00:00:00Z", "yesterday", "2026-10-01T00:00:00+00:00"} {
		if _, err := evidence.Verify(map[string]any{}, policy, evidence.Options{Now: moment}); !errors.Is(err, evidence.ErrInvalidNow) {
			t.Errorf("%s: %v", moment, err)
		}
	}
	if _, err := evidence.Verify(map[string]any{}, policy, evidence.Options{Now: now, ResponseClockSkewSeconds: -1}); err == nil {
		t.Error("a negative skew was accepted")
	}
	for _, bundle := range []any{nil, []any{}, "x", map[string]any{}, map[string]any{"envelopes": []any{}}} {
		report, err := evidence.Verify(bundle, policy, evidence.Options{Now: now})
		if err != nil || report.Verdict != evidence.Invalid || strings.Join(evidence.FindingCodes(report), " ") != evidence.SchemaInvalid {
			t.Errorf("%v: %v %v", bundle, report, err)
		}
	}
	var input *evidence.InputError
	if _, _, err := evidence.VerifyBytes(make([]byte, evidence.MaxBundleBytes+1), policyData, nil, evidence.Options{Now: now}); !errors.As(err, &input) {
		t.Error(err)
	}
	if _, _, err := evidence.VerifyBytes([]byte{0xff}, policyData, nil, evidence.Options{Now: now}); !errors.As(err, &input) {
		t.Error(err)
	}
	if _, _, err := evidence.VerifyBytes([]byte("{}"), []byte("{}"), nil, evidence.Options{Now: now}); !errors.As(err, &input) || input.Code != trust.SchemaInvalid {
		t.Error(err)
	}
}

func TestReportJSONShape(t *testing.T) {
	report, _, err := evidence.VerifyBytes(vectors.Read(t, "conformance/fixtures/evidence/succeeded.json"), vectors.Read(t, "conformance/fixtures/evidence/trust-policy.json"), nil, evidence.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	value := report.JSON()
	for _, member := range []string{"verdict", "primary", "envelope_checks", "binding_checks", "causal_status", "effects", "findings", "verification_profile", "accepted_current_trust_failure", "register", "scope", "completion_after_window", "trust_dependencies", "evaluation_time", "unresolved_predecessor_ids"} {
		if _, present := value[member]; !present {
			t.Errorf("missing %s", member)
		}
	}
	if len(value) != 15 || value["primary"] != nil || value["register"] != nil || value["completion_after_window"] != false {
		t.Fatalf("%d members: %v %v", len(value), value["register"], value["completion_after_window"])
	}
	scope, _ := value["scope"].(map[string]any)
	if fmt.Sprint(scope["established"]) != "[envelope-signatures current-trust object-rules decision-basis-recorded bindings release-within-authority causal-completeness]" ||
		fmt.Sprint(scope["not_established"]) != "[trusted-time recorded-times-true effects-occurred deployment-assessed statements-true]" ||
		fmt.Sprint(scope["reasons"]) != "map[]" {
		t.Fatalf("scope %v", scope)
	}
	// A bundle that records no release says so, with the reason stated.
	denied, _, err := evidence.VerifyBytes(vectors.Read(t, "conformance/fixtures/evidence/denied.json"), vectors.Read(t, "conformance/fixtures/evidence/trust-policy.json"), nil, evidence.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	deniedScope, _ := denied.JSON()["scope"].(map[string]any)
	if denied.Verdict != evidence.Verified || fmt.Sprint(deniedScope["reasons"]) != "map[release-within-authority:no-release-recorded]" || strings.Contains(fmt.Sprint(deniedScope["established"]), "release-within-authority") {
		t.Fatalf("%s %v", denied.Verdict, deniedScope)
	}
}

// EBMP2-070: a release records a discharge of each obligation left to Enforcement, as the
// reference reports it.
func TestPrereleaseObligationsDischarged(t *testing.T) {
	rule := evidence.DischargeRule
	for id, message := range map[string]string{
		"bundle-invalid-prerelease-approval-unmet":                "object 3: the release rests on obligations left to Enforcement and records no discharge",
		"bundle-invalid-prerelease-witness-unmet":                 "object 3: the release rests on obligations left to Enforcement and records no discharge",
		"bundle-invalid-prerelease-obligations-partly-discharged": "object 3: an obligation left to Enforcement has no discharge",
		"bundle-invalid-discharge-of-obligation-not-carried":      "object 3: /extensions/0/value/obligations/3: names an obligation the response does not carry",
		"bundle-invalid-discharge-checked-after-release":          "object 3: /extensions/0/value/obligations/0/checked_at: was checked after the release was observed",
		"bundle-invalid-discharge-checked-before-decision":        "object 3: /extensions/0/value/obligations/0/checked_at: was checked before the decision was issued",
		"bundle-invalid-discharge-proof-obtained-after-check":     "object 3: /extensions/0/value/obligations/0/proof/obtained_at: has a proof obtained after it was checked",
		"bundle-invalid-discharge-entry-duplicated":               "object 3: /extensions/0/value/obligations/3: names an obligation that another entry names",
		"bundle-invalid-discharge-proof-digest-of-bundle-object":  "object 3: /extensions/0/value/obligations/0/proof/digest: names an object of the bundle by another digest",
	} {
		report := verify(t, vectorByID(t, id), evidence.Options{})
		if report.Verdict != evidence.Invalid || len(report.Findings) != 1 || report.Findings[0] != (evidence.BundleFinding{Code: rule, Message: message}) {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Findings)
		}
	}
	discharged := verify(t, vectorByID(t, "bundle-valid-prerelease-obligations-discharged"), evidence.Options{})
	established := strings.Join(discharged.Scope.Established, " ")
	missing := strings.Join(discharged.Scope.NotEstablished, " ")
	if discharged.Verdict != evidence.Verified || !strings.Contains(established, "prerelease-obligations-discharge-recorded") || !strings.Contains(missing, "prerelease-obligations-met") {
		t.Fatalf("%s %v", discharged.Verdict, discharged.Scope)
	}
	// The proofs are not objects of the bundle: not verified, with the reason stated.
	if !strings.Contains(missing, evidence.ScopeProofs) || discharged.Scope.Reasons[evidence.ScopeProofs] != evidence.ReasonProofNotECLObject {
		t.Fatalf("%v", discharged.Scope)
	}
}

// EBMP2-070: a proof that is an object of the bundle is checked there, as
// the reference checks it, and the entry's fresh_until must lie after the release plus its guard.
func TestCarriedProofsAreVerified(t *testing.T) {
	carried := verify(t, vectorByID(t, "bundle-valid-prerelease-proofs-carried"), evidence.Options{})
	established := strings.Join(carried.Scope.Established, " ")
	if carried.Verdict != evidence.Verified || !strings.Contains(established, "prerelease-obligations-discharge-recorded "+evidence.ScopeProofs) || len(carried.Scope.Reasons) != 0 {
		t.Fatalf("%s %v %v", carried.Verdict, carried.Findings, carried.Scope)
	}
	for _, id := range []string{"bundle-valid-prerelease-proofs-not-carried", "bundle-valid-discharge-uncarried-proof-digest-not-checked"} {
		report := verify(t, vectorByID(t, id), evidence.Options{})
		if report.Verdict != evidence.Verified || report.Scope.Reasons[evidence.ScopeProofs] != evidence.ReasonProofNotECLObject {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Scope)
		}
	}
	for _, id := range []string{"bundle-valid-discharge-issuer-label-is-actor", "bundle-valid-discharge-issuer-label-percent-encoded", "bundle-valid-discharge-issuer-mislabeled"} {
		report := verify(t, vectorByID(t, id), evidence.Options{})
		if report.Verdict != evidence.Verified || !strings.Contains(strings.Join(report.Scope.Established, " "), evidence.ScopeProofs) {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Findings)
		}
	}
	// EBMP2-076: the decision names no issuer for the witness obligation, so the issuer test is not
	// made and the proofs are reported not verified; the bundle verifies.
	unnamed := verify(t, vectorByID(t, "bundle-valid-discharge-witness-source-not-named"), evidence.Options{})
	if unnamed.Verdict != evidence.Verified || unnamed.Scope.Reasons[evidence.ScopeProofs] != evidence.ReasonIssuerNotNamed {
		t.Errorf("issuer-not-named: %s %v %v", unnamed.Verdict, unnamed.Findings, unnamed.Scope)
	}
	entry := "object 4: /extensions/0/value/obligations"
	for id, messages := range map[string][]string{
		"bundle-invalid-discharge-approval-signed-without-approval-purpose": {entry + "/0/proof/reference: names an approval record signed by a key without the approval purpose"},
		"bundle-invalid-discharge-proof-signed-by-actor":                    {entry + "/1/proof/reference: names a proof that the requesting actor signed", entry + "/2/proof/reference: names a proof that the requesting actor signed"},
		"bundle-invalid-discharge-proof-not-from-named-source":              {entry + "/1/proof/reference: names a proof not signed by the issuer the obligation names", entry + "/2/proof/reference: names a proof not signed by the issuer the obligation names"},
		"bundle-invalid-discharge-proof-of-another-type":                    {entry + "/0/proof/reference: names a proof of a type the obligation does not admit"},
		"bundle-invalid-discharge-witness-result-of-another-witness":        {entry + "/1/proof/reference: names a witness result of another witness", entry + "/2/proof/reference: names a witness result of another witness"},
		"bundle-invalid-discharge-approval-by-another-approver":             {entry + "/0/proof/reference: names an approval by an approver other than the one the obligation names"},
		"bundle-invalid-discharge-approval-rejects":                         {entry + "/0/proof/reference: names an intervention that does not approve"},
		"bundle-invalid-discharge-proof-is-the-decision-response":           {entry + "/0/proof/reference: names a decision message as a proof"},
		"bundle-invalid-discharge-approval-of-another-request":              {entry + "/0/proof/reference: names an approval of another request"},
		"bundle-invalid-discharge-proof-expired-at-release":                 {entry + "/0/fresh_until: is not later than the release plus its declared release guard", entry + "/0/proof/reference: names a proof that expired before the release plus its declared release guard"},
		"bundle-invalid-discharge-fresh-until-beyond-proof-bound":           {entry + "/0/fresh_until: is later than the bound the proof declares"},
		"bundle-invalid-discharge-uncarried-proof-stale":                    {"object 3: /extensions/0/value/obligations/0/fresh_until: is not later than the release plus its declared release guard"},
	} {
		report := verify(t, vectorByID(t, id), evidence.Options{})
		var expected []evidence.BundleFinding
		for _, message := range messages {
			expected = append(expected, evidence.BundleFinding{Code: evidence.ObligationUnproven, Message: message})
		}
		if report.Verdict != evidence.Invalid || fmt.Sprint(report.Findings) != fmt.Sprint(expected) || len(report.Scope.Established) != 0 {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Findings)
		}
	}
	envelope := verify(t, vectorByID(t, "bundle-invalid-discharge-proof-envelope-invalid"), evidence.Options{})
	if envelope.Verdict != evidence.Invalid || envelope.Findings[0].Code != evidence.PolicyInvalid || !strings.Contains(fmt.Sprint(envelope.Findings), "names a proof whose envelope is not valid under the trust policy") {
		t.Fatalf("%s %v", envelope.Verdict, envelope.Findings)
	}
	if report := verify(t, vectorByID(t, "bundle-valid-discharge-uncarried-proof-fresh"), evidence.Options{}); report.Verdict != evidence.Verified {
		t.Fatalf("%s %v", report.Verdict, report.Findings)
	}
	if report := verify(t, vectorByID(t, "bundle-invalid-discharge-result-not-satisfied"), evidence.Options{}); report.Findings[0].Code != "ecl.rule.extension-value-valid.v1" {
		t.Fatalf("%v", report.Findings)
	}
	if report := verify(t, vectorByID(t, "bundle-valid-post-release-obligation"), evidence.Options{}); !strings.Contains(strings.Join(report.Scope.NotEstablished, " "), "post-release-obligations-met") {
		t.Fatalf("%v", report.Scope)
	}
}

// EBMP2-072 to EBMP2-075: recorded forwards, use counts, single-use releases and the MCP binding.
func TestReleaseRecordsAndAuthorityUse(t *testing.T) {
	for id, expected := range map[string]evidence.BundleFinding{
		"bundle-invalid-mcp-released-after-valid-until":         {Code: evidence.Expired, Message: "envelope 4: the terminal event records that the release completed after the authorization's valid_until"},
		"bundle-invalid-release-guard-reaches-valid-until":      {Code: evidence.Expired, Message: "the release, with its declared release guard, lies outside the authorization's validity window"},
		"bundle-invalid-mcp-terminal-names-another-call":        {Code: evidence.DecisionBindingInvalid, Message: "envelope 4: the event's MCP binding names another call than its request"},
		"bundle-invalid-mcp-success-without-response-digest":    {Code: evidence.DecisionBindingInvalid, Message: "envelope 4: the terminal event binds no server response"},
		"bundle-invalid-use-count-beyond-policy":                {Code: evidence.DecisionBindingInvalid, Message: "envelope 2: the use count is outside the authorization's use policy"},
		"bundle-invalid-single-use-consumed-twice":              {Code: evidence.DecisionBindingInvalid, Message: "two consumptions of one authorization record one use"},
		"bundle-invalid-single-use-release-without-consumption": {Code: evidence.DecisionBindingInvalid, Message: "envelope 2: a release of single-use authority has no recorded consumption"},
	} {
		report := verify(t, vectorByID(t, id), evidence.Options{})
		if report.Verdict != evidence.Invalid || len(report.Findings) == 0 || report.Findings[0] != expected {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Findings)
		}
	}
	if report := verify(t, vectorByID(t, "bundle-valid-mcp-forward-within-authority"), evidence.Options{}); report.Verdict != evidence.Verified || report.CompletionAfterWindow {
		t.Fatalf("%s %v", report.Verdict, report.Findings)
	}
	// The release plus its guard is tested, and a late answer is information.
	if report := verify(t, vectorByID(t, "bundle-valid-release-guard-inside-window"), evidence.Options{}); report.Verdict != evidence.Verified {
		t.Fatalf("%s %v", report.Verdict, report.Findings)
	}
	late := verify(t, vectorByID(t, "bundle-valid-mcp-forward-completed-after-valid-until"), evidence.Options{})
	if late.Verdict != evidence.Verified || !late.CompletionAfterWindow || !strings.Contains(strings.Join(late.Scope.Established, " "), "release-within-authority") {
		t.Fatalf("%s %v %v", late.Verdict, late.Findings, late.CompletionAfterWindow)
	}
	if report := verify(t, vectorByID(t, "bundle-invalid-mcp-released-after-valid-until"), evidence.Options{}); report.CompletionAfterWindow {
		t.Fatal("a late release is not a late answer")
	}
}

// EBMP2-076: every report carries the scope of its verdict, in the order of the table, and the
// scope follows a verdict that another check changes.
func TestReportScope(t *testing.T) {
	invalid := verify(t, vectorByID(t, "bundle-invalid-prerelease-approval-unmet"), evidence.Options{})
	// decision-basis-register applies only when the caller supplies a register.
	var applying []string
	for _, item := range evidence.ScopeChecks {
		if item != "decision-basis-register" {
			applying = append(applying, item)
		}
	}
	if len(invalid.Scope.Established) != 0 || strings.Join(invalid.Scope.NotEstablished, " ") != strings.Join(append(applying, "prerelease-obligations-met", "recorded-times-true", "effects-occurred", "deployment-assessed", "statements-true"), " ") {
		t.Fatalf("%v", invalid.Scope)
	}
	incomplete := verify(t, vectorByID(t, "bundle-incomplete-no-terminal"), evidence.Options{})
	if incomplete.Verdict != evidence.Incomplete || strings.Contains(strings.Join(incomplete.Scope.Established, " "), "causal-completeness") {
		t.Fatalf("%s %v", incomplete.Verdict, incomplete.Scope)
	}
	failedNow := verify(t, vectorByID(t, "bundle-current-trust-failed-revoked-after-use"), evidence.Options{})
	if failedNow.Verdict != evidence.CurrentTrustFailed || !strings.Contains(strings.Join(failedNow.Scope.NotEstablished, " "), "current-trust") || !strings.Contains(strings.Join(failedNow.Scope.Established, " "), "causal-completeness") {
		t.Fatalf("%s %v", failedNow.Verdict, failedNow.Scope)
	}
	discharged := verify(t, vectorByID(t, "bundle-valid-prerelease-obligations-discharged"), evidence.Options{})
	changed := *discharged
	changed.Verdict = evidence.Incomplete
	rescoped := evidence.ScopeOf(&changed)
	if strings.Contains(strings.Join(rescoped.Established, " "), "causal-completeness") || !strings.Contains(strings.Join(rescoped.Established, " "), "prerelease-obligations-discharge-recorded") {
		t.Fatalf("%v", rescoped)
	}
	for _, item := range append(append([]string{}, evidence.ScopeChecks...), evidence.ScopeNever...) {
		if text := evidence.ScopeText[item]; text == "" || strings.Contains(text, "\u2014") {
			t.Errorf("%s: %q", item, text)
		}
	}
}

func vectorByID(t *testing.T, id string) vectors.Vector {
	t.Helper()
	for _, vector := range vectors.Suite(t, "evidence-bundle").Vectors {
		if vector.ID == id {
			return vector
		}
	}
	t.Fatalf("no vector %s", id)
	return vectors.Vector{}
}

// DCMP2-053: the verifier requires the decision basis of every decision response.
func TestDecisionBasisRequired(t *testing.T) {
	plain := vectorByID(t, "bundle-invalid-missing-decision-basis")
	bundle, err := strict.Parse(vectors.Read(t, plain.Path))
	if err != nil {
		t.Fatal(err)
	}
	policy := load(t, plain.TrustPolicyPath)
	report, err := evidence.Verify(bundle, policy, evidence.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != evidence.Invalid || strings.Join(evidence.ReportedIdentifiers(report), " ") != evidence.DecisionBasisRequired {
		t.Fatalf("%s %v", report.Verdict, report.Findings)
	}
	if message := report.Findings[0].Message; !strings.HasSuffix(message, ": /extensions: the decision response records no decision basis") || !strings.HasPrefix(message, "object ") {
		t.Errorf("%q", message)
	}
}

// DCMP2-053: a decision basis is checked against the register that the caller supplies.
func TestDecisionBasisMatchesRegister(t *testing.T) {
	matched := vectorByID(t, "bundle-valid-decision-basis-matches-register")
	bundle, err := strict.Parse(vectors.Read(t, matched.Path))
	if err != nil {
		t.Fatal(err)
	}
	policy := load(t, matched.TrustPolicyPath)
	register, err := evidence.LoadRegister(vectors.Read(t, matched.RegisterPath))
	if err != nil {
		t.Fatal(err)
	}
	report, err := evidence.Verify(bundle, policy, evidence.Options{Now: now, Register: register})
	if err != nil || report.Verdict != evidence.Verified {
		t.Fatalf("%v %v", report, err)
	}
	reference, err := evidence.RegisterReference(register)
	if err != nil || fmt.Sprint(report.Register) != fmt.Sprint(reference) || report.JSON()["register"] == nil {
		t.Fatalf("%v %v %v", report.Register, reference, err)
	}
	other, err := evidence.LoadRegister(vectors.Read(t, "conformance/suites/evidence-bundle/register-version-2.json"))
	if err != nil {
		t.Fatal(err)
	}
	refused, err := evidence.Verify(bundle, policy, evidence.Options{Now: now, Register: other})
	if err != nil || refused.Verdict != evidence.Invalid || strings.Join(evidence.ReportedIdentifiers(refused), " ") != evidence.DecisionBasisMatchesRegister {
		t.Fatalf("%v %v", refused, err)
	}
	// A register that its schema refuses is a caller error, from bytes and as a value.
	broken := map[string]any{"register_id": "urn:example:register:bundle"}
	if _, err := evidence.Verify(bundle, policy, evidence.Options{Now: now, Register: broken}); !errors.Is(err, evidence.ErrInvalidRegister) {
		t.Errorf("value: %v", err)
	}
	if _, err := evidence.Verify(bundle, policy, evidence.Options{Now: now, Register: []any{}}); !errors.Is(err, evidence.ErrInvalidRegister) {
		t.Errorf("not an object: %v", err)
	}
	var input *evidence.InputError
	for _, data := range [][]byte{[]byte(`{"register_id":"urn:example:register:bundle"}`), []byte("{"), make([]byte, evidence.MaxRegisterBytes+1)} {
		if _, err := evidence.LoadRegister(data); !errors.As(err, &input) || !strings.Contains(input.Message, "register") {
			t.Errorf("%.20q: %v", data, err)
		}
	}
}

// Times against the register, the register rule, the same primary finding inside a
// bundle as alone (EBMP2-068), and the stage of each bundle rule.

const refusedRegister = "conformance/suites/document-coverage/register-invalid-action-class-declared-twice.json"

// DCMP2-053: times are checked against the register's deadlines and maximum ages, and derivations
// against its declarations.
func TestDecisionBasisTimesAndDerivationsAgainstRegister(t *testing.T) {
	for _, id := range []string{"bundle-valid-decision-basis-times-within-register", "bundle-valid-decision-basis-declared-derivation"} {
		if report := verify(t, vectorByID(t, id), evidence.Options{}); report.Verdict != evidence.Verified {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Findings)
		}
	}
	for id, suffix := range map[string]string{
		"bundle-invalid-decision-basis-input-after-deadline":         "/obtained_at: the input was obtained after its declared deadline",
		"bundle-invalid-decision-basis-value-older-than-maximum-age": "/value_at: the input's value is older than its declared maximum age",
		"bundle-invalid-decision-basis-hidden-derivation":            "/derived_from: the inputs it is computed from are not the ones the register declares",
	} {
		report := verify(t, vectorByID(t, id), evidence.Options{})
		if report.Verdict != evidence.Invalid || strings.Join(evidence.ReportedIdentifiers(report), " ") != evidence.DecisionBasisMatchesRegister || !strings.HasSuffix(report.Findings[0].Message, suffix) {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Findings)
		}
	}
}

// DCMP2-053: a register that breaks the register declarations rule is a usage error.
func TestRegisterRuleIsAUsageError(t *testing.T) {
	var input *evidence.InputError
	_, err := evidence.LoadRegister(vectors.Read(t, refusedRegister))
	expected := "malformed register: the register breaks ecl.rule.register-declarations-consistent.v1: /entries/1/action_class_id: the register declares this action class more than once"
	if !errors.As(err, &input) || input.Message != expected {
		t.Fatalf("%v", err)
	}
	matched := vectorByID(t, "bundle-valid-decision-basis-matches-register")
	bundle, err := strict.Parse(vectors.Read(t, matched.Path))
	if err != nil {
		t.Fatal(err)
	}
	register, err := strict.Parse(vectors.Read(t, refusedRegister))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.Verify(bundle, load(t, matched.TrustPolicyPath), evidence.Options{Now: now, Register: register}); !errors.Is(err, evidence.ErrInvalidRegister) {
		t.Fatalf("value: %v", err)
	}
}

// EBMP2-068, stage 3: an object that satisfies its schema but breaks a semantic rule is
// semantic-invalid, which ranks after the rules, so its own primary finding leads.
func TestSamePrimaryFindingInsideABundle(t *testing.T) {
	for id, code := range map[string]string{
		"bundle-invalid-admit-on-judgment":     "ecl.rule.decision-basis-one-way.v1",
		"bundle-invalid-negative-budget-debit": "ecl.rule.budget-debit-non-negative.v1",
	} {
		report := verify(t, vectorByID(t, id), evidence.Options{})
		if report.Verdict != evidence.Invalid || report.Findings[0].Code != code {
			t.Errorf("%s: %s %v", id, report.Verdict, report.Findings)
			continue
		}
		var refused []string
		for _, check := range report.EnvelopeChecks {
			if check.Historical != "valid" {
				refused = append(refused, check.Historical)
			}
		}
		codes := " " + strings.Join(evidence.FindingCodes(report), " ") + " "
		if strings.Join(refused, " ") != evidence.SemanticInvalid || !strings.Contains(codes, " "+evidence.SemanticInvalid+" ") || strings.Contains(codes, " "+evidence.SchemaInvalid+" ") {
			t.Errorf("%s: %v %v", id, refused, report.Findings)
		}
	}
}

// DCMP2-053: with the request in hand, an input whose source is the requesting actor is not
// verifiable.
func TestVerifiableInputFromTheRequestingActor(t *testing.T) {
	report := verify(t, vectorByID(t, "bundle-invalid-verifiable-input-from-actor"), evidence.Options{})
	expected := "ecl.rule.decision-basis-one-way.v1: object 1: /extensions/0/value/inputs/0/class: an input whose source is the requesting actor cannot be verifiable"
	if report.Verdict != evidence.Invalid || len(report.Findings) != 1 || report.Findings[0].Code+": "+report.Findings[0].Message != expected {
		t.Fatalf("%s %v", report.Verdict, report.Findings)
	}
	request := map[string]any{"actor": map[string]any{"id": "urn:example:agent:test-1"}}
	entry := func(class, source string) any {
		return map[string]any{"input": "urn:example:input:" + source, "class": class, "required": false, "status": "unavailable", "effect": "none", "source": source}
	}
	value := map[string]any{"inputs": []any{entry("verifiable", "URN:example:agent:test-1"), entry("judgment", "urn:example:agent:test-1"), entry("verifiable", "urn:example:agent:test-2")}}
	if found := evidence.ActorSourceProblems(value, request); fmt.Sprint(found) != "[[/inputs/0/class an input whose source is the requesting actor cannot be verifiable]]" {
		t.Fatalf("%v", found)
	}
	for _, other := range []map[string]any{{}, {"actor": "urn:example:agent:test-1"}, {"actor": map[string]any{"id": 7}}} {
		if found := evidence.ActorSourceProblems(value, other); len(found) != 0 {
			t.Errorf("%v: %v", other, found)
		}
	}
	if found := evidence.ActorSourceProblems(map[string]any{"inputs": "not a list"}, request); len(found) != 0 {
		t.Errorf("%v", found)
	}
}

// With the request in hand, a request was not received before it was issued,
// beyond the verification profile's response clock-skew allowance (DCMP2-047).
func TestRequestReceivedBeforeItWasIssued(t *testing.T) {
	request := map[string]any{"actor": map[string]any{"id": "urn:example:agent:payments-1"}, "issued_at": "2026-07-27T04:30:00.010000Z"}
	for _, item := range []struct {
		received string
		skew     int
		refused  bool
	}{
		{"2026-07-26T04:30:00.010000Z", 0, true},
		{"2026-07-27T04:30:00.010000Z", 0, false},
		{"2026-07-27T04:29:59.010000Z", 0, true},
		{"2026-07-27T04:29:59.010000Z", 1, false},
		{"2026-07-27T04:29:59.010000Z", -5, true},
	} {
		found := evidence.RequestProblems(map[string]any{"inputs": []any{}, "received_at": item.received}, request, item.skew)
		if refused := fmt.Sprint(found) == "[[/received_at the request was received before it was issued]]"; refused != item.refused || (!refused && len(found) != 0) {
			t.Errorf("%s %d: %v", item.received, item.skew, found)
		}
	}
	if found := evidence.RequestProblems(map[string]any{"inputs": []any{}}, request, 0); len(found) != 0 {
		t.Errorf("no received_at: %v", found)
	}
}

// A source is compared with the register's declared source as input names are; every
// entry names its source (DCMP2-053).
func TestSourceComparedWithTheDeclaredSource(t *testing.T) {
	value, err := strict.Parse(vectors.Read(t, "conformance/suites/evidence-bundle/register.json"))
	if err != nil {
		t.Fatal(err)
	}
	register := value.(map[string]any)
	digest, err := evidence.RegisterDigest(register)
	if err != nil {
		t.Fatal(err)
	}
	actionClass := "ecl.action.ai-proposed-operation.v1"
	declarations := evidence.DeclaredInputs(register, actionClass)
	basis := func(source any) map[string]any {
		var inputs []any
		for position, declaration := range declarations {
			entry := map[string]any{"input": declaration["input"], "class": declaration["class"], "required": declaration["required"], "status": "available", "effect": "none", "source": declaration["source"]}
			if position == 0 {
				if source == nil {
					delete(entry, "source")
				} else {
					entry["source"] = source
				}
			}
			inputs = append(inputs, entry)
		}
		return map[string]any{"inputs": inputs, "register": map[string]any{"uri": register["register_id"], "digest": digest}}
	}
	declared := declarations[0]["source"].(string)
	for _, item := range []struct {
		source  any
		refused bool
	}{
		{declared, false},
		{"URN:" + strings.SplitN(declared, ":", 2)[1], false},
		{declared + "-other", true},
		{nil, true},
	} {
		found, err := evidence.RegisterProblems(basis(item.source), register, actionClass)
		if err != nil {
			t.Fatal(err)
		}
		refused := fmt.Sprint(found) == "[[/inputs/0/source the source is not the one the register declares]]"
		if refused != item.refused || (!refused && len(found) != 0) {
			t.Errorf("%v: %v", item.source, found)
		}
	}
}

// EBMP2-068: each bundle rule names its stage in the registry.
func TestBundleRuleStages(t *testing.T) {
	expected := map[string]int{
		"ecl.rule.bundle-causal-graph-acyclic.v1":       8,
		"ecl.rule.bundle-causal-context-consistent.v1":  8,
		"ecl.rule.bundle-causal-sequence-monotonic.v1":  8,
		"ecl.rule.bundle-object-identifiers-unique.v1":  3,
		"ecl.rule.bundle-predecessor-digest-valid.v1":   8,
		"ecl.rule.decision-basis-matches-register.v1":   3,
		"ecl.rule.decision-basis-required.v1":           3,
		"ecl.rule.execution-state-transition-valid.v1":  8,
		"ecl.rule.prerelease-obligations-discharged.v1": 8,
	}
	if got := registry.Stages(); fmt.Sprint(got) != fmt.Sprint(expected) {
		t.Fatalf("%v", got)
	}
}

func ExampleVerifyBytes() {
	bundle, _ := vectors.ReadFile("conformance/fixtures/evidence/corroborated.json")
	policy, _ := vectors.ReadFile("conformance/fixtures/evidence/trust-policy.json")
	report, _, err := evidence.VerifyBytes(bundle, policy, nil, evidence.Options{Now: "2026-10-01T00:00:00Z"})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(report.Verdict, report.CausalStatus)
	for _, effect := range report.Effects {
		fmt.Println(effect.State, effect.Level, effect.Authority)
	}
	// Output:
	// verified complete
	// succeeded corroborated consumed
}

// RC-6 integration: EBMP2-062 and IE1-029. A payload that holds more values than remain of the
// bundle's node budget is refused at the budget, before a repeated member name after them (IE1-037,
// check 3 before check 5), and the bundle is not analyzed further.
func TestAPayloadBeyondTheBudgetIsRefusedBeforeItsLaterDefects(t *testing.T) {
	source, err := strict.Parse(vectors.Read(t, "conformance/fixtures/evidence/succeeded.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := source.(map[string]any)
	first := bundle["envelopes"].([]any)[0].(map[string]any)
	values := strings.TrimSuffix(strings.Repeat("0,", 100_500), ",")
	raw := []byte(`{"unrecognized":[` + values + `],"zz":1,"zz":2}`)
	sum := sha256.Sum256(raw)
	first["payload"] = base64.StdEncoding.EncodeToString(raw)
	first["payload_digest"] = map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": hex.EncodeToString(sum[:])}
	bundle["envelopes"] = []any{first}
	policy := load(t, "conformance/fixtures/evidence/trust-policy.json")
	report, err := evidence.Verify(bundle, policy, evidence.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != evidence.Invalid {
		t.Fatalf("verdict %s", report.Verdict)
	}
	if got := evidence.ReportedIdentifiers(report); len(got) != 1 || got[0] != "ecl.error.resource-limit-exceeded.v1" {
		t.Fatalf("identifiers %v", got)
	}
	if len(report.EnvelopeChecks) != 0 {
		t.Fatalf("envelope checks %v", report.EnvelopeChecks)
	}
}

// IE1-028: the record limits of the causal analysis are integers of at least 1.
func TestCausalAnalysisLimitsBelowOneAreRefused(t *testing.T) {
	for _, limits := range [][2]int{{0, 1}, {1, 0}, {-1, 1}, {1, -1}} {
		if _, err := evidence.Analyze(nil, nil, limits[0], limits[1]); !errors.Is(err, evidence.ErrLimits) {
			t.Fatalf("limits %v: %v", limits, err)
		}
	}
	if _, err := evidence.Analyze(nil, nil, 1, 1); err != nil {
		t.Fatalf("limits of 1: %v", err)
	}
}
