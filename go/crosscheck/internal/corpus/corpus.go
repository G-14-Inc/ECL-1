// Package corpus evaluates every vector of the shared conformance corpus with this module's
// packages and writes a cross-implementation report with raw evidence. Expected results never
// enter the evaluation; they are compared only afterwards.
package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/bindings"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/offline"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

// Capabilities are the corpus capabilities this module implements: the nine of RC-4, the three of
// the first RC-5 pass (the binding profiles' rules, the decision-basis rule and the claim and
// assessment document stage), the five of the RC-5 specification fixes (one version of an
// extension per object, the extension rules on documents, one role per key, binding inputs that
// agree with the decision basis, and keyed OpenTelemetry digests) and offline package
// verification (IE1-021, IE1-022). A capability that the corpus declares and this list lacks
// would be reported as unsupported, never as met. ML-DSA-65 signatures are recognized and refused
// as unsupported; no vector needs them.
var Capabilities = []string{
	"strict-json", "canonical-digest", "semantic-rules", "safe-state-profile-rules",
	"schema-validation", "trust-policy-load", "envelope-signature-verification",
	"evidence-bundle-verification", "control-extension-rules", "binding-profile-rules",
	"decision-basis-rule", "document-validation", "extension-version-rule",
	"document-extension-rules", "deployment-timing-case", "key-role-separation", "binding-basis-agreement-rule",
	"otel-export-keyed-digests", "offline-package-verification", "work-intent-contract",
}

// The v3 profile's capability vocabulary, separate from this implementation's support.
var requiredCapabilities = []string{"strict-json", "canonical-digest", "semantic-rules", "safe-state-profile-rules"}
var optionalCapabilities = []string{
	"schema-validation", "trust-policy-load", "envelope-signature-verification", "evidence-bundle-verification", "control-extension-rules", "binding-profile-rules", "decision-basis-rule", "document-validation", "extension-version-rule", "document-extension-rules", "deployment-timing-case", "key-role-separation", "binding-basis-agreement-rule", "otel-export-keyed-digests", "offline-package-verification", "work-intent-contract",
}

func corpusCapabilities(corpus Corpus) ([]string, error) {
	for name, list := range map[string][]string{"required_capabilities": corpus.Required, "optional_capabilities": corpus.Optional} {
		if list == nil {
			return nil, fmt.Errorf("%s must be an array", name)
		}
		seen := map[string]bool{}
		for _, item := range list {
			if item == "" || seen[item] {
				return nil, fmt.Errorf("invalid or duplicate %s", name)
			}
			seen[item] = true
		}
	}
	for _, required := range corpus.Required {
		if !has(Capabilities, required) {
			return nil, fmt.Errorf("missing required capability: %s", required)
		}
	}
	if len(corpus.Required) != len(requiredCapabilities) {
		return nil, errors.New("corpus required capabilities differ from the v3 profile")
	}
	for _, required := range requiredCapabilities {
		if !has(corpus.Required, required) {
			return nil, errors.New("corpus required capabilities differ from the v3 profile")
		}
	}
	for _, optional := range corpus.Optional {
		if !has(optionalCapabilities, optional) || has(corpus.Required, optional) {
			return nil, errors.New("unregistered or overlapping optional capability")
		}
	}
	if corpus.Vectors == nil {
		return nil, errors.New("corpus vectors must be an array")
	}
	supported := []string{}
	for _, capability := range Capabilities {
		if has(corpus.Required, capability) || has(corpus.Optional, capability) {
			supported = append(supported, capability)
		}
	}
	for _, implication := range [][2]string{{"evidence-bundle-verification", "decision-basis-rule"}, {"binding-profile-rules", "decision-basis-rule"}, {"binding-basis-agreement-rule", "decision-basis-rule"}, {"offline-package-verification", "evidence-bundle-verification"}} {
		if has(supported, implication[0]) && !has(supported, implication[1]) {
			return nil, fmt.Errorf("%s requires %s", implication[0], implication[1])
		}
	}
	return supported, nil
}

// Disclosure states how this implementation relates to the reference.
const Disclosure = "Robert F. Tilley Jr. and G-14, Inc. maintain this repository's Go library packages, protocol and profile rules, runner and Python reference. The imported foundation core is separately maintained. The repository code implements the documented behavior without importing or calling the Python reference."

const schemaInvalid = "ecl.error.schema-invalid.v1"
const semanticInvalid = "ecl.error.semantic-invalid.v1"

// strictRules are the registered rules of strict input (IE1-002, IE1-037).
var strictRules = map[string]bool{
	strict.RuleStrictSyntax:       true,
	strict.RuleNoDuplicateMembers: true,
	strict.RuleRestrictedNumbers:  true,
}

// Case is one vector of the shared corpus index.
type Case struct {
	Suite      string `json:"suite"`
	ID         string `json:"id"`
	Capability string `json:"capability"`
}

// Corpus is the shared corpus index.
type Corpus struct {
	Schema    string   `json:"schema_version"`
	Version   int      `json:"version"`
	Candidate string   `json:"candidate_version"`
	Required  []string `json:"required_capabilities"`
	Optional  []string `json:"optional_capabilities"`
	Vectors   []Case   `json:"vectors"`
}

// Vector is one vector of a suite manifest.
type Vector struct {
	ID                 string   `json:"id"`
	Path               string   `json:"path"`
	Stage              string   `json:"stage"`
	Schema             string   `json:"schema"`
	Expected           string   `json:"expected"`
	Primary            string   `json:"expected_primary_id"`
	Secondary          []string `json:"expected_secondary_ids"`
	CanonicalHash      string   `json:"expected_canonical_sha256"`
	TrustPolicyPath    string   `json:"trust_policy_path"`
	TrustPolicyHistory []string `json:"trust_policy_history_paths"`
	EvaluatedAt        string   `json:"evaluated_at"`
	RequireTrustedTime bool     `json:"require_trusted_time"`
	// RegisterPath names a Consequential Action Register to check each decision basis against.
	RegisterPath    string `json:"register_path"`
	ExpectedVerdict string `json:"expected_verdict"`
	// AcceptCurrentTrustFailure verifies the bundle or package with the caller's acceptance of
	// current trust failures (EBMP2-060).
	AcceptCurrentTrustFailure bool `json:"accept_current_trust_failure"`
	// ExpectedScope, ExpectedEffects and ExpectedUnresolved, when present, are the scope, evidence
	// levels and unresolved predecessors that the report must give (EBMP2-076, EBMP2-061).
	ExpectedScope      *ExpectedScope   `json:"expected_scope"`
	ExpectedEffects    []ExpectedEffect `json:"expected_effects"`
	ExpectedUnresolved *[]string        `json:"expected_unresolved_predecessor_ids"`
	// StrictJSONLimits are the declared limits under which the Parse step reads the artifact
	// (IE1-028, IE1-037); without them the library's own apply.
	StrictJSONLimits *StrictJSONLimits `json:"strict_json_limits"`
}

// StrictJSONLimits are a vector's declared strict JSON limits.
type StrictJSONLimits struct {
	MaxBytes int `json:"max_bytes"`
	MaxDepth int `json:"max_depth"`
	MaxNodes int `json:"max_nodes"`
}

// Parse reads data as strict JSON under the vector's declared limits, or the library's own.
func (v Vector) Parse(data []byte) (any, error) {
	if v.StrictJSONLimits == nil {
		return strict.Parse(data)
	}
	return strict.ParseLimited(data, strict.Limits{MaxBytes: v.StrictJSONLimits.MaxBytes, MaxDepth: v.StrictJSONLimits.MaxDepth, MaxNodes: v.StrictJSONLimits.MaxNodes})
}

// Manifest is a suite manifest.
type Manifest struct {
	Schema          string `json:"schema_version"`
	Suite           string `json:"suite"`
	TrustPolicyPath string `json:"trust_policy_path"`
	// ExportKeysPath names the suite's OpenTelemetry export key file (OE1-010).
	ExportKeysPath string   `json:"export_keys_path"`
	Vectors        []Vector `json:"vectors"`
}

// Result is one vector's result row of the report.
type Result struct {
	ID           string   `json:"id"`
	Suite        string   `json:"suite"`
	ArtifactHash string   `json:"artifact_sha256"`
	Expected     string   `json:"expected"`
	Status       string   `json:"status"`
	Primary      *any     `json:"observed_primary_id,omitempty"`
	Secondary    []string `json:"observed_secondary_ids"`
	Unsupported  string   `json:"unsupported_capability,omitempty"`
	RawHash      string   `json:"raw_result_sha256,omitempty"`
	// An outer nil omits a field; a pointer to nil records an unavailable observation.
	ObservedVerdict    *any `json:"observed_verdict,omitempty"`
	ObservedScope      *any `json:"observed_scope,omitempty"`
	ObservedEffects    *any `json:"observed_effects,omitempty"`
	ObservedUnresolved *any `json:"observed_unresolved_predecessor_ids,omitempty"`
	ObservedCanonical  *any `json:"observed_canonical_sha256,omitempty"`
}

// Context is what the vectors of one run share.
type Context struct {
	Root string
	// TrustPolicy is the manifest's trust policy, for the envelope suite.
	TrustPolicy *trust.Policy
	// ExportKeys are the export keys that the manifest's key file holds, for the otel-export suite.
	ExportKeys map[string]bindings.ExportKey
	Semantics  semantic.Options
	// Verdicts receives the verdict of each evidence-bundle vector.
	Verdicts         map[string]string
	CanonicalDigests map[string]string
	// Reports receives the report of each evidence-bundle and package vector.
	Reports map[string]*evidence.Report
}

func has(set []string, key string) bool {
	for _, item := range set {
		if item == key {
			return true
		}
	}
	return false
}

func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

func encode(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	// Python's compact ensure_ascii=False JSON leaves these scalar values literal.
	// Skip complete escape pairs so a literal backslash-u spelling stays unchanged.
	data := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	out := make([]byte, 0, len(data))
	for index := 0; index < len(data); {
		if data[index] == '\\' && index+1 < len(data) {
			if index+6 <= len(data) && (string(data[index:index+6]) == `\u2028` || string(data[index:index+6]) == `\u2029`) {
				out = append(out, 0xe2, 0x80, 0xa8+(data[index+5]-'8'))
				index += 6
				continue
			}
			out = append(out, data[index], data[index+1])
			index += 2
			continue
		}
		out = append(out, data[index])
		index++
	}
	return out, nil
}

// Reporting budgets are distinct from the verifier's stage limits. Files larger than
// this report-integrity ceiling cannot be bound by this runner's report.
const maxBoundFileBytes int64 = 512 * 1024 * 1024
const maxBoundTotalBytes int64 = 4 * 1024 * 1024 * 1024
const maxBoundFileCount = 100_000

func openArtifact(root, relative string) (*os.File, error) {
	if !fs.ValidPath(relative) || strings.Contains(relative, "\\") {
		return nil, fmt.Errorf("unsafe artifact path: %s", relative)
	}
	current := root
	for _, part := range strings.Split(relative, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("artifact symlink: %s", relative)
		}
	}
	file, err := os.Open(current)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("artifact type: %s", relative)
	}
	return file, nil
}

func readPrefix(root, relative string, limit int64) ([]byte, error) {
	file, err := openArtifact(root, relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

// Metadata retains its own bounded read. Vector data uses its declared stage below.
func read(root, relative string) ([]byte, error) {
	data, err := readPrefix(root, relative, strict.MaxInputBytes)
	if err != nil {
		return nil, err
	}
	if len(data) > strict.MaxInputBytes {
		return nil, errors.New("artifact byte limit exceeded")
	}
	return data, nil
}

// readAndHash retains at most prefixBytes and streams the exact file digest from the
// same open handle. A zero prefix hashes source bytes without retaining their contents.
func readAndHash(root, relative string, prefixBytes int64) ([]byte, string, int64, error) {
	file, err := openArtifact(root, relative)
	if err != nil {
		return nil, "", 0, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, "", 0, err
	}
	if before.Size() > maxBoundFileBytes {
		return nil, "", 0, fmt.Errorf("artifact exceeds report byte budget: %s", relative)
	}
	if prefixBytes < 0 {
		return nil, "", 0, errors.New("negative retained prefix")
	}
	if prefixBytes > maxBoundFileBytes+1 {
		prefixBytes = maxBoundFileBytes + 1
	}
	hash := sha256.New()
	data, err := io.ReadAll(io.TeeReader(io.LimitReader(file, prefixBytes), hash))
	if err != nil {
		return nil, "", 0, err
	}
	rest, err := io.Copy(hash, io.LimitReader(file, maxBoundFileBytes+1-int64(len(data))))
	if err != nil {
		return nil, "", 0, err
	}
	size := int64(len(data)) + rest
	after, err := file.Stat()
	if err != nil {
		return nil, "", 0, err
	}
	current, err := os.Stat(file.Name())
	if err != nil {
		return nil, "", 0, err
	}
	if size > maxBoundFileBytes {
		return nil, "", 0, fmt.Errorf("artifact exceeds report byte budget: %s", relative)
	}
	if size != before.Size() || after.Size() != before.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, current) || current.Size() != size {
		return nil, "", 0, fmt.Errorf("artifact changed during read: %s", relative)
	}
	return data, hex.EncodeToString(hash.Sum(nil)), size, nil
}

func vectorByteLimit(vector Vector) (int64, error) {
	switch vector.Stage {
	case "package":
		return offline.DefaultLimits.MaxArchiveBytes, nil
	case "trust-policy":
		return trust.MaxPolicyBytes, nil
	}
	limits := strict.DefaultLimits
	if vector.StrictJSONLimits != nil {
		limits = strict.Limits{MaxBytes: vector.StrictJSONLimits.MaxBytes, MaxDepth: vector.StrictJSONLimits.MaxDepth, MaxNodes: vector.StrictJSONLimits.MaxNodes}
	}
	for _, item := range []struct {
		name  string
		value int
	}{{"MaxBytes", limits.MaxBytes}, {"MaxDepth", limits.MaxDepth}, {"MaxNodes", limits.MaxNodes}} {
		if _, err := strict.LimitFromJSON(item.name, item.value); err != nil {
			return 0, err
		}
	}
	return int64(limits.MaxBytes), nil
}

func decode(root, path string, out any) error {
	data, err := read(root, path)
	if err != nil {
		return err
	}
	if _, err = strict.Parse(data); err != nil {
		return fmt.Errorf("configuration JSON: %w", err)
	}
	return json.Unmarshal(data, out)
}

// SourceHash returns the source-tree digest of a clean export: the SHA-256 of the compact JSON
// list of {path, sha256, size_bytes}, sorted by path.
func SourceHash(root string) (string, error) {
	return sourceHash(root, maxBoundFileCount*2)
}

// sourceHash counts descendant entries; the root itself is checked but is not an entry.
func sourceHash(root string, maxEntries int) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	entries := []map[string]any{}
	var totalBytes int64
	visited := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root {
			visited++
			if visited > maxEntries {
				return errors.New("source tree entry budget exceeded")
			}
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("source symlink")
		}
		if entry.Name() == ".git" {
			return errors.New("source must be a clean export")
		}
		if path != root && (!utf8.ValidString(entry.Name()) || strings.Contains(entry.Name(), "\\")) {
			return errors.New("source name is not a valid UTF-8 relative POSIX name")
		}
		if path == root && !entry.IsDir() {
			return errors.New("source root is not a directory")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("source is not regular")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		_, hash, size, err := readAndHash(root, filepath.ToSlash(relative), 0)
		if err != nil {
			return err
		}
		totalBytes += size
		if totalBytes > maxBoundTotalBytes || len(entries) >= maxBoundFileCount {
			return errors.New("source tree report budget exceeded")
		}
		entries = append(entries, map[string]any{"path": filepath.ToSlash(relative), "sha256": hash, "size_bytes": size})
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", errors.New("source tree is empty")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i]["path"].(string) < entries[j]["path"].(string) })
	encoded, err := encode(entries)
	return digest(encoded), err
}

func unique(ids []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func ruleIDs[T any](findings []T, id func(T) string) []string {
	out := []string{}
	for _, item := range findings {
		out = append(out, id(item))
	}
	return unique(out)
}

// Evaluate returns the identifiers that one vector's artifact yields, from its bytes and stage
// alone; the vector's expectations never enter it.
func Evaluate(data []byte, vector Vector, context *Context) ([]string, error) {
	if vector.Stage == "trust-policy" {
		if len(data) > trust.MaxPolicyBytes+1 {
			data = data[:trust.MaxPolicyBytes+1]
		}
		if _, err := trust.Load(data); err != nil {
			var refusal *trust.Error
			if errors.As(err, &refusal) {
				return []string{refusal.Code}, nil
			}
			return nil, err
		}
		return []string{}, nil
	}
	if vector.Stage == "package" {
		// An offline package is an archive, so the stage reads bytes, not strict JSON (IE1-022).
		// Its bundle is verified under the same caller inputs as an evidence-bundle vector's.
		policy, options, err := vectorOptions(context.Root, vector)
		if err != nil {
			return nil, err
		}
		report, err := offline.Verify(data, policy, offline.Options{Options: options})
		if err != nil {
			return nil, err
		}
		if context.Verdicts != nil {
			context.Verdicts[vector.ID] = report.Verdict
		}
		if context.Reports != nil {
			context.Reports[vector.ID] = report
		}
		return offline.Identifiers(report), nil
	}
	value, err := vector.Parse(data)
	if err != nil {
		var strictErr *strict.Error
		if errors.As(err, &strictErr) {
			// The corpus requires a verdict even when its common Parse step refuses
			// an evidence bundle. No trust, schema, scope or effect checks ran.
			if vector.Stage == "evidence-bundle" && context != nil && context.Verdicts != nil {
				context.Verdicts[vector.ID] = "invalid"
			}
			return []string{strictErr.RuleID}, nil
		}
		return nil, err
	}
	switch vector.Stage {
	case "strict-json":
		return []string{}, nil
	case "canonical":
		computed, err := canon.Digest(value)
		if err != nil {
			return nil, err
		}
		if context.CanonicalDigests != nil {
			context.CanonicalDigests[vector.ID] = computed
		}
		if computed != vector.CanonicalHash {
			return []string{"ecl.error.canonicalization-mismatch.v1"}, nil
		}
		return []string{}, nil
	case "bundle":
		// The causal analysis of EBMP-2 section 4 over the offered records (evidence.Analyze, the
		// analysis of the bundle verifier), with the closure checks of EBMP2-023 and DW1-028: an
		// offered bundle whose analysis finds no rule broken but leaves an unresolved predecessor
		// or an open attempt is incomplete.
		root, _ := value.(map[string]any)
		records, isList := root["records"].([]any)
		if !isList {
			return []string{schemaInvalid}, nil
		}
		analysis, err := evidence.Analyze(records, nil, evidence.MaxRecords, evidence.MaxPredecessors)
		if err != nil {
			return nil, err
		}
		found := ruleIDs(analysis.Findings, func(item evidence.Finding) string { return item.RuleID })
		if len(found) == 0 && analysis.Status != "complete" {
			return []string{"ecl.error.causal-closure-incomplete.v1"}, nil
		}
		return found, nil
	case "evidence-bundle":
		policy, options, err := vectorOptions(context.Root, vector)
		if err != nil {
			return nil, err
		}
		report, err := evidence.Verify(value, policy, options)
		if err != nil {
			return nil, err
		}
		if context.Verdicts != nil {
			context.Verdicts[vector.ID] = report.Verdict
		}
		if context.Reports != nil {
			context.Reports[vector.ID] = report
		}
		return evidence.ReportedIdentifiers(report), nil
	}
	object, isObject := value.(map[string]any)
	if !isObject {
		return []string{schemaInvalid}, nil
	}
	if vector.Schema == "" {
		return nil, fmt.Errorf("%s: a %s vector names no schema", vector.ID, vector.Stage)
	}
	if vector.Stage == "document" {
		// A claim or assessment document: strict parsing, its declared schema, and the registered
		// rules whose applies_to names its type (the extension rules for a work intent).
		findings, err := documents.Evaluate(vector.Schema, object)
		if err != nil {
			return nil, err
		}
		return ruleIDs(findings, func(item semantic.Finding) string { return item.RuleID }), nil
	}
	schemaErrors, err := schema.ECL().Errors(vector.Schema, object, 1)
	if err != nil {
		return nil, err
	}
	if vector.Stage == "binding" {
		// A binding profile's checker reads only records its schema accepts.
		if len(schemaErrors) > 0 {
			return []string{schemaInvalid}, nil
		}
		findings, err := bindings.FindingsWithKeys(object, context.ExportKeys)
		if err != nil {
			return nil, err
		}
		return ruleIDs(findings, func(item semantic.Finding) string { return item.RuleID }), nil
	}
	if vector.Stage == "envelope" {
		if len(schemaErrors) > 0 {
			return []string{schemaInvalid}, nil
		}
		if context.TrustPolicy == nil {
			return nil, errors.New("the envelope suite needs its manifest's trust policy")
		}
		return verifyEnvelope(object, context.TrustPolicy)
	}
	var ids []string
	switch vector.Stage {
	case "safe-state-profile":
		ids = ruleIDs(validatorx.Validate(object), func(item validator.Finding) string { return item.RuleID })
	case "semantic", "protocol":
		findings, err := semantic.Validate(object, context.Semantics)
		if err != nil {
			return nil, err
		}
		ids = ruleIDs(findings, func(item semantic.Finding) string { return item.RuleID })
	default:
		return nil, fmt.Errorf("unsupported evaluation stage: %s", vector.Stage)
	}
	if len(schemaErrors) > 0 {
		ids = append(ids, schemaInvalid)
	}
	return ids, nil
}

// vectorOptions loads the caller inputs of an evidence-bundle or package vector (TP1-001,
// IE1-022): its trust policy and the policy's earlier versions, the evaluation time, whether
// trusted time is required and the register that the vector names, if any.
func vectorOptions(root string, vector Vector) (*trust.Policy, evidence.Options, error) {
	policy, err := loadPolicyFile(root, vector.TrustPolicyPath)
	if err != nil {
		return nil, evidence.Options{}, err
	}
	var history []*trust.Policy
	for _, path := range vector.TrustPolicyHistory {
		older, err := loadPolicyFile(root, path)
		if err != nil {
			return nil, evidence.Options{}, err
		}
		history = append(history, older)
	}
	options := evidence.Options{Now: vector.EvaluatedAt, History: history, RequireTrustedTime: vector.RequireTrustedTime, AcceptCurrentTrustFailure: vector.AcceptCurrentTrustFailure}
	if vector.RegisterPath != "" {
		data, err := readPrefix(root, vector.RegisterPath, evidence.MaxRegisterBytes)
		if err != nil {
			return nil, evidence.Options{}, err
		}
		register, err := evidence.LoadRegister(data)
		if err != nil {
			return nil, evidence.Options{}, err
		}
		options.Register = register
	}
	return policy, options, nil
}

func verifyEnvelope(object map[string]any, policy *trust.Policy) ([]string, error) {
	_, err := envelope.VerifyWithContext(object, policy.Keyring(), func(payload any) (envelope.Context, error) {
		payloadObject, isObject := payload.(map[string]any)
		if !isObject {
			return envelope.Context{}, errors.New("envelope payload has no object time")
		}
		member, timePolicy := "observed_at", "ecl.time.observed-at.v1"
		if payloadObject["protocol"] == "DCMP-2" {
			member, timePolicy = "issued_at", "ecl.time.issued-at.v1"
		}
		at, hasTime := payloadObject[member].(string)
		if !hasTime || !instant.Valid(at) {
			return envelope.Context{}, errors.New("envelope payload lacks a valid verification-time timestamp")
		}
		return policy.VerificationContext(at, timePolicy)
	})
	var refusal *envelope.Error
	switch {
	case err == nil:
		return []string{}, nil
	case errors.As(err, &refusal):
		return []string{refusal.Code}, nil
	default:
		return nil, err
	}
}

// loadKeyFile reads a suite's export key file (OE1-010) within the trust-policy byte budget.
func loadKeyFile(root, path string) (map[string]bindings.ExportKey, error) {
	data, err := readPrefix(root, path, trust.MaxPolicyBytes)
	if err != nil {
		return nil, err
	}
	return bindings.LoadExportKeys(data)
}

func loadPolicyFile(root, path string) (*trust.Policy, error) {
	data, err := readPrefix(root, path, trust.MaxPolicyBytes)
	if err != nil {
		return nil, err
	}
	return trust.Load(data)
}

// selectBundleFinding is the primary finding of a signed bundle, alone or carried in an offline
// package: the first of its identifiers, which the verifier orders by EBMP2-068 (and a package's
// own checks by IE1-022). No secondary finding is reported.
func selectBundleFinding(observed []string, precedence map[string]int, errorCodes map[string]bool) (string, []string, error) {
	for _, id := range observed {
		if _, ranked := precedence[id]; !ranked && id != schemaInvalid && !errorCodes[id] {
			return "", nil, fmt.Errorf("unregistered finding: %s", id)
		}
	}
	if len(observed) == 0 {
		return "", []string{}, nil
	}
	return observed[0], []string{}, nil
}

// selectFindings is the reference runner's choice of a primary identifier and the sorted
// secondary ones: a strict-JSON rule first, then schema invalidity, then the one registered
// specific interface error, then the rule of lowest precedence, then semantic-invalid.
func selectFindings(observed []string, precedence map[string]int, errorCodes map[string]bool) (string, []string, error) {
	findings := map[string]bool{}
	for _, id := range observed {
		findings[id] = true
	}
	isError := func(id string) bool { return id == schemaInvalid || errorCodes[id] }
	var unknown []string
	for id := range findings {
		if _, ranked := precedence[id]; !ranked && !isError(id) {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return "", nil, fmt.Errorf("unregistered findings: %v", unknown)
	}
	best := func(ids []string) string {
		sort.Strings(ids)
		chosen := ids[0]
		for _, id := range ids[1:] {
			if precedence[id] < precedence[chosen] {
				chosen = id
			}
		}
		return chosen
	}
	var strict, reported, ranked []string
	for id := range findings {
		if _, ok := precedence[id]; ok {
			ranked = append(ranked, id)
		}
		if strictRules[id] {
			strict = append(strict, id)
		}
		// A generic semantic failure is not a second specific interface error.
		if isError(id) && id != semanticInvalid {
			reported = append(reported, id)
		}
	}
	var primary string
	switch {
	case len(strict) > 0:
		primary = best(strict)
	case findings[schemaInvalid]:
		primary = schemaInvalid
	case len(reported) > 1:
		return "", nil, errors.New("ambiguous interface errors: a vector must have one loader or integrity error")
	case len(reported) == 1:
		primary = reported[0]
	case len(ranked) > 0:
		primary = best(ranked)
	case findings[semanticInvalid]:
		primary = semanticInvalid
	default:
		return "", []string{}, nil
	}
	delete(findings, primary)
	secondary := []string{}
	for id := range findings {
		secondary = append(secondary, id)
	}
	sort.Strings(secondary)
	return primary, secondary, nil
}

func registries(root string) (map[string]int, map[string]bool, error) {
	var rules struct {
		Entries []struct {
			ID         string `json:"id"`
			Status     string `json:"status"`
			Attributes struct {
				Precedence *int `json:"precedence"`
			} `json:"attributes"`
		} `json:"entries"`
	}
	if err := decode(root, "registries/semantic-rules.json", &rules); err != nil {
		return nil, nil, err
	}
	precedence := map[string]int{}
	used := map[int]bool{}
	for _, entry := range rules.Entries {
		if entry.Status != "active" {
			continue
		}
		if entry.Attributes.Precedence == nil || used[*entry.Attributes.Precedence] {
			return nil, nil, errors.New("semantic precedence is missing, duplicate or invalid")
		}
		if _, repeated := precedence[entry.ID]; repeated {
			return nil, nil, errors.New("semantic precedence is missing, duplicate or invalid")
		}
		used[*entry.Attributes.Precedence] = true
		precedence[entry.ID] = *entry.Attributes.Precedence
	}
	var codes struct {
		Entries []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := decode(root, "registries/error-codes.json", &codes); err != nil {
		return nil, nil, err
	}
	errorCodes := map[string]bool{}
	for _, entry := range codes.Entries {
		if entry.Status == "active" {
			errorCodes[entry.ID] = true
		}
	}
	return precedence, errorCodes, nil
}

// Run evaluates the complete shared corpus under root, writes the report to reportPath and its
// raw evidence beside it, and returns a summary and whether every vector met its expectation.
func Run(root, revision, reportPath string) (map[string]any, bool, error) {
	return run(root, revision, reportPath, nil)
}

// run allows an internal caller to observe the completed input preflight before
// output starts. The public runner uses no callback; tests use the checkpoint
// to change a corpus deterministically after its bytes have been parsed.
func run(root, revision, reportPath string, afterCorpusParsed func() error) (map[string]any, bool, error) {
	corpusData, err := read(root, "conformance/shared-corpus.json")
	if err != nil {
		return nil, false, err
	}
	if _, err = strict.Parse(corpusData); err != nil {
		return nil, false, fmt.Errorf("configuration JSON: %w", err)
	}
	var corpus Corpus
	if err := json.Unmarshal(corpusData, &corpus); err != nil {
		return nil, false, err
	}
	if corpus.Schema != "ecl_shared_corpus_v1" || corpus.Version != 1 || corpus.Candidate != "1.0" {
		return nil, false, errors.New("unsupported corpus identity")
	}
	capabilities, err := corpusCapabilities(corpus)
	if err != nil {
		return nil, false, err
	}
	manifests := []string{"conformance/manifest.json"}
	paths, err := filepath.Glob(filepath.Join(root, "conformance/suites/*/manifest.json"))
	if err != nil {
		return nil, false, err
	}
	for _, path := range paths {
		relative, _ := filepath.Rel(root, path)
		manifests = append(manifests, filepath.ToSlash(relative))
	}
	vectors := map[string]Vector{}
	suites := map[string]string{}
	policies := map[string]string{}
	keyFiles := map[string]string{}
	seenSuites := map[string]bool{}
	for _, path := range manifests {
		var manifest Manifest
		if err := decode(root, path, &manifest); err != nil {
			return nil, false, err
		}
		if manifest.Schema != "ecl_conformance_vector_manifest_v3" {
			return nil, false, errors.New("manifest must be v3")
		}
		if manifest.Suite == "" || seenSuites[manifest.Suite] {
			return nil, false, errors.New("missing or duplicate manifest suite")
		}
		seenSuites[manifest.Suite] = true
		for _, vector := range manifest.Vectors {
			if _, exists := vectors[vector.ID]; exists {
				return nil, false, errors.New("duplicate manifest vector ID")
			}
			vectors[vector.ID] = vector
			suites[vector.ID] = manifest.Suite
			policies[vector.ID] = manifest.TrustPolicyPath
			keyFiles[vector.ID] = manifest.ExportKeysPath
		}
	}
	if len(vectors) != len(corpus.Vectors) {
		return nil, false, errors.New("corpus does not cover every vector")
	}
	seen := map[string]bool{}
	for _, item := range corpus.Vectors {
		if seen[item.ID] || suites[item.ID] != item.Suite {
			return nil, false, errors.New("corpus ID or suite differs from manifests")
		}
		seen[item.ID] = true
		if !has(corpus.Required, item.Capability) && !has(corpus.Optional, item.Capability) {
			return nil, false, errors.New("undeclared vector capability")
		}
	}
	precedence, errorCodes, err := registries(root)
	if err != nil {
		return nil, false, err
	}
	sourceHash, err := SourceHash(filepath.Join(root, "go/crosscheck"))
	if err != nil {
		return nil, false, err
	}
	if afterCorpusParsed != nil {
		if err := afterCorpusParsed(); err != nil {
			return nil, false, err
		}
	}
	// Preserve existing outputs before creating any raw-evidence directory.
	if _, err := os.Lstat(reportPath); err == nil {
		return nil, false, errors.New("report output already exists")
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	evidenceDir := strings.TrimSuffix(filepath.Base(reportPath), filepath.Ext(reportPath)) + "-evidence"
	if !offline.IsEntryName(evidenceDir) || len(evidenceDir) > 255 {
		nameHash := sha256.Sum256([]byte(filepath.Base(reportPath)))
		evidenceDir = "report-" + hex.EncodeToString(nameHash[:]) + "-evidence"
	}
	evidenceRoot := filepath.Join(filepath.Dir(reportPath), evidenceDir)
	if err := os.Mkdir(evidenceRoot, 0700); err != nil {
		return nil, false, err
	}
	loaded := map[string]*trust.Policy{}
	loadedKeys := map[string]map[string]bindings.ExportKey{}
	results := []Result{}
	evidenceRows := []map[string]string{}
	allMet := true
	counts := map[string]int{"met": 0, "not-met": 0, "unsupported": 0}
	verdicts := map[string]string{}
	canonicalDigests := map[string]string{}
	reports := map[string]*evidence.Report{}
	scopeMismatches := []string{}
	scopeChecks := 0
	verdictMismatches := []string{}
	secondaryMismatches := []string{}
	unsupported := map[string]int{}
	verdictChecks := 0
	for index, item := range corpus.Vectors {
		vector := vectors[item.ID]
		limit, err := vectorByteLimit(vector)
		if err != nil {
			return nil, false, err
		}
		data, artifactHash, _, err := readAndHash(root, vector.Path, limit+1)
		if err != nil {
			return nil, false, err
		}
		result := Result{ID: item.ID, Suite: item.Suite, ArtifactHash: artifactHash, Expected: vector.Expected, Secondary: []string{}}
		if !has(capabilities, item.Capability) {
			if !has(corpus.Optional, item.Capability) {
				return nil, false, fmt.Errorf("missing required capability: %s", item.Capability)
			}
			result.Status = "unsupported"
			result.Unsupported = item.Capability
			unsupported[item.Capability]++
		} else {
			context := &Context{Root: root, Semantics: semantic.Registered(), Verdicts: verdicts, Reports: reports, CanonicalDigests: canonicalDigests}
			if path := policies[item.ID]; path != "" {
				if loaded[path] == nil {
					if loaded[path], err = loadPolicyFile(root, path); err != nil {
						return nil, false, fmt.Errorf("%s: %w", path, err)
					}
				}
				context.TrustPolicy = loaded[path]
			}
			if path := keyFiles[item.ID]; path != "" {
				if loadedKeys[path] == nil {
					if loadedKeys[path], err = loadKeyFile(root, path); err != nil {
						return nil, false, fmt.Errorf("%s: %w", path, err)
					}
				}
				context.ExportKeys = loadedKeys[path]
			}
			observed, err := Evaluate(data, vector, context)
			if err != nil {
				return nil, false, fmt.Errorf("%s: %w", item.ID, err)
			}
			// A signed bundle's primary finding is its first identifier, in the order of EBMP2-068
			// (and, for an offline package, of IE1-022's checks before it), and a bundle has no
			// required secondary findings.
			selection := selectFindings
			if vector.Stage == "evidence-bundle" || vector.Stage == "package" {
				selection = selectBundleFinding
			}
			primary, secondary, err := selection(observed, precedence, errorCodes)
			if err != nil {
				return nil, false, fmt.Errorf("%s: %w", item.ID, err)
			}
			result.Secondary = secondary
			var primaryValue any
			if primary != "" {
				primaryValue = primary
			}
			result.Primary = &primaryValue
			recordObservations(&result, vector, verdicts[item.ID], reports[item.ID], canonicalDigests[item.ID])
			met := (vector.Expected == "pass" && primary == "" && len(secondary) == 0) || (vector.Expected == "fail" && primary == vector.Primary)
			if vector.CanonicalHash != "" && vector.Expected == "pass" && canonicalDigests[item.ID] != vector.CanonicalHash {
				met = false
			}
			result.Status = "met"
			if !met {
				result.Status = "not-met"
				allMet = false
			}
			if vector.Expected == "fail" {
				expected := append([]string{}, vector.Secondary...)
				sort.Strings(expected)
				if strings.Join(expected, " ") != strings.Join(secondary, " ") {
					secondaryMismatches = append(secondaryMismatches, item.ID)
				}
			}
			if vector.ExpectedVerdict != "" {
				verdictChecks++
				if verdicts[item.ID] != vector.ExpectedVerdict {
					verdictMismatches = append(verdictMismatches, item.ID)
					result.Status = "not-met"
					allMet = false
				}
			}
			// EBMP2-076 and EBMP2-061: a vector that names the scope, the evidence levels or the
			// unresolved predecessors of its verdict is met only with them.
			if vector.ExpectedScope != nil || vector.ExpectedEffects != nil || vector.ExpectedUnresolved != nil {
				scopeChecks++
				if !ReportMatches(reports[item.ID], vector.ExpectedScope, vector.ExpectedEffects, vector.ExpectedUnresolved) {
					scopeMismatches = append(scopeMismatches, item.ID)
					result.Status = "not-met"
					allMet = false
				}
			}
		}
		// Raw evidence binds every supported or unsupported result to this revision.
		raw := map[string]any{"schema_version": "ecl_external_vector_raw_result_v3", "implementation_revision": revision, "result": result}
		rawData, err := encode(raw)
		if err != nil {
			return nil, false, err
		}
		relative := fmt.Sprintf("%s/%04d.json", evidenceDir, index)
		if err := os.WriteFile(filepath.Join(filepath.Dir(reportPath), relative), append(rawData, '\n'), 0600); err != nil {
			return nil, false, err
		}
		// Evidence digest covers the exact bytes, including the trailing newline.
		result.RawHash = digest(append(rawData, '\n'))
		evidenceRows = append(evidenceRows, map[string]string{"path": relative, "sha256": result.RawHash})
		results = append(results, result)
		counts[result.Status]++
	}
	decision := "pass"
	if !allMet {
		decision = "fail"
	}
	limitations := []string{
		"ML-DSA-65 signatures are recognized and refused as unsupported: this Go verifier does not enable ML-DSA. No shared vector needs one.",
		Disclosure,
	}
	// The verification-time policy of each stage that a declared capability evaluates (IE1-023),
	// as conformance/README.md fixes them.
	evaluatedStages := map[string]bool{}
	for _, item := range corpus.Vectors {
		if has(capabilities, item.Capability) {
			evaluatedStages[vectors[item.ID].Stage] = true
		}
	}
	timePolicies := map[string]any{}
	if evaluatedStages["envelope"] {
		timePolicies["envelope"] = []string{"ecl.time.issued-at.v1", "ecl.time.observed-at.v1"}
	}
	if evaluatedStages["evidence-bundle"] {
		timePolicies["evidence-bundle"] = []string{"ecl.verification-profile.reference-trusted-time.v1", "ecl.verification-profile.reference.v1"}
	}
	if evaluatedStages["package"] {
		timePolicies["package"] = []string{"ecl.verification-profile.reference-trusted-time.v1", "ecl.verification-profile.reference.v1"}
	}
	report := map[string]any{"schema_version": "ecl_cross_implementation_report_v3", "candidate_version": "1.0", "profile_version": "3", "decision": decision,
		"implementation": map[string]any{"name": "ECL Go library", "version": evidence.SoftwareVersion, "source_repository": "go/crosscheck", "source_revision": revision, "source_tree_sha256": sourceHash, "language": "Go", "runtime": runtime.Version(), "maintainer": "Robert F. Tilley Jr.; G-14, Inc.", "relationship_disclosure": Disclosure, "imports_ecl_reference": false, "capabilities": capabilities},
		"suite":          map[string]any{"id": "ecl-1-v1.0-shared", "manifest_sha256": digest(corpusData), "vector_count": len(results), "corpus_version": corpus.Version}, "network_used": false, "time_policies": timePolicies, "vector_results": results, "evidence": evidenceRows,
		"limitations": limitations, "claim_boundary": "cross-implementation-corpus-replay"}
	encoded, err := encode(report)
	if err != nil {
		return nil, false, err
	}
	file, err := os.OpenFile(reportPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, false, err
	}
	_, err = file.Write(append(encoded, '\n'))
	closeErr := file.Close()
	if err != nil {
		return nil, false, err
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	unsupportedList := []string{}
	for capability := range unsupported {
		unsupportedList = append(unsupportedList, capability)
	}
	sort.Strings(unsupportedList)
	return map[string]any{
		"vector_count": len(results), "counts": counts, "decision": decision,
		"verdict_checks": verdictChecks, "verdict_mismatches": verdictMismatches,
		"scope_checks": scopeChecks, "scope_mismatches": scopeMismatches,
		"secondary_mismatches": secondaryMismatches, "unsupported_optional_capabilities": unsupportedList,
		"relationship_disclosure": Disclosure,
	}, allMet, nil
}
