package corpus

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

var runnerFoundation = []string{"strict-json", "canonical-digest", "semantic-rules", "safe-state-profile-rules"}

func runnerPut(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func runnerJSON(t *testing.T, root, relative string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	runnerPut(t, root, relative, data)
}
func runnerMiniature(t *testing.T) (string, map[string]any, map[string]any) {
	t.Helper()
	root := t.TempDir()
	runnerPut(t, root, "go/crosscheck/control.txt", []byte("bounded source fixture\n"))
	for _, name := range []string{"semantic-rules", "error-codes"} {
		data, err := os.ReadFile(filepath.Join(context().Root, "registries", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		runnerPut(t, root, "registries/"+name+".json", data)
	}
	vectors := []any{}
	cases := []any{}
	for _, id := range []string{"a", "b"} {
		vectors = append(vectors, map[string]any{"id": id, "path": "conformance/" + id + ".json", "stage": "semantic", "schema": "https://externalcontrollayer.ai/ns/schema/common/1", "expected": "pass", "expected_secondary_ids": []string{}})
		cases = append(cases, map[string]any{"id": id, "suite": "bounded-fixture", "capability": "semantic-rules"})
		runnerPut(t, root, "conformance/"+id+".json", []byte(`{}`))
	}
	optional := []string{}
	for _, name := range Capabilities {
		if !has(runnerFoundation, name) {
			optional = append(optional, name)
		}
	}
	index := map[string]any{"schema_version": "ecl_shared_corpus_v1", "version": 1, "candidate_version": "1.0", "required_capabilities": append([]string{}, runnerFoundation...), "optional_capabilities": optional, "vectors": cases}
	manifest := map[string]any{"schema_version": "ecl_conformance_vector_manifest_v3", "suite": "bounded-fixture", "vectors": vectors}
	return root, index, manifest
}
func runnerWrite(t *testing.T, root string, index, manifest map[string]any) {
	t.Helper()
	runnerJSON(t, root, "conformance/shared-corpus.json", index)
	runnerJSON(t, root, "conformance/manifest.json", manifest)
}

func TestRunnerDeclaredDepthIsAppliedOnce(t *testing.T) {
	for _, stage := range []string{"protocol", "semantic"} {
		for _, depth := range []int{20, 270} {
			for _, broken := range []bool{false, true} {
				t.Run(stage+"/depth="+strconv.Itoa(depth)+"/broken="+map[bool]string{false: "no", true: "yes"}[broken], func(t *testing.T) {
					data, err := os.ReadFile(filepath.Join(context().Root, "conformance/vectors/dcmp-2/valid-decision-request.json"))
					if err != nil {
						t.Fatal(err)
					}
					var value map[string]any
					decoder := json.NewDecoder(bytes.NewReader(data))
					decoder.UseNumber()
					if err = decoder.Decode(&value); err != nil {
						t.Fatal(err)
					}
					var nested any = json.Number("1")
					for i := 0; i < depth; i++ {
						nested = []any{nested}
					}
					value["extensions"] = []any{map[string]any{"id": "urn:example:deep", "version": 1, "critical": broken, "value": map[string]any{"nested": nested}}}
					data, err = json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					vector := Vector{Stage: stage, Schema: dcmpSchema, StrictJSONLimits: &StrictJSONLimits{MaxBytes: len(data), MaxDepth: 512, MaxNodes: 10000}}
					found, err := Evaluate(data, vector, context())
					want := []string{}
					if broken {
						want = []string{"ecl.rule.unknown-critical-extension-rejected.v1"}
					}
					if err != nil || !reflect.DeepEqual(found, want) {
						t.Fatalf("found %v err %v; want %v", found, err, want)
					}
					vector.StrictJSONLimits.MaxDepth = 10
					found, err = Evaluate(data, vector, context())
					if err != nil || !reflect.DeepEqual(found, []string{strict.ResourceLimitExceeded}) {
						t.Fatalf("restrictive declared depth: %v %v", found, err)
					}
				})
			}
		}
	}
}

func TestRunnerCapabilityMetadataPreflight(t *testing.T) {
	for _, mode := range []string{"null-required", "duplicate-required", "missing-required", "extra-required", "null-optional", "duplicate-optional", "overlap", "unknown-optional", "missing-bundle-implication", "missing-basis-implication", "null-vectors", "duplicate-suite", "duplicate-corpus-id", "wrong-suite", "undeclared-vector-capability"} {
		t.Run(mode, func(t *testing.T) {
			root, index, manifest := runnerMiniature(t)
			optional := index["optional_capabilities"].([]string)
			vectors := index["vectors"].([]any)
			switch mode {
			case "null-required":
				index["required_capabilities"] = nil
			case "duplicate-required":
				index["required_capabilities"] = append(append([]string{}, runnerFoundation...), "strict-json")
			case "missing-required":
				index["required_capabilities"] = runnerFoundation[:3]
			case "extra-required":
				index["required_capabilities"] = append(append([]string{}, runnerFoundation...), "schema-validation")
				index["optional_capabilities"] = optional[1:]
			case "null-optional":
				index["optional_capabilities"] = nil
			case "duplicate-optional":
				index["optional_capabilities"] = append(optional, "schema-validation")
			case "overlap":
				index["optional_capabilities"] = append(optional, "semantic-rules")
			case "unknown-optional":
				index["optional_capabilities"] = append(optional, "not-registered")
				vectors[0].(map[string]any)["capability"] = "not-registered"
			case "missing-bundle-implication", "missing-basis-implication":
				drop := "evidence-bundle-verification"
				if mode == "missing-basis-implication" {
					drop = "decision-basis-rule"
				}
				filtered := []string{}
				for _, name := range optional {
					if name != drop {
						filtered = append(filtered, name)
					}
				}
				index["optional_capabilities"] = filtered
			case "null-vectors":
				index["vectors"] = nil
				manifest["vectors"] = []any{}
			case "duplicate-suite":
				extra := map[string]any{"schema_version": "ecl_conformance_vector_manifest_v3", "suite": "bounded-fixture", "vectors": []any{manifest["vectors"].([]any)[1]}}
				manifest["vectors"] = manifest["vectors"].([]any)[:1]
				runnerJSON(t, root, "conformance/suites/extra/manifest.json", extra)
			case "duplicate-corpus-id":
				vectors[1] = vectors[0]
			case "wrong-suite":
				vectors[0].(map[string]any)["suite"] = "wrong"
			case "undeclared-vector-capability":
				vectors[0].(map[string]any)["capability"] = "unregistered"
			}
			runnerWrite(t, root, index, manifest)
			report := filepath.Join(root, "report.json")
			_, _, err := Run(root, strings.Repeat("a", 40), report)
			if err == nil {
				t.Error("invalid corpus metadata accepted")
			}
			if _, err = os.Stat(filepath.Join(root, "report-evidence")); !os.IsNotExist(err) {
				t.Error("evidence emitted before metadata refusal")
			}
		})
	}
}

func TestRunnerFoundationOnlyReport(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	index["optional_capabilities"] = []string{}
	runnerWrite(t, root, index, manifest)
	path := filepath.Join(root, "report.json")
	_, met, err := Run(root, strings.Repeat("a", 40), path)
	if err != nil || !met {
		t.Fatalf("%v %v", met, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Implementation struct {
			Capabilities []string `json:"capabilities"`
		} `json:"implementation"`
	}
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Implementation.Capabilities, runnerFoundation) {
		t.Fatalf("capabilities %v, want %v", report.Implementation.Capabilities, runnerFoundation)
	}
}

func TestRunnerSourceHashRejectsEmpty(t *testing.T) {
	if hash, err := SourceHash(t.TempDir()); err == nil {
		t.Fatalf("empty source accepted: %s", hash)
	}
}
func TestRunnerSourceHashUTF8Separators(t *testing.T) {
	root := t.TempDir()
	name := "a\u2028b\u2029.txt"
	runnerPut(t, root, name, []byte("x"))
	hash, err := SourceHash(root)
	if err != nil {
		t.Fatal(err)
	}
	want := digest([]byte(`[{"path":"` + name + `","sha256":"` + digest([]byte("x")) + `","size_bytes":1}]`))
	if hash != want {
		t.Fatalf("source hash %s, want %s", hash, want)
	}
}
func TestRunnerEncodePreservesLiteralEscapeText(t *testing.T) {
	value := map[string]any{"raw": "\u2028\u2029", "literal": `\u2028\u2029`}
	data, err := encode(value)
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]string
	if err = json.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}
	if actual["raw"] != "\u2028\u2029" || actual["literal"] != `\u2028\u2029` {
		t.Fatalf("changed value %s", data)
	}
	if !bytes.Contains(data, []byte("\u2028\u2029")) {
		t.Fatalf("raw Unicode separator escaped: %s", data)
	}
}

func TestRunnerReadBoundaryIsAResult(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	index["optional_capabilities"] = []string{}
	index["vectors"] = []any{map[string]any{"id": "limit", "suite": "bounded-fixture", "capability": "strict-json"}}
	manifest["vectors"] = []any{map[string]any{"id": "limit", "path": "conformance/large.json", "stage": "strict-json", "strict_json_limits": map[string]any{"max_bytes": 16 * 1024 * 1024, "max_depth": 256, "max_nodes": 1000000}, "expected": "fail", "expected_primary_id": strict.ResourceLimitExceeded, "expected_secondary_ids": []string{}}}
	runnerWrite(t, root, index, manifest)
	f, err := os.Create(filepath.Join(root, "conformance/large.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(16*1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	_, met, err := Run(root, strings.Repeat("a", 40), filepath.Join(root, "report.json"))
	if err != nil || !met {
		t.Fatalf("resource refusal must be a classified result: met=%v err=%v", met, err)
	}
}

func TestRunnerNullRequiredWithOptionalVectors(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	index["required_capabilities"] = nil
	for _, row := range index["vectors"].([]any) {
		row.(map[string]any)["capability"] = "schema-validation"
	}
	runnerWrite(t, root, index, manifest)
	if _, _, err := Run(root, strings.Repeat("a", 40), filepath.Join(root, "report.json")); err == nil {
		t.Fatal("null required list accepted when no vector needs a required capability")
	}
}

func TestRunnerLargerDeclaredByteWindow(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	index["optional_capabilities"] = []string{}
	index["vectors"] = []any{map[string]any{"id": "larger", "suite": "bounded-fixture", "capability": "strict-json"}}
	limit := 16*1024*1024 + 2
	manifest["vectors"] = []any{map[string]any{"id": "larger", "path": "conformance/larger.json", "stage": "strict-json", "strict_json_limits": map[string]any{"max_bytes": limit, "max_depth": 256, "max_nodes": 1000000}, "expected": "pass", "expected_secondary_ids": []string{}}}
	runnerWrite(t, root, index, manifest)
	f, err := os.Create(filepath.Join(root, "conformance/larger.json"))
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte(" "), 1024)
	for i := 0; i < 16*1024; i++ {
		if _, err = f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = f.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	_, met, err := Run(root, strings.Repeat("a", 40), filepath.Join(root, "report.json"))
	if err != nil || !met {
		t.Fatalf("declared larger window: met=%v err=%v", met, err)
	}
}

func TestRunnerSourceHashLargerRegularFile(t *testing.T) {
	root := t.TempDir()
	f, err := os.Create(filepath.Join(root, "source.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(16*1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = SourceHash(root); err != nil {
		t.Fatalf("regular source within report budget: %v", err)
	}
}

func TestRunnerBindsInitiallyParsedCorpus(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	index["optional_capabilities"] = []string{}
	rows := []any{}
	vectors := []any{}
	for i := 0; i < 64; i++ {
		id := "row-" + strconv.Itoa(i)
		rows = append(rows, map[string]any{"id": id, "suite": "bounded-fixture", "capability": "semantic-rules"})
		vectors = append(vectors, map[string]any{"id": id, "path": "conformance/a.json", "stage": "semantic", "schema": "https://externalcontrollayer.ai/ns/schema/common/1", "expected": "pass", "expected_secondary_ids": []string{}})
	}
	index["vectors"] = rows
	manifest["vectors"] = vectors
	runnerWrite(t, root, index, manifest)
	initial, err := os.ReadFile(filepath.Join(root, "conformance/shared-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := 0
	_, met, runErr := run(root, strings.Repeat("a", 40), filepath.Join(root, "report.json"), func() error {
		mutations++
		return os.WriteFile(filepath.Join(root, "conformance/shared-corpus.json"), append(initial, '\n'), 0600)
	})
	if mutations != 1 {
		t.Fatalf("parsed-corpus checkpoint calls: got %d, want 1", mutations)
	}
	if runErr != nil || !met {
		t.Fatalf("run: %v %v", met, runErr)
	}
	data, err := os.ReadFile(filepath.Join(root, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Suite struct {
			Hash string `json:"manifest_sha256"`
		} `json:"suite"`
	}
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Suite.Hash != digest(initial) {
		t.Fatalf("report bound reread corpus %s; initial parsed bytes %s", report.Suite.Hash, digest(initial))
	}
}

func TestRunnerMalformedEvidenceBundleRecordsInvalidVerdict(t *testing.T) {
	for _, tc := range []struct {
		name, data, rule string
		limit            *StrictJSONLimits
	}{
		{"syntax", "[", strict.RuleStrictSyntax, nil},
		{"duplicates", `{"a":1,"a":2}`, strict.RuleNoDuplicateMembers, nil},
		{"restricted", `{"n":1.5}`, strict.RuleRestrictedNumbers, nil},
		{"resource", "{}", strict.ResourceLimitExceeded, &StrictJSONLimits{MaxBytes: 1, MaxDepth: 1, MaxNodes: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context()
			found, err := Evaluate([]byte(tc.data), Vector{ID: tc.name, Stage: "evidence-bundle", StrictJSONLimits: tc.limit, TrustPolicyPath: "must-not-be-read"}, ctx)
			if err != nil || !reflect.DeepEqual(found, []string{tc.rule}) {
				t.Fatalf("%v %v", found, err)
			}
			if ctx.Verdicts[tc.name] != "invalid" {
				t.Fatalf("verdict %q, want invalid", ctx.Verdicts[tc.name])
			}
			if len(ctx.Reports) != 0 {
				t.Fatal("parse failure invented scope report")
			}
		})
	}
}

func TestRunnerBoundedPrefixAndExactDigest(t *testing.T) {
	root := t.TempDir()
	data := bytes.Repeat([]byte("x"), 4096)
	runnerPut(t, root, "value", data)
	prefix, hash, size, err := readAndHash(root, "value", 5)
	if err != nil || !bytes.Equal(prefix, data[:5]) || hash != digest(data) || size != int64(len(data)) {
		t.Fatalf("prefix=%d hash=%s size=%d err=%v", len(prefix), hash, size, err)
	}
	prefix, err = readPrefix(root, "value", 4)
	if err != nil || len(prefix) != 5 {
		t.Fatalf("prefix %d %v", len(prefix), err)
	}
}

func TestRunnerReportingCeilingBeforeAllocation(t *testing.T) {
	root := t.TempDir()
	f, err := os.Create(filepath.Join(root, "large"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxBoundFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = readAndHash(root, "large", 1); err == nil || !strings.Contains(err.Error(), "report byte budget") {
		t.Fatalf("over-budget sparse file: %v", err)
	}
}

func TestRunnerStageLimits(t *testing.T) {
	for _, tc := range []struct {
		v    Vector
		want int64
	}{{Vector{Stage: "package"}, 1073741824}, {Vector{Stage: "trust-policy"}, 262144}, {Vector{Stage: "protocol"}, 16777216}, {Vector{Stage: "semantic", StrictJSONLimits: &StrictJSONLimits{MaxBytes: 23, MaxDepth: 3, MaxNodes: 9}}, 23}} {
		got, err := vectorByteLimit(tc.v)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %d %v", tc.v.Stage, got, err)
		}
	}
	for _, limits := range []StrictJSONLimits{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}, {1, 4097, 1}} {
		_, err := vectorByteLimit(Vector{Stage: "semantic", StrictJSONLimits: &limits})
		if err == nil {
			t.Fatalf("invalid limits accepted: %+v", limits)
		}
	}
}

func TestRunnerRecognizedUnsupportedOptional(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	index["optional_capabilities"] = []string{"schema-validation"}
	index["vectors"].([]any)[0].(map[string]any)["capability"] = "schema-validation"
	runnerWrite(t, root, index, manifest)
	original := Capabilities
	Capabilities = append([]string{}, runnerFoundation...)
	t.Cleanup(func() { Capabilities = original })
	path := filepath.Join(root, "report.json")
	_, met, err := Run(root, strings.Repeat("a", 40), path)
	if err != nil || !met {
		t.Fatalf("optional unsupported should remain reportable: %v %v", met, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Results []Result `json:"vector_results"`
	}
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 2 || report.Results[0].Status != "unsupported" || report.Results[0].Unsupported != "schema-validation" || report.Results[1].Status != "met" {
		t.Fatalf("%+v", report.Results)
	}
}

func TestRunnerParseValidInvalidBundleHasObservedVerdict(t *testing.T) {
	var manifest Manifest
	if err := decode(context().Root, "conformance/suites/evidence-bundle/manifest.json", &manifest); err != nil {
		t.Fatal(err)
	}
	v := manifest.Vectors[0]
	v.ID = "invalid-shape"
	v.Stage = "evidence-bundle"
	ctx := context()
	found, err := Evaluate([]byte(`[]`), v, ctx)
	if err != nil || !has(found, schemaInvalid) || ctx.Verdicts[v.ID] != "invalid" {
		t.Fatalf("%v %v %v", found, ctx.Verdicts, err)
	}
}

func TestRunnerAllowedSecondaryReportingDifference(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	index["optional_capabilities"] = []string{}
	v := manifest["vectors"].([]any)[1].(map[string]any)
	v["expected"] = "fail"
	v["expected_primary_id"] = "ecl.rule.non-admit-prohibits-authority.v1"
	runnerJSON(t, root, "conformance/b.json", map[string]any{"protocol": "DCMP-2", "message_type": "decision_response", "outcome": "deny", "authorization": map[string]any{}})
	v["expected_secondary_ids"] = []string{"ecl.rule.unknown-critical-extension-rejected.v1"}
	runnerWrite(t, root, index, manifest)
	summary, met, err := Run(root, strings.Repeat("a", 40), filepath.Join(root, "report.json"))
	if err != nil || !met {
		t.Fatalf("external profile compares primary agreement: %v %v %+v", met, err, summary)
	}
	if !reflect.DeepEqual(summary["secondary_mismatches"], []string{"b"}) {
		t.Fatalf("difference not recorded: %+v", summary)
	}
}

func TestRunnerPackageBeyondJSONReadBudget(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	var actual Manifest
	if err := decode(context().Root, "conformance/suites/offline-package/manifest.json", &actual); err != nil {
		t.Fatal(err)
	}
	v := actual.Vectors[0]
	v.ID = "large-package"
	v.Path = "conformance/package.zip"
	v.Stage = "package"
	v.Expected = "fail"
	v.Primary = "ecl.error.semantic-invalid.v1"
	v.Secondary = []string{}
	v.ExpectedVerdict = "invalid"
	v.ExpectedScope = nil
	v.ExpectedEffects = nil
	v.ExpectedUnresolved = nil
	for _, relative := range append(append([]string{v.TrustPolicyPath}, v.TrustPolicyHistory...), v.RegisterPath) {
		if relative == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(context().Root, relative))
		if err != nil {
			t.Fatal(err)
		}
		runnerPut(t, root, relative, data)
	}
	index["vectors"] = []any{map[string]any{"id": v.ID, "suite": "bounded-fixture", "capability": "offline-package-verification"}}
	manifest["vectors"] = []Vector{v}
	runnerWrite(t, root, index, manifest)
	f, err := os.Create(filepath.Join(root, v.Path))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(16*1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	_, met, err := Run(root, strings.Repeat("a", 40), filepath.Join(root, "report.json"))
	if err != nil || !met {
		t.Fatalf("package dispatch within report limit: met=%v err=%v", met, err)
	}
}

func TestRunnerPortableReportNames(t *testing.T) {
	for _, name := range []string{"report with spaces.json", "résultat.json", "CON.json", strings.Repeat("a", 250) + ".json"} {
		t.Run(name, func(t *testing.T) {
			root, index, manifest := runnerMiniature(t)
			runnerWrite(t, root, index, manifest)
			report := filepath.Join(t.TempDir(), name)
			if _, met, err := Run(root, strings.Repeat("a", 40), report); err != nil || !met {
				t.Fatalf("report failed: %v", err)
			}
			data, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var value struct {
				Evidence []struct {
					Path string `json:"path"`
				} `json:"evidence"`
			}
			if err = json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			for _, entry := range value.Evidence {
				for _, r := range entry.Path {
					if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./-", r)) {
						t.Fatalf("nonportable evidence path: %q", entry.Path)
					}
				}
				if _, err = os.Stat(filepath.Join(filepath.Dir(report), filepath.FromSlash(entry.Path))); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestRunnerExistingReportCreatesNoEvidence(t *testing.T) {
	root, index, manifest := runnerMiniature(t)
	runnerWrite(t, root, index, manifest)
	output := t.TempDir()
	report := filepath.Join(output, "report.json")
	if err := os.WriteFile(report, []byte("preserve original"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Run(root, strings.Repeat("a", 40), report); err == nil {
		t.Fatal("existing report accepted")
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("failed report left artifacts: %v", entries)
	}
	data, err := os.ReadFile(report)
	if err != nil || string(data) != "preserve original" {
		t.Fatal("report changed")
	}
}
