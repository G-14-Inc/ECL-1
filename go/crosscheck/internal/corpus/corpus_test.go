package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validator"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

const dcmpSchema = "https://externalcontrollayer.ai/ns/schema/dcmp/2"

func context() *Context {
	return &Context{Root: filepath.Join("..", "..", "..", ".."), Semantics: semantic.Registered(), Verdicts: map[string]string{}}
}

func TestExpectedClassDoesNotEnterValidator(t *testing.T) {
	data, readErr := os.ReadFile(filepath.Join("..", "..", "..", "..", "conformance/vectors/dcmp-2/invalid-admit-reversed-authority-window.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	vector := Vector{Stage: "protocol", Schema: dcmpSchema, Expected: "pass", Primary: "invented"}
	first, err := Evaluate(data, vector, context())
	if err != nil {
		t.Fatal(err)
	}
	vector.Expected = "fail"
	vector.Primary = "other"
	second, err := Evaluate(data, vector, context())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || strings.Join(first, " ") != strings.Join(second, " ") {
		t.Fatalf("expectation affected evaluator: %v/%v", first, second)
	}
}
func TestMissingRequiredCapabilityFailsBeforeReport(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "conformance"), 0700); err != nil {
		t.Fatal(err)
	}
	doc := `{"schema_version":"ecl_shared_corpus_v1","version":1,"candidate_version":"1.0","required_capabilities":["missing"],"optional_capabilities":[],"vectors":[]}`
	if err := os.WriteFile(filepath.Join(root, "conformance/shared-corpus.json"), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(root, "report.json")
	_, _, err := Run(root, strings.Repeat("a", 40), report)
	if err == nil || !strings.Contains(err.Error(), "missing required capability: missing") {
		t.Fatal(err)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatal("report created after missing capability")
	}
}
func TestArtifactPathEscapeAndSymlinkFail(t *testing.T) {
	root := t.TempDir()
	if _, err := read(root, "../escape"); err == nil {
		t.Fatal("path escape accepted")
	}
	outside := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(outside, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := read(root, "link"); err == nil {
		t.Fatal("symlink accepted")
	}
}

// The RC-4 divergence (ebmp-valid-bundle-manifest): an EBMP-2 bundle manifest has a records
// member of references, and is classified by its protocol, not read as a bare bundle. A bare
// bundle is still checked as one.
func TestBundleManifestIsClassifiedByProtocol(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	manifest, err := os.ReadFile(filepath.Join(root, "conformance/suites/schema-coverage/ebmp-valid-bundle-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Evaluate(manifest, Vector{Stage: "protocol", Schema: "https://externalcontrollayer.ai/ns/schema/ebmp/2"}, context())
	if err != nil || len(findings) != 0 {
		t.Fatalf("bundle manifest: %v %v", findings, err)
	}
	bundle, err := os.ReadFile(filepath.Join(root, "conformance/vectors/bundles/invalid-duplicate-object-id.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The analysis reports every rule the records break, as the reference does: the repeated
	// terminal is also a transition from a terminal state.
	findings, err = Evaluate(bundle, Vector{Stage: "bundle"}, context())
	if err != nil || len(findings) != 2 || findings[0] != validator.RuleBundleObjectUnique || findings[1] != validator.RuleExecutionTransition {
		t.Fatalf("bare bundle: %v %v", findings, err)
	}
}

// Every capability of the shared corpus is one this module implements, offline package
// verification included, so no vector is reported unsupported and none is pending.
func TestEveryCorpusCapabilityIsImplemented(t *testing.T) {
	var corpus Corpus
	if err := decode(context().Root, "conformance/shared-corpus.json", &corpus); err != nil {
		t.Fatal(err)
	}
	for _, capability := range append(append([]string{}, corpus.Required...), corpus.Optional...) {
		if !has(Capabilities, capability) {
			t.Errorf("%s is not implemented", capability)
		}
	}
}

// The package stage reads an archive as bytes and gives each package vector its verdict and
// primary finding.
func TestPackageStage(t *testing.T) {
	root := context().Root
	var manifest Manifest
	if err := decode(root, "conformance/suites/offline-package/manifest.json", &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Vectors) < 15 {
		t.Fatalf("%d package vectors", len(manifest.Vectors))
	}
	for _, vector := range manifest.Vectors {
		data, err := read(root, vector.Path)
		if err != nil {
			t.Fatal(err)
		}
		local := context()
		found, err := Evaluate(data, vector, local)
		if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		if local.Verdicts[vector.ID] != vector.ExpectedVerdict {
			t.Errorf("%s: verdict %s, want %s", vector.ID, local.Verdicts[vector.ID], vector.ExpectedVerdict)
		}
		if (vector.Expected == "pass" && len(found) != 0) || (vector.Expected == "fail" && !has(found, vector.Primary)) {
			t.Errorf("%s: %v, want %q", vector.ID, found, vector.Primary)
		}
	}
}

// The binding stage applies the record schema and then the profile's rules; the document stage
// applies the schema the vector names.
func TestBindingAndDocumentStages(t *testing.T) {
	root := context().Root
	cases := []struct {
		path, stage, schema, want string
	}{
		{"conformance/suites/mcp-gateway/mcp-invalid-forwarded-when-unavailable.json", "binding", "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1", "ecl.rule.mcp-decision-failure-not-forwarded.v1"},
		{"conformance/suites/document-coverage/assessment-invalid-artifact-role-outside-enum.json", "document", "https://externalcontrollayer.ai/ns/schema/assessment-package/1", schemaInvalid},
		{"conformance/suites/document-coverage/assessment-valid-l1-class-a.json", "document", "https://externalcontrollayer.ai/ns/schema/assessment-package/1", ""},
	}
	for _, item := range cases {
		data, err := read(root, item.path)
		if err != nil {
			t.Fatal(err)
		}
		found, err := Evaluate(data, Vector{Stage: item.stage, Schema: item.schema}, context())
		if err != nil {
			t.Fatalf("%s: %v", item.path, err)
		}
		if (item.want == "" && len(found) != 0) || (item.want != "" && !has(found, item.want)) {
			t.Errorf("%s: %v, want %q", item.path, found, item.want)
		}
	}
	if _, err := Evaluate([]byte(`{}`), Vector{Stage: "binding", Schema: "https://externalcontrollayer.ai/ns/schema/unknown/1"}, context()); err == nil {
		t.Fatal("an unknown record schema was accepted")
	}
}
