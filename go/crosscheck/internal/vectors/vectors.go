// Package vectors reads the repository's shared conformance vectors for the module's tests.
package vectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

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
	// AcceptCurrentTrustFailure verifies with the caller's acceptance of current trust failures.
	AcceptCurrentTrustFailure bool `json:"accept_current_trust_failure"`
	// ExpectedScope, ExpectedEffects and ExpectedUnresolved are the scope, evidence levels and
	// unresolved predecessors that the report must give, when the vector names them.
	ExpectedScope *struct {
		Established    []string          `json:"established"`
		NotEstablished []string          `json:"not_established"`
		Reasons        map[string]string `json:"reasons"`
	} `json:"expected_scope"`
	ExpectedEffects []struct {
		ActionID string `json:"action_id"`
		Level    string `json:"level"`
	} `json:"expected_effects"`
	ExpectedUnresolved *[]string `json:"expected_unresolved_predecessor_ids"`
	// StrictJSONLimits are the declared limits under which a strict-json vector is read
	// (IE1-028); without them the library's own apply.
	StrictJSONLimits *struct {
		MaxBytes int `json:"max_bytes"`
		MaxDepth int `json:"max_depth"`
		MaxNodes int `json:"max_nodes"`
	} `json:"strict_json_limits"`
}

// Manifest is a suite manifest.
type Manifest struct {
	Suite           string   `json:"suite"`
	TrustPolicyPath string   `json:"trust_policy_path"`
	ExportKeysPath  string   `json:"export_keys_path"`
	Vectors         []Vector `json:"vectors"`
}

// Root returns the repository root: four directories above this file.
func Root() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "..", "..")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

// ReadFile returns the bytes of a repository file.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(Root(), filepath.FromSlash(path)))
}

// Read returns the bytes of a repository file, failing the test when it cannot.
func Read(t testing.TB, path string) []byte {
	t.Helper()
	data, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Suite returns the manifest of conformance/suites/<name>, or of conformance/manifest.json for
// the name "foundation".
func Suite(t testing.TB, name string) Manifest {
	t.Helper()
	path := "conformance/suites/" + name + "/manifest.json"
	if name == "foundation" {
		path = "conformance/manifest.json"
	}
	var manifest Manifest
	if err := json.Unmarshal(Read(t, path), &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

// Capabilities returns the capability that the shared corpus assigns to each vector, by vector
// identifier.
func Capabilities(t testing.TB) map[string]string {
	t.Helper()
	var corpus struct {
		Vectors []struct {
			ID         string `json:"id"`
			Capability string `json:"capability"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(Read(t, "conformance/shared-corpus.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, row := range corpus.Vectors {
		result[row.ID] = row.Capability
	}
	return result
}
