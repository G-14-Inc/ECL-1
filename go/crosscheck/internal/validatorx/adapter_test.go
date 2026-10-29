package validatorx

import (
	"encoding/json"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/canonical"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	parser "externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// binding reads the shared valid adapter binding.
func binding(t *testing.T) map[string]any {
	t.Helper()
	value, err := parser.Parse(vectors.Read(t, "conformance/vectors/adapters/valid-native-binding.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

// rebind recomputes the body digest, so that an edit is the binding's only defect.
func rebind(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{}
	for key, value := range root {
		if key != "binding_digest" {
			body[key] = value
		}
	}
	digest, err := canonical.Digest(body)
	if err != nil {
		t.Fatal(err)
	}
	root["binding_digest"] = map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": digest}
	return root
}

func paths(t *testing.T, root map[string]any) []string {
	t.Helper()
	found := []string{}
	for _, finding := range AdapterBinding(root) {
		found = append(found, finding.Path)
	}
	return found
}

func TestAdapterBindingConditions(t *testing.T) {
	if found := paths(t, binding(t)); len(found) != 0 {
		t.Fatalf("valid binding: %v", found)
	}
	objects := func(root map[string]any) []any { return root["ecl_objects"].([]any) }
	cases := []struct {
		name string
		edit func(map[string]any)
		want []string
	}{
		{"body digest", func(root map[string]any) {
			root["binding_digest"] = map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": "00"}
		}, []string{"/binding_digest"}},
		{"identity", func(root map[string]any) {
			root["binding_id"] = "https://externalcontrollayer.ai/ns/adapter-binding/sha256/00"
			rebind(t, root)
		}, []string{"/binding_id"}},
		{"media type", func(root map[string]any) {
			objects(root)[0].(map[string]any)["media_type"] = "application/vnd.ecl.ebmp+json"
			rebind(t, root)
		}, []string{"/ecl_objects/0/media_type"}},
		{"loss class", func(root map[string]any) {
			root["loss_class"] = "loss_accounted"
			rebind(t, root)
		}, []string{"/loss_class"}},
		{"target index", func(root map[string]any) {
			root["derived_fields"].([]any)[0].(map[string]any)["target_path"] = "/01/message_id"
			rebind(t, root)
		}, []string{"/derived_fields/0"}},
		{"coverage of an unlisted responsibility", func(root map[string]any) {
			authority := root["responsibility_coverage"].(map[string]any)["Authority"].(map[string]any)
			authority["object_ids"] = []any{objects(root)[0].(map[string]any)["object_id"]}
			rebind(t, root)
		}, []string{"/responsibility_coverage/Authority"}},
		{"authority boundary", func(root map[string]any) {
			root["authority_boundary"].(map[string]any)["conflict_disposition"] = "release"
			rebind(t, root)
		}, []string{"/authority_boundary"}},
		// The number 1 is not the JSON value true that the boundary holds.
		{"authority boundary member that is a number", func(root map[string]any) {
			root["authority_boundary"].(map[string]any)["native_authoritative_for_effects"] = json.Number("1")
			rebind(t, root)
		}, []string{"/authority_boundary"}},
		// DCMP2-043: a member one condition cannot read leaves the other conditions checked.
		{"mistyped loss class", func(root map[string]any) {
			root["loss_class"] = json.Number("1")
			objects(root)[0].(map[string]any)["media_type"] = "application/json"
			rebind(t, root)
		}, []string{"/ecl_objects/0/media_type"}},
	}
	for _, item := range cases {
		root := binding(t)
		item.edit(root)
		found := paths(t, root)
		if len(found) != len(item.want) {
			t.Fatalf("%s: %v", item.name, found)
		}
		for index := range found {
			if found[index] != item.want[index] {
				t.Fatalf("%s: %v", item.name, found)
			}
		}
	}
}
