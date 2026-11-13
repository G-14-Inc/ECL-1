package schema_test

import (
	"encoding/json"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
)

func TestPublicReviewROOT026AuthorityBrackets(t *testing.T) {
	for _, uri := range []string{"https://user[info]@[::1]/profile", "https://[v1.[a]/profile", "https://[::1]:[80]/profile"} {
		if schema.IsURI(uri) {
			t.Fatalf("accepted %q", uri)
		}
	}
	for _, uri := range []string{"https://[::1]/profile", "https://user:info@[::1]:80/profile", "https://[v1.a]/profile", "https://[fe80::1%25eth0]/profile"} {
		if !schema.IsURI(uri) {
			t.Fatalf("refused %q", uri)
		}
	}
}

func TestPublicReviewROOT070CalendarBounds(t *testing.T) {
	for _, value := range []string{"2026-10-00T00:00:00Z", "2026-01-00T00:00:00Z", "2025-02-29T00:00:00Z", "2026-04-31T00:00:00Z"} {
		if schema.IsDateTime(value) {
			t.Fatal(value)
		}
		if _, err := instant.Parse(value); err == nil {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"2026-09-30T00:00:00Z", "2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z"} {
		if !schema.IsDateTime(value) {
			t.Fatal(value)
		}
	}
	a, err := instant.Parse("2026-01-01T00:00:00.000000001Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := instant.Parse("2026-01-01T00:00:00.000000002Z")
	if err != nil || instant.Compare(a, b) != -1 || b.Nanos-a.Nanos != 1 {
		t.Fatalf("%v %v %v", a, b, err)
	}
}

func TestPublicReviewROOT074IncidentWhitespace(t *testing.T) {
	var incident map[string]any
	if err := json.Unmarshal(vectors.Read(t, "schemas/ecl-incident-scenario-v1.schema.json"), &incident); err != nil {
		t.Fatal(err)
	}
	uri := incident["$defs"].(map[string]any)["uri"]
	set, err := schema.NewSet(map[string]any{"urn:example:incident-uri": uri})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		char  string
		valid bool
	}{{"x", true}, {" ", false}, {"\u0085", true}, {"\u00a0", false}, {"\u2028", false}, {"\ufeff", false}} {
		valid, err := set.Valid("urn:example:incident-uri", "urn:example:"+row.char)
		if err != nil || valid != row.valid {
			t.Fatalf("%q: %v %v", row.char, valid, err)
		}
	}
}
