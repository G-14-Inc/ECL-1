// Package registry reads the registry entries embedded in this module (internal/generated),
// which scripts/generate_sdk_sources.py copies from the repository's registries/ directory.
package registry

import (
	"fmt"
	"sync"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/generated"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/strictjson"
)

// Entry is one registry entry with the attributes that the library reads.
type Entry struct {
	ID         string
	Status     string
	Precedence int64
	// Stage is the stage of EBMP2-068 that a bundle rule names, 0 for none.
	Stage       int64
	Version     int64
	ValueSchema string
	// ComposableVersions is true only when an extension's entry sets composable_versions to true:
	// one object may then carry two versions of it (XR1-010).
	ComposableVersions bool
	// AppliesTo names the object types that a semantic rule applies to.
	AppliesTo   []string
	Category    string
	Kind        string
	Description string
}

var (
	once    sync.Once
	entries map[string][]Entry
)

func load() {
	value, err := strictjson.Parse(generated.Registries)
	if err != nil {
		panic(fmt.Sprintf("embedded registries: %v", err))
	}
	document, _ := pyjson.Object(value)
	entries = map[string][]Entry{}
	for name, list := range document {
		rows, _ := pyjson.Array(list)
		for _, item := range rows {
			row, _ := pyjson.Object(item)
			entry := Entry{}
			entry.ID, _ = pyjson.Text(row["id"])
			entry.Status, _ = pyjson.Text(row["status"])
			entry.Precedence, _ = pyjson.Int(row["precedence"])
			entry.Stage, _ = pyjson.Int(row["stage"])
			entry.Version, _ = pyjson.Int(row["version"])
			entry.ValueSchema, _ = pyjson.Text(row["value_schema"])
			entry.ComposableVersions = row["composable_versions"] == true
			kinds, _ := pyjson.Array(row["applies_to"])
			for _, kind := range kinds {
				if text, isText := pyjson.Text(kind); isText {
					entry.AppliesTo = append(entry.AppliesTo, text)
				}
			}
			entry.Category, _ = pyjson.Text(row["category"])
			entry.Kind, _ = pyjson.Text(row["kind"])
			entry.Description, _ = pyjson.Text(row["description"])
			entries[name] = append(entries[name], entry)
		}
	}
}

// Entries returns the entries of one registry (error-codes, semantic-rules, extensions,
// vocabulary or algorithm-suites).
func Entries(name string) []Entry {
	once.Do(load)
	return entries[name]
}

// ActiveIDs returns the identifiers of the active entries of a registry, optionally only those
// with the given category (vocabulary) or kind (algorithm-suites).
func ActiveIDs(name, category, kind string) map[string]bool {
	found := map[string]bool{}
	for _, entry := range Entries(name) {
		if entry.Status != "active" || (category != "" && entry.Category != category) || (kind != "" && entry.Kind != kind) {
			continue
		}
		found[entry.ID] = true
	}
	return found
}

// Precedence returns the precedence of each active rule and error identifier.
func Precedence() map[string]int64 {
	found := map[string]int64{}
	for _, entry := range Entries("semantic-rules") {
		if entry.Status == "active" {
			found[entry.ID] = entry.Precedence
		}
	}
	return found
}

// Stages returns the stage of EBMP2-068 that each active bundle rule names in its registry stage
// attribute.
func Stages() map[string]int {
	found := map[string]int{}
	for _, entry := range Entries("semantic-rules") {
		if entry.Status == "active" && entry.Stage > 0 {
			found[entry.ID] = int(entry.Stage)
		}
	}
	return found
}

// Description returns the registered description of an error code or rule, if there is one.
func Description(identifier string) (string, bool) {
	for _, name := range []string{"error-codes", "semantic-rules"} {
		for _, entry := range Entries(name) {
			if entry.ID == identifier && entry.Description != "" {
				return entry.Description, true
			}
		}
	}
	return "", false
}

// ComposableExtensions returns the extension identifiers whose registry entry declares their
// versions composable (XR1-010); anything but composable_versions set to true leaves two versions
// of an identifier in one object a conflict.
func ComposableExtensions() map[string]bool {
	found := map[string]bool{}
	for _, entry := range Entries("extensions") {
		if entry.ComposableVersions {
			found[entry.ID] = true
		}
	}
	return found
}

// RulesApplyingTo returns the active semantic rules whose applies_to names the object type kind,
// such as ECL-WI-1 for a work intent: the rules that the document stage applies to a document
// whose protocol is kind.
func RulesApplyingTo(kind string) map[string]bool {
	found := map[string]bool{}
	for _, entry := range Entries("semantic-rules") {
		if entry.Status != "active" {
			continue
		}
		for _, item := range entry.AppliesTo {
			if item == kind {
				found[entry.ID] = true
			}
		}
	}
	return found
}
