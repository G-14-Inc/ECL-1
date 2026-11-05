// Package bindings checks the records of the five ECL binding profiles: AARM-BINDING-1,
// ACS-BINDING-1, MCP-GATEWAY-1, OTEL-EVIDENCE-EXPORT-1 and OAUTH-AUTHORITY-1, with RFC 8785
// (jcs.go) and compact JWS (jose.go) beneath them.
//
// Findings dispatches on a record's schema_version and returns the findings of that profile's
// registered rules. Like the reference's checkers, it reads only a record that its schema has
// accepted: EvaluateRecord is the conformance runner's binding stage (strict parsing done, then
// the record's schema, then the profile's rules). A record of no binding profile yields one
// schema finding.
//
// The rules compare values as the reference's Python compares them (true == 1, and a double
// equals an integer of the same value), and the segments of a token are read under the strict
// JSON profile of ECL objects, as the reference reads them (pyjson.go, OA1-007). On the few inputs that a record schema accepts but the
// reference cannot handle, the reference raises an exception instead of reporting a finding;
// Findings then returns an error, so that both fail on the same input.
//
// This is repository code maintained by the maintainers of the Python reference, written to the
// normative text of the profiles without importing or calling the reference; agreement with it
// is implementation diversity, not independent assessment.
package bindings

import (
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
)

// Profile is a binding profile's record version, the $id of its record schema and its checker.
type Profile struct {
	Version string
	Schema  string
	check   func(map[string]any) []Finding
}

// Profiles are the five binding profiles, by record version. The OpenTelemetry checker given here
// holds no export key; FindingsWithKeys gives it the caller's.
var Profiles = map[string]Profile{
	AARMExchangeVersion:      {AARMExchangeVersion, AARMExchangeSchema, checkAARM},
	ACSExchangeVersion:       {ACSExchangeVersion, ACSExchangeSchema, checkACS},
	MCPExchangeVersion:       {MCPExchangeVersion, MCPExchangeSchema, checkMCP},
	OTelExportVersion:        {OTelExportVersion, OTelExportSchema, func(record map[string]any) []Finding { return checkOTel(record, nil) }},
	OAuthPresentationVersion: {OAuthPresentationVersion, OAuthPresentationSchema, checkOAuth},
}

// Rules returns the registered rules of the five profiles, in each profile's order.
func Rules() []string {
	var out []string
	for _, row := range aarmRules {
		out = append(out, row.rule)
	}
	for _, row := range acsRules {
		out = append(out, row.rule)
	}
	for _, row := range mcpRules {
		out = append(out, row.rule)
	}
	for _, row := range otelRules {
		out = append(out, row.rule)
	}
	for _, row := range oauthIssuerRules {
		out = append(out, row.rule)
	}
	for _, row := range oauthAcceptanceRules {
		out = append(out, row.rule)
	}
	for _, row := range oauthRefusalRules {
		out = append(out, row.rule)
	}
	return out
}

// raised is the panic value of raise: an exception that the reference raises at that point.
type raised struct{ err error }

// raise turns an error that is not a refusal of the checked content into the exception that the
// reference raises there; Findings recovers it as its error.
func raise(err error) {
	panic(raised{err})
}

// Findings returns the findings of the binding profile whose record value is, sorted by rule,
// path and detail, holding no OpenTelemetry export key. The error is the exception that the
// reference raises on the same record (a *PythonError, or the error of a package beneath this
// one).
func Findings(value any) ([]Finding, error) {
	return FindingsWithKeys(value, nil)
}

// FindingsWithKeys is Findings with the OpenTelemetry export keys that the caller holds, by
// identifier (OE1-010): the OpenTelemetry checker compares a record's keyed digests only under a
// key that the record names.
func FindingsWithKeys(value any, exportKeys map[string]ExportKey) (out []Finding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			switch problem := recovered.(type) {
			case raised:
				out, err = nil, problem.err
			case *pyjson.TypeError:
				out, err = nil, &PythonError{Kind: "TypeError", Message: problem.Message}
			default:
				panic(recovered)
			}
		}
	}()
	record, isObject := value.(map[string]any)
	version, isText := pyjson.Get(value, "schema_version").(string)
	profile, known := Profiles[version]
	if !isObject || !isText || !known {
		return []Finding{{RuleID: schemaInvalid, Path: "/schema_version", Detail: "not a binding profile record"}}, nil
	}
	if version == OTelExportVersion {
		out = checkOTel(record, exportKeys)
	} else {
		out = profile.check(record)
	}
	if out == nil {
		out = []Finding{}
	}
	semantic.Sort(out)
	return out, nil
}

// EvaluateRecord is the conformance runner's binding stage for a parsed record and the schema
// that the vector names: one schema finding when the value is not an object or fails that
// schema, else the profile's findings, holding no export key.
func EvaluateRecord(schemaID string, value any) ([]Finding, error) {
	return EvaluateRecordWithKeys(schemaID, value, nil)
}

// EvaluateRecordWithKeys is EvaluateRecord with the OpenTelemetry export keys that the caller
// holds.
func EvaluateRecordWithKeys(schemaID string, value any, exportKeys map[string]ExportKey) ([]Finding, error) {
	if _, isObject := value.(map[string]any); !isObject {
		return []Finding{{RuleID: schemaInvalid, Path: "/", Detail: "a binding record is a JSON object"}}, nil
	}
	refusals, err := schema.ECL().Errors(schemaID, value, 1)
	if err != nil {
		return nil, err
	}
	if len(refusals) > 0 {
		return []Finding{{RuleID: schemaInvalid, Path: refusals[0].Path, Detail: refusals[0].Keyword + ": " + refusals[0].Message}}, nil
	}
	return FindingsWithKeys(value, exportKeys)
}
