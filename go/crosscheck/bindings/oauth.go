package bindings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
)

// OAUTH-AUTHORITY-1: one ECL admit as one sender-constrained OAuth 2.0 access token.
const (
	OAuthPresentationVersion = "ecl_oauth_presentation_v1"
	OAuthPresentationSchema  = "https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1"
	DetailsType              = "https://externalcontrollayer.ai/ns/authorization-details/action/1"
	defaultMaxLifetime       = 300
	defaultProofWindow       = 60
	// maxJTICharacters bounds a DPoP proof's jti: 1 to 256 characters, as a presentation record
	// holds it in seen_dpop_jti (OA1-004).
	maxJTICharacters = 256
	// defaultClockSkew is the clock-skew allowance a resource server applies to nbf and exp
	// (OA1-003), zero by default.
	defaultClockSkew = 0

	RuleOAuthIssue        = "ecl.rule.oauth-token-expresses-admit.v1"
	RuleOAuthSignature    = "ecl.rule.oauth-token-signature-checked.v1"
	RuleOAuthPresentation = "ecl.rule.oauth-presentation-checked.v1"
	RuleOAuthRefusal      = "ecl.rule.oauth-refusal-named.v1"

	// The codes of the presentation table (OA1-011).
	errorAudienceMismatch = "ecl.error.audience-mismatch.v1"
	errorScopeMismatch    = "ecl.error.scope-mismatch.v1"
	errorExpired          = "ecl.error.expired.v1"
	errorReplay           = "ecl.error.replay.v1"
	errorIntegrityInvalid = "ecl.error.integrity-invalid.v1"
)

// codedProblem is a reason a resource server must refuse a presentation, with the error code of
// the presentation table that it refuses with (OA1-011).
type codedProblem struct {
	path    string
	message string
	code    string
}

func uncoded(problems []codedProblem) []problem {
	out := make([]problem, 0, len(problems))
	for _, item := range problems {
		out = append(out, problem{item.path, item.message})
	}
	return out
}

// pyInteger is Python's type(x) is int for a JSON value: an integer of any size, never a boolean
// or a double.
func pyInteger(value any) (*big.Int, bool) {
	number, isNumber := value.(json.Number)
	if !isNumber {
		return nil, false
	}
	return new(big.Int).SetString(number.String(), 10)
}

func times(value *big.Int) *big.Int { return new(big.Int).Mul(value, nanosecond) }

// AuthorizationDetailsEntry is the ECL authorization_details entry for an admit, as the
// profile's entry table gives it.
func AuthorizationDetailsEntry(request, response map[string]any, withDecision bool) map[string]any {
	authorization, _ := response["authorization"].(map[string]any)
	action, _ := request["action"].(map[string]any)
	entry := map[string]any{
		"type":              DetailsType,
		"locations":         []any{authorization["audience"]},
		"actions":           []any{action["operation"]},
		"identifier":        member(action, "target", "uri"),
		"authorization_id":  authorization["authorization_id"],
		"request_id":        request["message_id"],
		"action_id":         action["action_id"],
		"action_class":      action["action_class"],
		"scope_digest":      authorization["scope_digest"],
		"parameters_digest": action["parameters_digest"],
		"use_policy":        authorization["use_policy"],
		"valid_from":        authorization["valid_from"],
		"valid_until":       authorization["valid_until"],
	}
	if holds(authorization, "max_uses") {
		entry["max_uses"] = authorization["max_uses"]
	}
	if withDecision {
		entry["decision"] = map[string]any{"uri": response["message_id"], "digest": digestValue(digestOf(response))}
	}
	return entry
}

// subjectAndActor returns sub, and act.sub when the subject differs from the actor (OA1-006).
func subjectAndActor(request map[string]any) (string, any) {
	actor := pyjson.Str(member(request, "actor", "id"))
	subject, isText := textOf(request, "subject", "id")
	if !isText || subject == actor {
		return actor, nil
	}
	return subject, actor
}

func tokenReferenceDigest(token string) map[string]any {
	sum := sha256.Sum256([]byte(token))
	return map[string]any{"algorithm": digestSuite, "value": hex.EncodeToString(sum[:])}
}

func detailsEntries(claims map[string]any) []any {
	var found []any
	listed, _ := claims["authorization_details"].([]any)
	for _, item := range listed {
		if entry, isObject := item.(map[string]any); isObject && entry["type"] == DetailsType {
			found = append(found, item)
		}
	}
	return found
}

// joseProblem turns a refusal of a token or proof into a problem; any other error is the
// exception the reference raises.
func joseProblem(err error, path, message string) problem {
	var refusal *JoseError
	if !errors.As(err, &refusal) {
		raise(err)
	}
	return problem{path, message + refusal.Reason + " check"}
}

func oauthIssue(record, request, response map[string]any, token string) []problem {
	if !pyjson.Equal(response["outcome"], "admit") || !binds(request, response) {
		return []problem{{"/token", "the token was issued for something other than a verified admit"}}
	}
	obligations, emptyList := response["obligations"].([]any)
	if !emptyList || len(obligations) != 0 {
		return []problem{{"/response/obligations", "OAuth profile 1.0 cannot carry obligations"}}
	}
	decoded, err := DecodeJWS(token)
	if err != nil {
		var refusal *JoseError
		if !errors.As(err, &refusal) {
			raise(err)
		}
		return []problem{{"/token", "the token is not a compact JWS"}}
	}
	claims := decoded.Claims
	maxLifetime, ok := integer(record, "max_token_lifetime_seconds")
	if !ok || maxLifetime == 0 {
		maxLifetime = defaultMaxLifetime
	}
	var problems []problem
	found := detailsEntries(claims)
	expected := AuthorizationDetailsEntry(request, response, false)
	if len(found) != 1 {
		problems = append(problems, problem{"/token/authorization_details", "not exactly one ECL entry"})
	} else {
		entry := map[string]any{}
		// The entry may name the decision; a decision of null is present and names none, so it is
		// not taken for an entry without one.
		named := false
		var decision any
		for name, value := range found[0].(map[string]any) {
			if name == "decision" {
				named = true
				decision = value
			} else {
				entry[name] = value
			}
		}
		// OA1-001: the entry's members are the admit's as the same JSON values, so true is not a
		// max_uses of 1.
		if !sameJSON(entry, expected) {
			problems = append(problems, problem{"/token/authorization_details", "the entry is not the admit's"})
		}
		if named && !pyjson.Equal(decision, map[string]any{"uri": response["message_id"], "digest": digestValue(digestOf(response))}) {
			problems = append(problems, problem{"/token/authorization_details", "the entry names another decision"})
		}
	}
	if !pyjson.Equal(claims["aud"], member(response, "authorization", "audience")) {
		problems = append(problems, problem{"/token/aud", "not the authorization's audience as a single value"})
	}
	start := nanos(member(response, "authorization", "valid_from"))
	end := nanos(member(response, "authorization", "valid_until"))
	issued, issuedOK := pyInteger(claims["iat"])
	beginsValue := claims["iat"]
	if holds(claims, "nbf") {
		beginsValue = claims["nbf"]
	}
	begins, beginsOK := pyInteger(beginsValue)
	expires, expiresOK := pyInteger(claims["exp"])
	valid := issuedOK && beginsOK && expiresOK && start != nil && end != nil &&
		times(begins).Cmp(start) >= 0 && times(expires).Cmp(end) <= 0
	if valid {
		lifetime := new(big.Int).Sub(expires, issued)
		valid = lifetime.Sign() > 0 && lifetime.Cmp(big.NewInt(maxLifetime)) <= 0
	}
	if !valid {
		problems = append(problems, problem{"/token/exp", "the token's validity is not inside the window and bound"})
	}
	subject, actor := subjectAndActor(request)
	if !pyjson.Equal(claims["sub"], subject) || (actor != nil && !pyjson.Equal(member(claims, "act", "sub"), actor)) {
		problems = append(problems, problem{"/token/act", "the subject and actor are not the request's"})
	}
	confirmation, isObject := claims["cnf"].(map[string]any)
	single := false
	if isObject && len(confirmation) == 1 {
		// OA1-004: one key, named by a string; a jkt or x5t#S256 of null names no key.
		_, jkt := confirmation["jkt"].(string)
		_, certificate := confirmation["x5t#S256"].(string)
		single = jkt || certificate
	}
	if !single {
		problems = append(problems, problem{"/token/cnf", "the token is not sender-constrained by one key"})
	}
	if reference := member(response, "authorization", "token_reference", "digest"); reference != nil && !sameDigest(reference, tokenReferenceDigest(token)) {
		problems = append(problems, problem{"/token", "the admit's token_reference names another token"})
	}
	// OA1-001: the token is a JWT access token of RFC 9068, whose Section 2.2 requires iss,
	// client_id and jti, each a string (RFC 7519, Sections 4.1.1 and 4.1.7; RFC 8693, Section 4.3).
	for _, name := range []string{"client_id", "iss", "jti"} {
		if _, isText := claims[name].(string); !isText {
			problems = append(problems, problem{"/token/" + name, "the token carries no " + name + " string, which RFC 9068 requires"})
		}
	}
	return problems
}

func issuerKeys(record map[string]any) map[string]map[string]any {
	keys := map[string]map[string]any{}
	for _, item := range array(record, "issuer_keys", "keys") {
		if key, isObject := item.(map[string]any); isObject {
			if kid, isText := key["kid"].(string); isText {
				keys[kid] = key
			}
		}
	}
	return keys
}

func oauthSignature(record map[string]any, token string) []problem {
	_, claims, err := VerifyJWS(token, issuerKeys(record), AccessType)
	if err != nil {
		return []problem{joseProblem(err, "/token", "the token fails the ")}
	}
	if !pyjson.Equal(claims["iss"], record["issuer"]) {
		return []problem{{"/token/iss", "the token's issuer is not the configured one"}}
	}
	return nil
}

// htu returns the request URI without its query and fragment (RFC 9449 section 4.3), or false
// when the URI cannot be split.
func htu(uri string) (string, bool) {
	parts, ok := schema.SplitURI(uri)
	if !ok {
		return "", false
	}
	return schema.URIParts{Scheme: parts.Scheme, Netloc: parts.Netloc, Path: parts.Path}.String(), true
}

func oauthPossession(record, claims map[string]any, token string, presentation map[string]any, presented *big.Int) []codedProblem {
	confirmation, _ := claims["cnf"].(map[string]any)
	if certificate, bound := confirmation["x5t#S256"]; bound {
		// The bound thumbprint is a string: a null one is not matched by a presentation that
		// carries no client certificate.
		if _, isText := certificate.(string); !isText || !pyjson.Equal(presentation["client_certificate_sha256"], certificate) {
			return []codedProblem{{"/presentation", "the client certificate is not the bound one", errorIntegrityInvalid}}
		}
		return nil
	}
	jkt, hasKey := confirmation["jkt"]
	proof, isText := presentation["dpop_proof"].(string)
	if !hasKey || !isText {
		return []codedProblem{{"/presentation/dpop_proof", "no proof of possession", errorIntegrityInvalid}}
	}
	_, proofClaims, key, err := VerifyDPoP(proof)
	if err != nil {
		refusal := joseProblem(err, "/presentation/dpop_proof", "the proof fails the ")
		return []codedProblem{{refusal.path, refusal.message, errorIntegrityInvalid}}
	}
	var problems []codedProblem
	window, ok := integer(record, "dpop_proof_window_seconds")
	if !ok || window == 0 {
		window = defaultProofWindow
	}
	issued, issuedOK := pyInteger(proofClaims["iat"])
	targetURI, targetOK := "", false
	if uri, uriIsText := presentation["uri"].(string); uriIsText {
		targetURI, targetOK = htu(uri)
	}
	bound := pyjson.Equal(key, jkt) && pyjson.Equal(proofClaims["htm"], presentation["method"]) && targetOK &&
		pyjson.Equal(proofClaims["htu"], targetURI)
	if bound {
		hash, err := TokenHash(token)
		if err != nil {
			raise(err)
		}
		bound = pyjson.Equal(proofClaims["ath"], hash) && issuedOK && presented != nil
	}
	if bound {
		skew := new(big.Int).Sub(presented, times(issued))
		bound = skew.Abs(skew).Cmp(times(big.NewInt(window))) <= 0
	}
	if !bound {
		problems = append(problems, codedProblem{"/presentation/dpop_proof", "the proof does not bind this request", errorIntegrityInvalid})
	}
	// OA1-004: the proof's jti is a string of 1 to 256 characters that the resource server has not
	// accepted; a proof without one, with one of another type or with one that no
	// presentation record can hold among the jti values seen cannot be checked for
	// replay. Characters are code points, as the record schema counts them.
	if jti, isText := proofClaims["jti"].(string); !isText || utf8.RuneCountInString(jti) < 1 || utf8.RuneCountInString(jti) > maxJTICharacters {
		problems = append(problems, codedProblem{"/presentation/dpop_proof", "the proof carries no jti string of 1 to 256 characters", errorIntegrityInvalid})
	} else if pyjson.InList(proofClaims["jti"], array(presentation, "seen_dpop_jti")) {
		problems = append(problems, codedProblem{"/presentation/dpop_proof", "the proof's jti was seen before", errorReplay})
	}
	return problems
}

// oauthWithinValidity reports whether the time of presentation lies within the token's validity,
// widened by the declared clock-skew allowance, and, when the token carries one ECL entry, within
// that entry's window, to which no allowance applies (OA1-003).
func oauthWithinValidity(record, claims map[string]any, entries []any, presented *big.Int) bool {
	skew, ok := integer(record, "clock_skew_seconds")
	if !ok {
		skew = defaultClockSkew
	}
	beginsValue := claims["iat"]
	if holds(claims, "nbf") {
		beginsValue = claims["nbf"]
	}
	begins, beginsOK := pyInteger(beginsValue)
	expires, expiresOK := pyInteger(claims["exp"])
	if presented == nil || !beginsOK || !expiresOK {
		return false
	}
	allowance := big.NewInt(skew)
	if times(new(big.Int).Sub(begins, allowance)).Cmp(presented) > 0 || presented.Cmp(times(new(big.Int).Add(expires, allowance))) >= 0 {
		return false
	}
	if len(entries) != 1 {
		return true
	}
	start := nanos(member(entries[0], "valid_from"))
	end := nanos(member(entries[0], "valid_until"))
	return start != nil && end != nil && start.Cmp(presented) <= 0 && presented.Cmp(end) < 0
}

// oauthPresentationChecks returns each reason a resource server must refuse the presentation
// (OA1-002 to OA1-005), with its error code, in the order a resource server checks them.
func oauthPresentationChecks(record map[string]any) []codedProblem {
	token, _ := textOf(record, "token")
	decoded, err := DecodeJWS(token)
	if err != nil {
		var refusal *JoseError
		if !errors.As(err, &refusal) {
			raise(err)
		}
		return []codedProblem{{"/token", "the token is not a compact JWS", errorIntegrityInvalid}}
	}
	claims := decoded.Claims
	presentation, isObject := object(record, "presentation")
	if !isObject {
		presentation = map[string]any{}
	}
	var problems []codedProblem
	if !pyjson.Equal(claims["aud"], record["resource_server"]) {
		problems = append(problems, codedProblem{"/token/aud", "the token is for another audience", errorAudienceMismatch})
	}
	presented := nanos(presentation["presented_at"])
	found := detailsEntries(claims)
	entry := map[string]any{}
	if len(found) == 1 {
		entry = found[0].(map[string]any)
	}
	if !oauthWithinValidity(record, claims, found, presented) {
		problems = append(problems, codedProblem{"/presentation/presented_at", "outside the token's validity", errorExpired})
	}
	problems = append(problems, oauthPossession(record, claims, token, presentation, presented)...)
	actions, _ := entry["actions"].([]any)
	if !pyjson.Equal(presentation["target"], entry["identifier"]) || !pyjson.InList(presentation["operation"], actions) ||
		!sameDigest(presentation["parameters_digest"], entry["parameters_digest"]) {
		problems = append(problems, codedProblem{"/presentation", "another target, operation or parameter digest", errorScopeMismatch})
	}
	limit, limited := pyInteger(entry["max_uses"])
	if pyjson.Equal(entry["use_policy"], "single_use") {
		limit, limited = big.NewInt(1), true
	}
	used, usedOK := integer(presentation, "use_count")
	if !usedOK || (limited && big.NewInt(used).Cmp(limit) > 0) {
		problems = append(problems, codedProblem{"/presentation/use_count", "beyond the entry's use policy", errorReplay})
	}
	return problems
}

func oauthPresentation(record map[string]any, _ string) []problem {
	return uncoded(oauthPresentationChecks(record))
}

// oauthRefusalProblems returns each check of the presentation table that the presentation fails,
// in the table's order (OA1-011): the token's JWS checks (OA1-007), then the resource server's
// checks of audience, validity, proof of possession, scope and uses.
func oauthRefusalProblems(record map[string]any) []codedProblem {
	token, _ := textOf(record, "token")
	if signature := oauthSignature(record, token); len(signature) > 0 {
		out := make([]codedProblem, 0, len(signature))
		for _, item := range signature {
			out = append(out, codedProblem{item.path, item.message, errorIntegrityInvalid})
		}
		return out
	}
	return oauthPresentationChecks(record)
}

// oauthRefusal checks that a refusal names the code of the first check of the presentation table
// that fails; a refusal of a presentation that fails no check may name any registered error.
func oauthRefusal(record map[string]any) []problem {
	problems := oauthRefusalProblems(record)
	if len(problems) == 0 {
		return nil
	}
	expected := problems[0].code
	if !pyjson.Equal(member(record, "result", "error"), expected) {
		return []problem{{"/result/error", "the first check that fails gives " + expected}}
	}
	return nil
}

// oauthIssuerRules are checked for every record, oauthAcceptanceRules only when the resource server
// accepted the presentation and oauthRefusalRules only when it refused it, each in the order the
// reference reports them. A rule added to the registry for this profile is one function and one
// row in the table it belongs to.
var (
	oauthIssuerRules = []struct {
		rule  string
		check func(record, request, response map[string]any, token string) []problem
	}{
		{RuleOAuthIssue, oauthIssue},
	}
	oauthAcceptanceRules = []struct {
		rule  string
		check func(record map[string]any, token string) []problem
	}{
		{RuleOAuthSignature, oauthSignature},
		{RuleOAuthPresentation, oauthPresentation},
	}
	oauthRefusalRules = []struct {
		rule  string
		check func(record map[string]any) []problem
	}{
		{RuleOAuthRefusal, oauthRefusal},
	}
)

// checkOAuth returns the findings of an ecl_oauth_presentation_v1 record that its schema accepted
// (OA1-001 to OA1-011): the issuer's side always, the resource server's checks when the
// presentation was accepted, and the refusal's code when it was refused.
func checkOAuth(record map[string]any) []Finding {
	request, hasRequest := object(record, "request")
	response, hasResponse := object(record, "response")
	token, hasToken := textOf(record, "token")
	if !hasRequest || !hasResponse || !hasToken {
		return nil
	}
	var out []Finding
	for _, row := range oauthIssuerRules {
		out = append(out, findings(row.rule, row.check(record, request, response, token))...)
	}
	accepted := member(record, "result", "accepted")
	if accepted == false {
		for _, row := range oauthRefusalRules {
			out = append(out, findings(row.rule, row.check(record))...)
		}
		return out
	}
	if accepted != true {
		return out
	}
	for _, row := range oauthAcceptanceRules {
		out = append(out, findings(row.rule, row.check(record, token))...)
	}
	return out
}
