// Package envelope verifies ECL-IE-1 integrity envelopes (INTEGRITY-ENVELOPE-1).
//
// The payload travels as canonical base64 with its SHA-256 digest (IE1-005, IE1-006). The
// signing input is the DSSE v1 pre-authentication encoding of the payload type and the exact
// payload bytes (IE1-009 to IE1-011); the bytes are verified as transported and only then proved
// canonical. The signed payload carries its own integrity policy (IE1-012 to IE1-015), which an
// envelope cannot weaken, and the verifier's context must match the trust policy it names.
// Verification follows the seven steps of IE1-040, and each refusal carries the code of its step.
//
// Ed25519 uses Go's crypto/ed25519, which checks the cofactorless equation as the profile
// requires; ECDSA P-256 uses crypto/ecdsa after the minimal-DER and low-S checks written here.
// ML-DSA-65 is recognized and refused with ErrUnsupportedSuite.
package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// The registered errors that a refusal names (IE1-040).
const (
	IntegrityInvalid       = "ecl.error.integrity-invalid.v1"
	SignaturePolicyInvalid = "ecl.error.signature-policy-invalid.v1"
	Revoked                = "ecl.error.revoked.v1"
	Expired                = "ecl.error.expired.v1"
	ThresholdNotMet        = "ecl.error.threshold-not-met.v1"
	ResourceLimitExceeded  = "ecl.error.resource-limit-exceeded.v1"
)

// Limits of the verifier (IE1-028). They apply to the envelope as received (IE1-040, step 2): the
// base64 text of the payload and of each signature value, which bounds the decoded bytes.
const (
	MaxPayloadBytes      = 64 * 1024 * 1024
	MaxSignatureBytes    = 16 * 1024
	MaxSignatures        = 32
	MaxPolicyListEntries = 64
	maxEncodedPayload    = (MaxPayloadBytes + 2) / 3 * 4
	maxEncodedSignature  = (MaxSignatureBytes + 2) / 3 * 4
)

// Why a signature does not count (IE1-040, step 6).
const (
	reasonUnacceptable = "unacceptable"
	reasonRevoked      = "revoked"
	reasonExpired      = "expired"
	reasonUnverified   = "unverified"
)

// reasonCodes gives, in the order of the checks of IE1-040 step 6, why a signature does not count
// and the code that the earliest such reason gives a refusal in step 7.
var reasonCodes = []struct{ reason, code string }{
	{reasonUnacceptable, SignaturePolicyInvalid},
	{reasonRevoked, Revoked},
	{reasonExpired, Expired},
	{reasonUnverified, SignaturePolicyInvalid},
}

// Trusted-time countersignatures (IE1-032 to IE1-036).
const (
	TrustedTimeClaim    = "ecl.claim.trusted-time.v1"
	TimeAttestationType = "application/vnd.ecl.time-attestation+json"
)

// ProtocolMediaTypes maps each protocol to the payload type of its envelopes.
var ProtocolMediaTypes = map[string]string{
	"DCMP-2": "application/vnd.ecl.dcmp+json",
	"EBMP-2": "application/vnd.ecl.ebmp+json",
}

// Error is a malformed or unverifiable envelope. Code is the registered error of the step of
// IE1-040 that refused it. NodeBudget marks a payload refused at the value limit that its caller
// passed to DecodeCanonicalJSONPayloadWithin.
type Error struct {
	Code       string
	Message    string
	NodeBudget bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func integrity(message string) error { return &Error{Code: IntegrityInvalid, Message: message} }
func policyError(message string) error {
	return &Error{Code: SignaturePolicyInvalid, Message: message}
}
func limitError(message string) error {
	return &Error{Code: ResourceLimitExceeded, Message: message}
}

// Key is one trusted verification key, as a keyring holds it.
type Key struct {
	KeyID   string
	SuiteID string
	// PublicKey is the raw key: 32 bytes for Ed25519, the 65-byte SEC 1 point for P-256.
	PublicKey      []byte
	TrustPolicyIDs []string
	// Purposes are the payload types the key may sign; none means any.
	Purposes []string
	// ValidFrom and ValidUntil are ECL instants; "" means unbounded.
	ValidFrom  string
	ValidUntil string
	// RolePurposes are the key's TRUST-POLICY-1 purposes, when it comes from a trust policy: a
	// DCMP-2 message then counts only under a key that holds the purpose IE1-039 gives its message
	// type (TP1-010). Empty, the key is checked by payload type alone, as one built by hand is.
	RolePurposes []string
}

// rolePurposes maps each DCMP-2 message type to the purpose that its signer's key holds
// (TP1-010, IE1-039). A decision point answers a request with a response or a challenge, a
// requester answers a challenge, and the control plane issues control messages.
var rolePurposes = map[string]string{
	"decision_request":   "ecl.purpose.decision-request.v1",
	"challenge_response": "ecl.purpose.decision-request.v1",
	"decision_response":  "ecl.purpose.decision-response.v1",
	"challenge":          "ecl.purpose.decision-response.v1",
	"control":            "ecl.purpose.control.v1",
}

// rolePurpose returns the purpose that the signer of a DCMP-2 message must hold (IE1-039), or "".
func rolePurpose(payload any) string {
	object, isObject := payload.(map[string]any)
	if !isObject {
		return ""
	}
	if protocol, _ := object["protocol"].(string); protocol != "DCMP-2" {
		return ""
	}
	messageType, _ := object["message_type"].(string)
	return rolePurposes[messageType]
}

// Revocation revokes one key from an effective time on.
type Revocation struct {
	KeyID       string
	EffectiveAt string
	Reason      string
}

// Context is the trust policy and time under which an envelope is verified.
type Context struct {
	TrustPolicyID          string
	TrustPolicyVersion     string
	TrustPolicyDigest      string
	TrustPolicyEpoch       int64
	EvaluatedAt            string
	VerificationTimePolicy string
	RevocationPolicy       string
	AllowedSuites          []string
	ProhibitedSuites       []string
	Revocations            []Revocation
	// KeyTimes gives a signing key its own evaluation time, which takes the place of EvaluatedAt
	// for that key's revocation and validity (IE1-034: a signature that a trusted-time
	// countersignature covers is evaluated at its attested time, each other one at the object's
	// own time); the threshold counts each signature as evaluated at its own time.
	KeyTimes map[string]string
}

// Result is a verified envelope.
type Result struct {
	Payload     any
	ValidKeyIDs []string
}

func isASCII(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] >= 0x80 {
			return false
		}
	}
	return true
}

// SigningInput returns the DSSE v1 pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload.
func SigningInput(payloadType string, payload []byte) ([]byte, error) {
	if !isASCII(payloadType) {
		return nil, integrity("payload_type must be ASCII")
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out.Write(payload)
	return out.Bytes(), nil
}

// DecodeCanonicalBase64 decodes standard padded base64 that is in canonical form: the text that
// encoding the result gives back.
func DecodeCanonicalBase64(text string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, false
	}
	return decoded, true
}

// DecodePayload returns the payload bytes of an envelope after checking canonical base64 and
// the declared digest.
func DecodePayload(envelope any) ([]byte, error) {
	object, ok := pyjson.Object(envelope)
	if !ok {
		return nil, integrity("integrity envelope must be an object")
	}
	encoded, ok := pyjson.Text(object["payload"])
	if !ok || !isASCII(encoded) {
		return nil, integrity("payload is not valid canonical base64")
	}
	if len(encoded) > maxEncodedPayload {
		return nil, limitError("payload exceeds the integrity byte budget")
	}
	payload, ok := DecodeCanonicalBase64(encoded)
	if !ok {
		return nil, integrity("payload is not canonical base64")
	}
	sum := sha256.Sum256(payload)
	declared := object["payload_digest"]
	if !pyjson.Truthy(declared) {
		declared = map[string]any{}
	}
	if _, isObject := pyjson.Object(declared); !isObject {
		return nil, integrity("payload digest must be an object")
	}
	if !pyjson.Equal(pyjson.Get(declared, "algorithm"), canon.DigestAlgorithm) {
		return nil, integrity("unsupported or missing payload digest suite")
	}
	if !pyjson.Equal(pyjson.Get(declared, "value"), hex.EncodeToString(sum[:])) {
		return nil, integrity("payload digest mismatch")
	}
	return payload, nil
}

// DecodeCanonicalJSONPayload returns the payload as a JSON value, after proving that its bytes
// are canonical ECL JSON.
func DecodeCanonicalJSONPayload(envelope any) (any, error) {
	return DecodeCanonicalJSONPayloadWithin(envelope, strict.DefaultLimits.MaxNodes)
}

// DecodeCanonicalJSONPayloadWithin is DecodeCanonicalJSONPayload with the value limit maxNodes,
// at most the library's own (IE1-037, check 3), so that no value is built beyond it (IE1-029). A
// refusal at that limit is an *Error with NodeBudget set.
func DecodeCanonicalJSONPayloadWithin(envelope any, maxNodes int) (any, error) {
	payload, err := DecodePayload(envelope)
	if err != nil {
		return nil, err
	}
	limits := strict.DefaultLimits
	limits.MaxNodes = min(max(maxNodes, 1), strict.DefaultLimits.MaxNodes)
	value, err := strict.ParseLimited(payload, limits)
	if err != nil {
		// A declared limit of the strict parser is a resource limit; any other refusal leaves the
		// payload outside canonical strict JSON (IE1-040, step 3).
		var refusal *strict.Error
		if errors.As(err, &refusal) && refusal.RuleID == strict.ResourceLimitExceeded {
			if refusal.Reason == strict.NodeBudgetReason(limits.MaxNodes) {
				return nil, &Error{Code: ResourceLimitExceeded, Message: err.Error(), NodeBudget: true}
			}
			return nil, limitError(err.Error())
		}
		return nil, integrity(err.Error())
	}
	encoded, err := canon.Marshal(value)
	if err != nil {
		return nil, integrity(err.Error())
	}
	if !bytes.Equal(encoded, payload) {
		return nil, integrity("payload is not canonical ECL JSON")
	}
	return value, nil
}

// SignatureDigest returns the ecl.digest.sha-256.v1 digest of the signature bytes that a signature
// entry's signature encodes (IE1-033), or an error when the entry has no canonical base64
// signature.
func SignatureDigest(entry any) (map[string]any, error) {
	object, isObject := pyjson.Object(entry)
	if !isObject {
		return nil, integrity("integrity signature entry must be an object")
	}
	raw, err := decodeSignature(object["signature"])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": hex.EncodeToString(sum[:])}, nil
}

// SignatureVerifies reports whether one signature entry of an envelope verifies with key's public
// key over the envelope's signing input (IE1-040 step 6 (d) and (e)); false for any failure.
func SignatureVerifies(envelopeValue any, entry any, key Key) bool {
	object, isObject := pyjson.Object(envelopeValue)
	signatureEntry, entryIsObject := pyjson.Object(entry)
	if !isObject || !entryIsObject {
		return false
	}
	payloadType, ok := pyjson.Text(object["payload_type"])
	if !ok {
		return false
	}
	payload, err := DecodePayload(object)
	if err != nil {
		return false
	}
	message, err := SigningInput(payloadType, payload)
	if err != nil {
		return false
	}
	signature, err := decodeSignature(signatureEntry["signature"])
	if err != nil {
		return false
	}
	verified, err := VerifySignature(key.SuiteID, key.PublicKey, message, signature)
	return err == nil && verified
}

func decodeSignature(value any) ([]byte, error) {
	text, ok := pyjson.Text(value)
	if !ok || !isASCII(text) {
		return nil, integrity("signature is not valid canonical base64")
	}
	if len(text) > maxEncodedSignature {
		return nil, limitError("signature exceeds the integrity byte budget")
	}
	decoded, ok := DecodeCanonicalBase64(text)
	if !ok {
		return nil, integrity("signature is not canonical base64")
	}
	return decoded, nil
}

// micros reads an instant with digits after the microsecond dropped, as the reference's
// datetime comparisons floor them.
func micros(value string) (instant.Instant, error) {
	parsed, err := instant.Parse(value)
	if err != nil {
		return instant.Instant{}, integrity("invalid UTC timestamp: " + strconv.Quote(value))
	}
	return parsed.Micro(), nil
}

func validateContext(policy map[string]any, context Context) (instant.Instant, error) {
	trust, ok := pyjson.Object(policy["trust_policy"])
	if !ok {
		return instant.Instant{}, policyError("signed payload lacks a trust policy reference")
	}
	// A digest that is not an object, absent or of any other type, names no digest suite (IE1-040,
	// step 4), as the reference refuses it.
	declared, isObject := pyjson.Object(trust["digest"])
	if !isObject {
		return instant.Instant{}, policyError("trust policy digest suite is unsupported")
	}
	observed := []any{trust["id"], trust["version"], pyjson.Get(declared, "value"), trust["epoch"]}
	expected := []any{context.TrustPolicyID, context.TrustPolicyVersion, context.TrustPolicyDigest, context.TrustPolicyEpoch}
	if !pyjson.Equal(pyjson.Get(declared, "algorithm"), canon.DigestAlgorithm) {
		return instant.Instant{}, policyError("trust policy digest suite is unsupported")
	}
	// Each member as the same JSON value, as the reference's same_json compares it, so an epoch of
	// true is not epoch 1. The members are strings and an integer, which SchemaEqual
	// compares exactly.
	if !pyjson.SchemaEqual(observed, expected) {
		return instant.Instant{}, policyError("verification context does not match signed trust policy")
	}
	if !pyjson.Equal(policy["verification_time_policy"], context.VerificationTimePolicy) {
		return instant.Instant{}, policyError("verification context does not match signed verification-time policy")
	}
	if !pyjson.Equal(policy["revocation_policy"], context.RevocationPolicy) {
		return instant.Instant{}, policyError("verification context does not match signed revocation policy")
	}
	return micros(context.EvaluatedAt)
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

// keyIneligibility says why a key cannot count for this payload at evaluatedAt (IE1-040, step 6
// (a) to (c)): not acceptable for the trust policy, payload type or role, revoked, or outside its
// validity interval, in that order; "" when it can count.
func keyIneligibility(key Key, payloadType string, context Context, evaluatedAt instant.Instant, role string) (string, error) {
	if len(key.TrustPolicyIDs) > 0 && !contains(key.TrustPolicyIDs, context.TrustPolicyID) {
		return reasonUnacceptable, nil
	}
	if len(key.Purposes) > 0 && !contains(key.Purposes, payloadType) {
		return reasonUnacceptable, nil
	}
	if role != "" && len(key.RolePurposes) > 0 && !contains(key.RolePurposes, role) {
		return reasonUnacceptable, nil
	}
	for _, revocation := range context.Revocations {
		if revocation.KeyID != key.KeyID {
			continue
		}
		effective, err := micros(revocation.EffectiveAt)
		if err != nil {
			return "", err
		}
		if instant.Compare(evaluatedAt, effective) >= 0 {
			return reasonRevoked, nil
		}
	}
	if key.ValidFrom != "" {
		from, err := micros(key.ValidFrom)
		if err != nil {
			return "", err
		}
		if instant.Compare(evaluatedAt, from) < 0 {
			return reasonExpired, nil
		}
	}
	if key.ValidUntil != "" {
		until, err := micros(key.ValidUntil)
		if err != nil {
			return "", err
		}
		if instant.Compare(evaluatedAt, until) >= 0 {
			return reasonExpired, nil
		}
	}
	return "", nil
}

func policyStringSet(policy map[string]any, name string) (map[string]bool, error) {
	raw, ok := pyjson.Array(policy[name])
	if !ok {
		return nil, policyError(name + " must be an array of identifiers")
	}
	set := map[string]bool{}
	for _, entry := range raw {
		text, isText := pyjson.Text(entry)
		if !isText || text == "" {
			return nil, policyError(name + " must be an array of identifiers")
		}
		set[text] = true
	}
	if len(set) != len(raw) {
		return nil, policyError(name + " contains duplicate identifiers")
	}
	return set, nil
}

// Verify checks an envelope's signatures against the integrity policy bound inside its payload,
// with the keys of keyring, under context, in the order of IE1-040. A refusal is an *Error whose
// Code is the code of the step that fails: ResourceLimitExceeded for a declared limit,
// IntegrityInvalid for a malformed envelope, payload or signature encoding,
// SignaturePolicyInvalid for a policy that cannot hold, and for signatures that do not meet the
// policy the code of the earliest reason a signature has (SignaturePolicyInvalid, Revoked,
// Expired), or ThresholdNotMet. ErrUnsupportedSuite is returned as it is. Step 1, the envelope
// schema, is the caller's.
func Verify(envelope any, keyring map[string]Key, context Context) (*Result, error) {
	object, ok := pyjson.Object(envelope)
	if !ok {
		return nil, integrity("integrity envelope must be an object")
	}
	// Step 2: the declared limits that the envelope as received shows.
	if encoded, isText := pyjson.Text(object["payload"]); isText && len(encoded) > maxEncodedPayload {
		return nil, limitError("payload exceeds the integrity byte budget")
	}
	signatures, signaturesOK := pyjson.Array(object["signatures"])
	if signaturesOK {
		if len(signatures) > MaxSignatures {
			return nil, limitError("integrity signature set exceeds the verifier budget")
		}
		for _, item := range signatures {
			entry, isObject := pyjson.Object(item)
			if !isObject {
				continue
			}
			if value, isText := pyjson.Text(entry["signature"]); isText && len(value) > maxEncodedSignature {
				return nil, limitError("signature exceeds the integrity byte budget")
			}
		}
	}
	// Step 3: the payload's encoding, digest, canonical form and media type.
	payloadBytes, err := DecodePayload(object)
	if err != nil {
		return nil, err
	}
	payload, err := DecodeCanonicalJSONPayload(object)
	if err != nil {
		return nil, err
	}
	payloadType, ok := pyjson.Text(object["payload_type"])
	if !ok {
		return nil, integrity("integrity envelope lacks a valid payload_type")
	}
	if utf8.RuneCountInString(payloadType) > 255 || !isASCII(payloadType) {
		return nil, integrity("integrity envelope payload_type is invalid")
	}
	protocol, hasProtocol := pyjson.Text(pyjson.Get(payload, "protocol"))
	if expected, known := ProtocolMediaTypes[protocol]; hasProtocol && known && payloadType != expected {
		return nil, integrity("integrity envelope payload_type does not match the signed " + protocol + " payload")
	}
	for claimed, mediaType := range ProtocolMediaTypes {
		if mediaType == payloadType && (!hasProtocol || protocol != claimed) {
			return nil, integrity("integrity envelope payload does not match the claimed " + claimed + " media type")
		}
	}
	policy, ok := pyjson.Object(pyjson.Get(payload, "integrity_policy"))
	if !ok {
		return nil, integrity("signed payload lacks integrity_policy")
	}
	// Step 4: the payload-bound policy, its lists' declared limit first.
	for _, name := range []string{"accepted_suites", "eligible_key_ids", "required_key_ids"} {
		if raw, isArray := pyjson.Array(policy[name]); isArray && len(raw) > MaxPolicyListEntries {
			return nil, limitError(name + " exceeds the policy resource budget")
		}
	}
	// The policy requires integrity when required is the JSON value true; the number 1 is not.
	if required, isBool := policy["required"].(bool); !isBool || !required {
		return nil, policyError("an integrity envelope cannot elevate a payload that declares integrity optional")
	}
	threshold, ok := pyjson.Int(policy["threshold"])
	if !ok || threshold < 1 {
		return nil, policyError("integrity threshold must be at least one")
	}
	acceptedSuites, err := policyStringSet(policy, "accepted_suites")
	if err != nil {
		return nil, err
	}
	eligibleKeys, err := policyStringSet(policy, "eligible_key_ids")
	if err != nil {
		return nil, err
	}
	requiredKeys, err := policyStringSet(policy, "required_key_ids")
	if err != nil {
		return nil, err
	}
	if len(acceptedSuites) == 0 {
		return nil, policyError("accepted_suites cannot be empty")
	}
	if len(requiredKeys) > 0 && threshold < int64(len(requiredKeys)) {
		return nil, policyError("threshold cannot be lower than required key count")
	}
	evaluatedAt, err := validateContext(policy, context)
	if err != nil {
		return nil, err
	}
	role := rolePurpose(payload)
	// Step 5: every signature entry names a key and a suite, each pair once.
	if !signaturesOK || len(signatures) == 0 {
		return nil, integrity("integrity signature set is missing")
	}
	type signed struct {
		keyID, suiteID string
		entry          map[string]any
	}
	entries := make([]signed, 0, len(signatures))
	observed := map[string]bool{}
	for _, item := range signatures {
		entry, isObject := pyjson.Object(item)
		if !isObject {
			return nil, integrity("integrity signature entry must be an object")
		}
		keyID, suiteID := "", ""
		if pyjson.Truthy(entry["key_id"]) {
			keyID = pyjson.Str(entry["key_id"])
		}
		if pyjson.Truthy(entry["suite_id"]) {
			suiteID = pyjson.Str(entry["suite_id"])
		}
		if keyID == "" || suiteID == "" {
			return nil, integrity("integrity signature identity is incomplete")
		}
		identity, _ := json.Marshal([]string{keyID, suiteID})
		if observed[string(identity)] {
			return nil, integrity("duplicate signature identity")
		}
		observed[string(identity)] = true
		entries = append(entries, signed{keyID, suiteID, entry})
	}
	// Step 6: each signature in turn.
	message, err := SigningInput(payloadType, payloadBytes)
	if err != nil {
		return nil, err
	}
	valid := map[string]bool{}
	reasons := map[string]bool{}
	for _, item := range entries {
		keyID, suiteID, entry := item.keyID, item.suiteID, item.entry
		// (a) an acceptable key for this suite, payload and policy.
		key, known := keyring[keyID]
		if !acceptedSuites[suiteID] || !contains(context.AllowedSuites, suiteID) || contains(context.ProhibitedSuites, suiteID) ||
			(len(eligibleKeys) > 0 && !eligibleKeys[keyID]) || !known || key.SuiteID != suiteID || key.KeyID != keyID {
			reasons[reasonUnacceptable] = true
			continue
		}
		// (a) to (c): the key's trust policy, payload type, role, revocation and validity.
		keyTime := evaluatedAt
		if own, present := context.KeyTimes[keyID]; present {
			if keyTime, err = micros(own); err != nil {
				return nil, err
			}
		}
		reason, err := keyIneligibility(key, payloadType, context, keyTime, role)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			reasons[reason] = true
			continue
		}
		// (d) and (e): the signature's encoding, then the signature itself.
		raw, present := entry["signature"]
		if !present {
			return nil, integrity("integrity signature bytes are missing")
		}
		signature, err := decodeSignature(raw)
		if err != nil {
			return nil, err
		}
		verified, err := VerifySignature(suiteID, key.PublicKey, message, signature)
		var encoding *EncodingError
		switch {
		case errors.As(err, &encoding):
			return nil, integrity(encoding.Message)
		case err != nil:
			return nil, err
		}
		if !verified {
			reasons[reasonUnverified] = true
			continue
		}
		valid[keyID] = true
	}
	// Step 7: every required key and at least the threshold of keys counted.
	missing := []string{}
	for keyID := range requiredKeys {
		if !valid[keyID] {
			missing = append(missing, keyID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 || int64(len(valid)) < threshold {
		code := ThresholdNotMet
		for _, candidate := range reasonCodes {
			if reasons[candidate.reason] {
				code = candidate.code
				break
			}
		}
		if len(missing) > 0 {
			encoded, _ := json.Marshal(missing)
			return nil, &Error{Code: code, Message: "required signatures are missing or invalid: " + string(encoded)}
		}
		return nil, &Error{Code: code, Message: fmt.Sprintf("signature threshold not met: valid=%d required=%d", len(valid), threshold)}
	}
	keys := make([]string, 0, len(valid))
	for keyID := range valid {
		keys = append(keys, keyID)
	}
	sort.Strings(keys)
	return &Result{Payload: payload, ValidKeyIDs: keys}, nil
}
