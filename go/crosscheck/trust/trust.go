// Package trust loads TRUST-POLICY-1 trust policies: which keys a verifier trusts, for which
// purposes, on whose behalf, and when. The caller of a verifier supplies the policy; an evidence
// bundle never does (IE1-022, TP1-001).
//
// Load refuses anything else with an *Error whose Code says which layer failed:
// ecl.error.schema-invalid.v1 for bytes that are not strict JSON of the schema's shape (TP1-002),
// ecl.error.resource-limit-exceeded.v1 for more than 256 KiB or a document past the strict
// parser's nesting or value limits (TP1-007, IE1-037), and ecl.error.semantic-invalid.v1 for a
// document that cannot hold (TP1-003): a
// key id or public key twice, a suite this version does not carry, a public key that does not
// decode for its suite (for Ed25519: not canonical, or of small order), a validity end not after
// its start, an unregistered purpose or revocation policy, a key that carries the purposes of
// more than one role (TP1-009), or a revocation of an unknown key or of a key twice.
package trust

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

// Registered errors and limits.
const (
	SchemaInvalid         = "ecl.error.schema-invalid.v1"
	SemanticInvalid       = "ecl.error.semantic-invalid.v1"
	ResourceLimitExceeded = "ecl.error.resource-limit-exceeded.v1"
	Schema                = "https://externalcontrollayer.ai/ns/schema/trust-policy/1"
	MaxPolicyBytes        = 256 * 1024
)

// The registered key purposes.
const (
	PurposeDecisionRequest  = "ecl.purpose.decision-request.v1"
	PurposeDecisionResponse = "ecl.purpose.decision-response.v1"
	PurposeEvidenceEvent    = "ecl.purpose.evidence-event.v1"
	PurposeObservation      = "ecl.purpose.observation.v1"
	PurposeTrustedTime      = "ecl.purpose.trusted-time.v1"
	PurposeControl          = "ecl.purpose.control.v1"
	// PurposeApproval qualifies a key that holds the evidence-event purpose as an approval
	// service's (EBMP2-070, MG1-013); it lets a key sign no payload by itself.
	PurposeApproval = "ecl.purpose.approval.v1"
)

// PurposePayloadTypes maps each purpose to the payload type it may sign; the keyring keeps
// DCMP-2 and EBMP-2 keys apart. A request, a response and a control message are DCMP-2 objects
// (IE1-039).
var PurposePayloadTypes = map[string]string{
	PurposeDecisionRequest:  envelope.ProtocolMediaTypes["DCMP-2"],
	PurposeDecisionResponse: envelope.ProtocolMediaTypes["DCMP-2"],
	PurposeControl:          envelope.ProtocolMediaTypes["DCMP-2"],
	PurposeEvidenceEvent:    envelope.ProtocolMediaTypes["EBMP-2"],
	PurposeObservation:      envelope.ProtocolMediaTypes["EBMP-2"],
	PurposeTrustedTime:      envelope.TimeAttestationType,
}

// QualifyingPurposes are the purposes that qualify a key for a role without letting it sign a
// payload type of their own: the approval purpose marks an approval service's key, which also
// holds the evidence-event purpose, so that a verifier admits a human intervention event as the
// proof of an approval obligation only when every key that signed it holds the purpose.
var QualifyingPurposes = map[string]bool{PurposeApproval: true}

// RolePurposes are the purposes that each belong to one component role (TP1-009, ECL1N-0157):
// the requester of a decision, the decision point, the control plane, an observer and a time
// authority. A key carries at most one of them. The evidence-event purpose is no role of its own:
// a requester, a decision point or another component records its evidence with it, so it may
// accompany one.
var RolePurposes = []string{PurposeDecisionRequest, PurposeDecisionResponse, PurposeControl, PurposeObservation, PurposeTrustedTime}

// RoleConflict returns the role purposes among purposes when there is more than one of them
// (TP1-009), in the order of RolePurposes; nil when they belong to one role at most.
func RoleConflict(purposes []string) []string {
	var roles []string
	for _, role := range RolePurposes {
		for _, purpose := range purposes {
			if purpose == role {
				roles = append(roles, role)
				break
			}
		}
	}
	if len(roles) > 1 {
		return roles
	}
	return nil
}

// Error is a trust policy that cannot be used. Code is the registered error.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func cut(text string) string {
	if utf8.RuneCountInString(text) <= 200 {
		return text
	}
	return string([]rune(text)[:199]) + "…"
}

func schemaError(message string) error { return &Error{Code: SchemaInvalid, Message: cut(message)} }
func semanticError(message string) error {
	return &Error{Code: SemanticInvalid, Message: cut(message)}
}

// Key is one key of a trust policy.
type Key struct {
	KeyID     string
	SuiteID   string
	PublicKey []byte
	Principal string
	Purposes  []string
	// ValidFrom is an ECL instant; ValidUntil is one too, or "" when the key has no end.
	ValidFrom  string
	ValidUntil string
}

// Reference is the trust policy as an object embeds it in integrity_policy.trust_policy.
type Reference struct {
	ID      string
	Version string
	Digest  string
	Epoch   int64
}

// Policy is a loaded trust policy. Make one with Load; treat it as read-only.
type Policy struct {
	ID               string
	Version          string
	Epoch            int64
	RevocationPolicy string
	Keys             []Key
	Revocations      []envelope.Revocation
	// Digest is the SHA-256 of the policy's canonical JSON: whitespace and member order aside,
	// it covers every member.
	Digest string
	// Document is the policy as loaded.
	Document map[string]any
}

// Load reads a policy from data: strict JSON, then the schema, then the semantic checks. It
// returns an *Error, never a partly checked policy.
func Load(data []byte) (*Policy, error) {
	if len(data) > MaxPolicyBytes {
		return nil, &Error{Code: ResourceLimitExceeded, Message: fmt.Sprintf("a trust policy is at most %d bytes", MaxPolicyBytes)}
	}
	value, err := strict.Parse(data)
	if err != nil {
		// A declared limit is TP1-007's error; any other strict refusal is TP1-002's.
		var refusal *strict.Error
		if errors.As(err, &refusal) && refusal.RuleID == strict.ResourceLimitExceeded {
			return nil, &Error{Code: ResourceLimitExceeded, Message: cut(err.Error())}
		}
		return nil, schemaError(err.Error())
	}
	errorsFound, err := schema.ECL().Errors(Schema, value, 1)
	if err != nil {
		return nil, err
	}
	if len(errorsFound) > 0 {
		first := errorsFound[0]
		return nil, schemaError(fmt.Sprintf("the trust policy does not satisfy %s: %s: %s: %s", Schema, first.Path, first.Keyword, first.Message))
	}
	document := value.(map[string]any)
	policy := &Policy{Document: document}
	policy.ID, _ = pyjson.Text(document["policy_id"])
	policy.Version, _ = pyjson.Text(document["version"])
	policy.Epoch, _ = pyjson.Int(document["epoch"])
	policy.RevocationPolicy, _ = pyjson.Text(document["revocation_policy"])
	if !registry.ActiveIDs("vocabulary", "revocation_policy", "")[policy.RevocationPolicy] {
		return nil, semanticError(policy.RevocationPolicy + " is not an active revocation policy of the vocabulary registry")
	}
	items, _ := pyjson.Array(document["keys"])
	if policy.Keys, err = loadKeys(items); err != nil {
		return nil, err
	}
	held := map[string]bool{}
	for _, key := range policy.Keys {
		held[key.KeyID] = true
	}
	revocations, _ := pyjson.Array(document["revocations"])
	if policy.Revocations, err = loadRevocations(revocations, held); err != nil {
		return nil, err
	}
	if policy.Digest, err = canon.Digest(document); err != nil {
		return nil, schemaError(err.Error())
	}
	return policy, nil
}

func loadKeys(items []any) ([]Key, error) {
	suites := registry.ActiveIDs("algorithm-suites", "", "signature")
	purposes := registry.ActiveIDs("vocabulary", "key_purpose", "")
	ids := map[string]bool{}
	var keys []Key
	for _, item := range items {
		key, err := loadKey(item.(map[string]any), suites, purposes)
		if err != nil {
			return nil, err
		}
		if ids[key.KeyID] {
			return nil, semanticError("key_id " + key.KeyID + " appears twice in the trust policy")
		}
		ids[key.KeyID] = true
		for _, earlier := range keys {
			if bytes.Equal(earlier.PublicKey, key.PublicKey) {
				return nil, semanticError("keys " + earlier.KeyID + " and " + key.KeyID + " have the same public key")
			}
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func loadKey(item map[string]any, suites, purposes map[string]bool) (Key, error) {
	key := Key{}
	key.KeyID, _ = pyjson.Text(item["key_id"])
	key.SuiteID, _ = pyjson.Text(item["suite_id"])
	key.Principal, _ = pyjson.Text(item["principal"])
	key.ValidFrom, _ = pyjson.Text(item["valid_from"])
	key.ValidUntil, _ = pyjson.Text(item["valid_until"])
	if !suites[key.SuiteID] {
		return Key{}, semanticError("key " + key.KeyID + ": " + key.SuiteID + " is not an active signature suite of the algorithm-suites registry")
	}
	encoded, _ := pyjson.Text(item["public_key"])
	raw, ok := envelope.DecodeCanonicalBase64(encoded)
	if !ok {
		return Key{}, semanticError("key " + key.KeyID + ": public_key is not canonical standard base64")
	}
	if problem := envelope.KeyProblem(key.SuiteID, raw); problem != "" {
		return Key{}, semanticError("key " + key.KeyID + ": " + problem)
	}
	key.PublicKey = raw
	listed, _ := pyjson.Array(item["purposes"])
	for _, entry := range listed {
		purpose, _ := pyjson.Text(entry)
		if !purposes[purpose] {
			return Key{}, semanticError("key " + key.KeyID + ": " + purpose + " is not an active key purpose of the vocabulary registry")
		}
		if _, known := PurposePayloadTypes[purpose]; !known && !QualifyingPurposes[purpose] {
			return Key{}, semanticError("key " + key.KeyID + ": " + purpose + " has no payload type in this module")
		}
		key.Purposes = append(key.Purposes, purpose)
	}
	signing := false
	for _, purpose := range key.Purposes {
		if _, known := PurposePayloadTypes[purpose]; known {
			signing = true
		}
	}
	if !signing {
		return Key{}, semanticError("key " + key.KeyID + ": carries no purpose that signs a payload type, only a qualifying one")
	}
	if roles := RoleConflict(key.Purposes); roles != nil {
		return Key{}, semanticError("key " + key.KeyID + ": one key carries the purposes of more than one role: " + strings.Join(roles, ", ") + " (TP1-009)")
	}
	if _, present := item["valid_until"]; present {
		from, errFrom := instant.Parse(key.ValidFrom)
		until, errUntil := instant.Parse(key.ValidUntil)
		if errFrom != nil || errUntil != nil {
			return Key{}, schemaError("key " + key.KeyID + ": validity times are not ECL instants")
		}
		if instant.Compare(until.Micro(), from.Micro()) <= 0 {
			return Key{}, semanticError("key " + key.KeyID + ": valid_until must be later than valid_from")
		}
	}
	return key, nil
}

func loadRevocations(items []any, held map[string]bool) ([]envelope.Revocation, error) {
	revoked := map[string]bool{}
	revocations := []envelope.Revocation{}
	for _, item := range items {
		keyID, _ := pyjson.TextAt(item, "key_id")
		if !held[keyID] {
			return nil, semanticError("revocation names " + keyID + ", which is not a key of this policy")
		}
		if revoked[keyID] {
			return nil, semanticError("revocation of " + keyID + " appears twice in the trust policy")
		}
		revoked[keyID] = true
		effective, _ := pyjson.TextAt(item, "effective_at")
		reason, _ := pyjson.TextAt(item, "reason")
		revocations = append(revocations, envelope.Revocation{KeyID: keyID, EffectiveAt: effective, Reason: reason})
	}
	return revocations, nil
}

// Reference returns the policy as an object embeds it.
func (p *Policy) Reference() Reference {
	return Reference{ID: p.ID, Version: p.Version, Digest: p.Digest, Epoch: p.Epoch}
}

// Key returns the key with this id.
func (p *Policy) Key(keyID string) (Key, bool) {
	for _, key := range p.Keys {
		if key.KeyID == keyID {
			return key, true
		}
	}
	return Key{}, false
}

// Keyring returns the keys as envelope.Verify reads them: one verification key per key, whose
// purposes become the payload types it may sign and, as RolePurposes, the roles it holds. So
// envelope.Verify keeps DCMP-2 and EBMP-2 keys apart and, within the DCMP-2 media type, counts
// each message only under a key that holds the purpose IE1-039 gives its message type (TP1-010).
// Separating an evidence event from an observation, both EBMP-2, is the bundle verifier's.
func (p *Policy) Keyring() map[string]envelope.Key {
	ring := map[string]envelope.Key{}
	for _, key := range p.Keys {
		types := map[string]bool{}
		for _, purpose := range key.Purposes {
			if QualifyingPurposes[purpose] {
				// A qualifying purpose (the approval purpose) lets the key sign no payload by itself.
				continue
			}
			types[PurposePayloadTypes[purpose]] = true
		}
		purposes := make([]string, 0, len(types))
		for kind := range types {
			purposes = append(purposes, kind)
		}
		sort.Strings(purposes)
		roles := append([]string{}, key.Purposes...)
		sort.Strings(roles)
		ring[key.KeyID] = envelope.Key{
			KeyID: key.KeyID, SuiteID: key.SuiteID, PublicKey: key.PublicKey,
			TrustPolicyIDs: []string{p.ID}, Purposes: purposes,
			ValidFrom: key.ValidFrom, ValidUntil: key.ValidUntil, RolePurposes: roles,
		}
	}
	return ring
}

// VerificationContext returns the context for envelope.Verify at evaluatedAt, under the
// object's own verification-time policy, which must be registered.
func (p *Policy) VerificationContext(evaluatedAt, timePolicy string) (envelope.Context, error) {
	if !registry.ActiveIDs("vocabulary", "verification_time_policy", "")[timePolicy] {
		return envelope.Context{}, semanticError(strconv.Quote(timePolicy) + " is not a verification-time policy of the vocabulary registry")
	}
	suites := map[string]bool{}
	for _, key := range p.Keys {
		suites[key.SuiteID] = true
	}
	allowed := make([]string, 0, len(suites))
	for suite := range suites {
		allowed = append(allowed, suite)
	}
	sort.Strings(allowed)
	return envelope.Context{
		TrustPolicyID: p.ID, TrustPolicyVersion: p.Version, TrustPolicyDigest: p.Digest,
		TrustPolicyEpoch: p.Epoch, EvaluatedAt: evaluatedAt, VerificationTimePolicy: timePolicy,
		RevocationPolicy: p.RevocationPolicy, AllowedSuites: allowed, ProhibitedSuites: []string{},
		Revocations: p.Revocations,
	}, nil
}
