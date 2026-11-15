package envelope_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
)

const reviewKeyID = "urn:example:key:public-review"

func reviewContext() envelope.Context {
	return envelope.Context{TrustPolicyID: "urn:example:policy:review", TrustPolicyVersion: "1", TrustPolicyDigest: strings.Repeat("ab", 32), TrustPolicyEpoch: 1,
		EvaluatedAt: "2026-11-09T00:00:00Z", VerificationTimePolicy: "ecl.time.issued-at.v1", RevocationPolicy: "ecl.revocation.offline-bundle.v1", AllowedSuites: []string{envelope.Ed25519Suite}}
}

func reviewPayload(t *testing.T) map[string]any {
	value := parse(t, "conformance/vectors/dcmp-2/valid-decision-request.json")
	context := reviewContext()
	value["integrity_policy"] = map[string]any{"required": true, "threshold": 1, "accepted_suites": []any{envelope.Ed25519Suite}, "eligible_key_ids": []any{}, "required_key_ids": []any{},
		"verification_time_policy": context.VerificationTimePolicy, "revocation_policy": context.RevocationPolicy,
		"trust_policy": map[string]any{"id": context.TrustPolicyID, "version": "1", "epoch": 1, "digest": map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": context.TrustPolicyDigest}}}
	return value
}

func reviewSign(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := canon.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	media := "application/vnd.ecl.dcmp+json"
	message, err := envelope.SigningInput(media, raw)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	digest := sha256.Sum256(raw)
	return map[string]any{"envelope_version": "ECL-IE-1", "payload_type": media, "payload": base64.StdEncoding.EncodeToString(raw),
		"payload_digest": map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": hex.EncodeToString(digest[:])},
		"signatures":     []any{map[string]any{"key_id": reviewKeyID, "suite_id": envelope.Ed25519Suite, "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))}}}
}

func reviewVerify(t *testing.T, value map[string]any, code string) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	key := envelope.Key{KeyID: reviewKeyID, SuiteID: envelope.Ed25519Suite, PublicKey: private.Public().(ed25519.PublicKey), RolePurposes: []string{"ecl.purpose.decision-request.v1"}}
	_, err := envelope.Verify(value, map[string]envelope.Key{reviewKeyID: key}, reviewContext())
	if code == "" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var failure *envelope.Error
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("want %s: %v", code, err)
	}
}

func TestPublicReviewROOT015OptionalPolicyLists(t *testing.T) {
	reviewVerify(t, reviewSign(t, reviewPayload(t)), "")
	for _, member := range []string{"eligible_key_ids", "required_key_ids"} {
		value := reviewPayload(t)
		policy := value["integrity_policy"].(map[string]any)
		delete(policy, member)
		reviewVerify(t, reviewSign(t, value), "")
		for _, invalid := range []any{nil, "", []any{reviewKeyID, reviewKeyID}, []any{1}} {
			policy[member] = invalid
			reviewVerify(t, reviewSign(t, value), envelope.SignaturePolicyInvalid)
		}
	}
}

func TestPublicReviewROOT032UnknownDCMPPurpose(t *testing.T) {
	for _, kind := range []string{"", "review_unknown", "control"} {
		value := reviewPayload(t)
		if kind == "" {
			delete(value, "message_type")
		} else {
			value["message_type"] = kind
		}
		reviewVerify(t, reviewSign(t, value), envelope.SignaturePolicyInvalid)
	}
}

func TestPublicReviewROOT071OuterExtensionsAndPrecedence(t *testing.T) {
	ext := func(id string, version int, critical bool) map[string]any {
		return map[string]any{"id": id, "version": version, "critical": critical, "value": map[string]any{}}
	}
	tag := "com.example.audit-tag.v1"
	duplicate := ext(tag, 1, false)
	for _, row := range []struct {
		entries []any
		code    string
	}{
		{nil, ""}, {[]any{duplicate}, ""},
		{[]any{ext(tag, 1, true)}, "ecl.rule.unknown-critical-extension-rejected.v1"},
		{[]any{duplicate, duplicate}, "ecl.rule.extension-identifiers-unique.v1"},
		{[]any{duplicate, ext(tag, 2, false)}, "ecl.rule.extension-single-version.v1"},
		{[]any{duplicate, duplicate, ext("urn:example:unknown", 1, true)}, "ecl.rule.unknown-critical-extension-rejected.v1"},
	} {
		value := reviewSign(t, reviewPayload(t))
		if row.entries != nil {
			value["extensions"] = row.entries
		}
		reviewVerify(t, value, row.code)
	}
	value := reviewSign(t, reviewPayload(t))
	value["extensions"] = []any{ext(tag, 1, true)}
	value["payload_digest"].(map[string]any)["value"] = strings.Repeat("0", 64)
	reviewVerify(t, value, envelope.IntegrityInvalid)
	signature := value["signatures"].([]any)[0]
	signatures := make([]any, 33)
	for i := range signatures {
		signatures[i] = signature
	}
	value["signatures"] = signatures
	reviewVerify(t, value, envelope.ResourceLimitExceeded)
	payload := reviewPayload(t)
	payload["integrity_policy"].(map[string]any)["required"] = false
	value = reviewSign(t, payload)
	value["extensions"] = []any{ext(tag, 1, true)}
	reviewVerify(t, value, "ecl.rule.unknown-critical-extension-rejected.v1")
}
