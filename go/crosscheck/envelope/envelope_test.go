package envelope_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/envelope"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func decodeHex(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func parse(t *testing.T, path string) map[string]any {
	t.Helper()
	value, err := strict.Parse(vectors.Read(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func TestSigningInput(t *testing.T) {
	encoded, err := envelope.SigningInput("http://example.com/HelloWorld", []byte("hello world"))
	if err != nil || string(encoded) != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatalf("%q %v", encoded, err)
	}
	if _, err := envelope.SigningInput("café", nil); err == nil {
		t.Fatal("a non-ASCII payload type was accepted")
	}
}

func TestCanonicalBase64(t *testing.T) {
	if data, ok := envelope.DecodeCanonicalBase64("aGk="); !ok || string(data) != "hi" {
		t.Fatal("aGk=")
	}
	for _, text := range []string{"aGk", "aGl=", "aG k=", "aGk==", "a===", "aGk=\n", "aG\nk=", "!!!!", "aGk=aGk="} {
		if _, ok := envelope.DecodeCanonicalBase64(text); ok {
			t.Errorf("accepted %q", text)
		}
	}
}

func TestEd25519RFC8032(t *testing.T) {
	cases := [][3]string{
		{"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
	}
	for _, item := range cases {
		key, message, signature := decodeHex(t, item[0]), decodeHex(t, item[1]), decodeHex(t, item[2])
		if !envelope.VerifyEd25519(key, message, signature) {
			t.Fatal("RFC 8032 signature refused")
		}
		signature[0] ^= 1
		if envelope.VerifyEd25519(key, message, signature) {
			t.Fatal("changed signature accepted")
		}
	}
}

// The 14 small-order encodings and the point not on the curve are refused as keys.
func TestKeyProblems(t *testing.T) {
	count := 0
	for _, vector := range vectors.Suite(t, "trust-policy").Vectors {
		if !strings.HasPrefix(vector.ID, "trust-policy-invalid-small-order-") && vector.ID != "trust-policy-invalid-bad-point" {
			continue
		}
		refused := false
		for _, item := range parse(t, vector.Path)["keys"].([]any) {
			key := item.(map[string]any)
			raw, ok := envelope.DecodeCanonicalBase64(key["public_key"].(string))
			if !ok {
				t.Fatal(vector.ID)
			}
			if envelope.KeyProblem(key["suite_id"].(string), raw) != "" {
				refused = true
			}
		}
		if !refused {
			t.Errorf("%s: no key refused", vector.ID)
		}
		if len(strings.TrimPrefix(vector.ID, "trust-policy-invalid-small-order-")) == 2 {
			count++
		}
	}
	if count != 14 {
		t.Fatalf("%d small-order vectors", count)
	}
	if problem := envelope.KeyProblem(envelope.MLDSA65Suite, make([]byte, 1952)); !strings.Contains(problem, "not supported by trust policy v1") {
		t.Fatal(problem)
	}
}

// The cofactorless equation, a canonical S and no torsion in R (IE1-016).
func TestEd25519Edges(t *testing.T) {
	policy := parse(t, "conformance/suites/envelope/trust-policy.json")
	keys := map[string][]byte{}
	for _, item := range policy["keys"].([]any) {
		key := item.(map[string]any)
		raw, _ := envelope.DecodeCanonicalBase64(key["public_key"].(string))
		keys[key["key_id"].(string)] = raw
	}
	expected := map[string]bool{"envelope-valid-mixed-order": true, "envelope-invalid-mixed-order": false, "envelope-invalid-torsion-r": false, "envelope-invalid-noncanonical-s": false, "envelope-valid-ed25519-signed": true}
	for name, accepted := range expected {
		document := parse(t, "conformance/suites/envelope/"+name+".json")
		signature := document["signatures"].([]any)[0].(map[string]any)
		key := keys[signature["key_id"].(string)]
		if problem := envelope.Ed25519KeyProblem(key); problem != "" {
			t.Fatalf("%s: %s", name, problem)
		}
		payload, err := envelope.DecodePayload(document)
		if err != nil {
			t.Fatal(err)
		}
		message, _ := envelope.SigningInput(document["payload_type"].(string), payload)
		raw, _ := base64.StdEncoding.DecodeString(signature["signature"].(string))
		if envelope.VerifyEd25519(key, message, raw) != accepted {
			t.Errorf("%s: accepted is not %v", name, accepted)
		}
	}
}

func TestP256Encoding(t *testing.T) {
	low := parse(t, "conformance/suites/envelope/envelope-valid-p256-low-s.json")
	high := parse(t, "conformance/suites/envelope/envelope-invalid-p256-high-s.json")
	var key []byte
	for _, item := range parse(t, "conformance/suites/envelope/trust-policy.json")["keys"].([]any) {
		if entry := item.(map[string]any); entry["suite_id"] == envelope.P256Suite {
			key, _ = envelope.DecodeCanonicalBase64(entry["public_key"].(string))
		}
	}
	payload, _ := envelope.DecodePayload(low)
	message, _ := envelope.SigningInput(low["payload_type"].(string), payload)
	signatureOf := func(document map[string]any) []byte {
		raw, _ := base64.StdEncoding.DecodeString(document["signatures"].([]any)[0].(map[string]any)["signature"].(string))
		return raw
	}
	if ok, err := envelope.VerifyP256(key, message, signatureOf(low)); !ok || err != nil {
		t.Fatalf("low-S signature: %v %v", ok, err)
	}
	var encoding *envelope.EncodingError
	if _, err := envelope.VerifyP256(key, message, signatureOf(high)); !errors.As(err, &encoding) {
		t.Fatalf("high-S signature: %v", err)
	}
	der := signatureOf(low)
	longForm := append([]byte{0x30, 0x81, der[1]}, der[2:]...)
	for _, refused := range [][]byte{longForm, append(append([]byte{}, der...), 0), decodeHex(t, "30060201ff020101"), decodeHex(t, "300702020001020101")} {
		if _, err := envelope.VerifyP256(key, message, refused); !errors.As(err, &encoding) {
			t.Errorf("%x: %v", refused, err)
		}
	}
	if ok, err := envelope.VerifyP256(key, message, decodeHex(t, "3006020100020101")); ok || err != nil {
		t.Fatalf("r of zero: %v %v", ok, err)
	}
	if problem := envelope.P256KeyProblem(append([]byte{0x02}, key[1:]...)); problem == "" {
		t.Fatal("a compressed-prefix key was accepted")
	}
}

func TestMLDSAIsUnsupported(t *testing.T) {
	if _, err := envelope.VerifySignature(envelope.MLDSA65Suite, make([]byte, 1952), nil, make([]byte, 3309)); !errors.Is(err, envelope.ErrUnsupportedSuite) {
		t.Fatal(err)
	}
	var encoding *envelope.EncodingError
	if _, err := envelope.VerifySignature("ecl.sig.unknown.v1", nil, nil, nil); !errors.As(err, &encoding) {
		t.Fatal(err)
	}
}

// Every envelope vector that passes its schema verifies, or fails with its expected code, under
// its suite's trust policy at the payload's own time: those of the envelope suite and those of
// the key-roles suite, whose decision request and response count only under a key of their role
// (TP1-010).
func TestEnvelopeSuite(t *testing.T) {
	for _, name := range []string{"envelope", "key-roles"} {
		checkEnvelopeSuite(t, vectors.Suite(t, name))
	}
}

func checkEnvelopeSuite(t *testing.T, suite vectors.Manifest) {
	policy, err := trust.Load(vectors.Read(t, suite.TrustPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range suite.Vectors {
		if vector.Primary == "ecl.error.schema-invalid.v1" || vector.Stage != "envelope" {
			continue
		}
		document := parse(t, vector.Path)
		payload, err := envelope.DecodeCanonicalJSONPayload(document)
		code := ""
		if err == nil {
			object := payload.(map[string]any)
			member, timePolicy := "observed_at", "ecl.time.observed-at.v1"
			if object["protocol"] == "DCMP-2" {
				member, timePolicy = "issued_at", "ecl.time.issued-at.v1"
			}
			var context envelope.Context
			context, err = policy.VerificationContext(object[member].(string), timePolicy)
			if err == nil {
				_, err = envelope.Verify(document, policy.Keyring(), context)
			}
		}
		var refusal *envelope.Error
		if errors.As(err, &refusal) {
			code = refusal.Code
		} else if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		if code != vector.Primary {
			t.Errorf("%s: %q, not %q", vector.ID, code, vector.Primary)
		}
	}
}

// IE1-040, step 4: a trust-policy digest that is not an object, of any type, is refused as
// signature-policy-invalid, as the reference refuses it. The valid envelope's payload is re-encoded
// with its digest replaced and its payload digest recomputed; the signature no longer matches, but
// step 4 refuses first.
func TestTrustPolicyDigestThatIsNotAnObject(t *testing.T) {
	suite := vectors.Suite(t, "envelope")
	policy, err := trust.Load(vectors.Read(t, suite.TrustPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range []any{"abc", json.Number("1"), true, []any{json.Number("1")}} {
		document := parse(t, "conformance/suites/envelope/envelope-valid-ed25519-signed.json")
		payload, err := envelope.DecodeCanonicalJSONPayload(document)
		if err != nil {
			t.Fatal(err)
		}
		object := payload.(map[string]any)
		object["integrity_policy"].(map[string]any)["trust_policy"].(map[string]any)["digest"] = digest
		encoded, err := canon.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(encoded)
		document["payload"] = base64.StdEncoding.EncodeToString(encoded)
		document["payload_digest"] = map[string]any{"algorithm": canon.DigestAlgorithm, "value": hex.EncodeToString(sum[:])}
		context, err := policy.VerificationContext(object["issued_at"].(string), "ecl.time.issued-at.v1")
		if err != nil {
			t.Fatal(err)
		}
		var refusal *envelope.Error
		_, err = envelope.Verify(document, policy.Keyring(), context)
		if !errors.As(err, &refusal) || refusal.Code != envelope.SignaturePolicyInvalid || refusal.Message != "trust policy digest suite is unsupported" {
			t.Errorf("digest %v: %v", digest, err)
		}
	}
}

// A keyring built by hand records no trust-policy purposes, so a decision response is checked by
// its payload type alone; the same keys from a trust policy count it only under a
// decision-response key (TP1-010).
func TestRolePurposesApplyOnlyFromATrustPolicy(t *testing.T) {
	suite := vectors.Suite(t, "key-roles")
	policy, err := trust.Load(vectors.Read(t, suite.TrustPolicyPath))
	if err != nil {
		t.Fatal(err)
	}
	document := parse(t, "conformance/suites/key-roles/key-roles-invalid-response-by-requester-key.json")
	payload, err := envelope.DecodeCanonicalJSONPayload(document)
	if err != nil {
		t.Fatal(err)
	}
	context, err := policy.VerificationContext(payload.(map[string]any)["issued_at"].(string), "ecl.time.issued-at.v1")
	if err != nil {
		t.Fatal(err)
	}
	var refusal *envelope.Error
	if _, err := envelope.Verify(document, policy.Keyring(), context); !errors.As(err, &refusal) || refusal.Code != envelope.SignaturePolicyInvalid {
		t.Fatalf("from the trust policy: %v", err)
	}
	byHand := map[string]envelope.Key{}
	for id, key := range policy.Keyring() {
		key.RolePurposes = nil
		byHand[id] = key
	}
	if _, err := envelope.Verify(document, byHand, context); err != nil {
		t.Fatalf("built by hand: %v", err)
	}
}

func ExampleVerify() {
	data, _ := vectors.ReadFile("conformance/suites/envelope/envelope-valid-ed25519-signed.json")
	document, _ := strict.Parse(data)
	policyData, _ := vectors.ReadFile("conformance/suites/envelope/trust-policy.json")
	policy, _ := trust.Load(policyData)
	payload, _ := envelope.DecodeCanonicalJSONPayload(document)
	issued := payload.(map[string]any)["issued_at"].(string)
	context, _ := policy.VerificationContext(issued, "ecl.time.issued-at.v1")
	result, err := envelope.Verify(document, policy.Keyring(), context)
	fmt.Println(result.ValidKeyIDs, err)
	// Output: [urn:example:key:vector-ed] <nil>
}
