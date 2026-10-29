package bindings

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/registry"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func TestJCSNumberSamplesOfAppendixB(t *testing.T) {
	samples := map[uint64]string{
		0x0000000000000000: "0", 0x8000000000000000: "0", 0x0000000000000001: "5e-324",
		0x8000000000000001: "-5e-324", 0x7fefffffffffffff: "1.7976931348623157e+308",
		0xffefffffffffffff: "-1.7976931348623157e+308", 0x4340000000000000: "9007199254740992",
		0xc340000000000000: "-9007199254740992", 0x4430000000000000: "295147905179352830000",
		0x44b52d02c7e14af5: "9.999999999999997e+22", 0x44b52d02c7e14af6: "1e+23",
		0x44b52d02c7e14af7: "1.0000000000000001e+23", 0x444b1ae4d6e2ef4e: "999999999999999700000",
		0x444b1ae4d6e2ef4f: "999999999999999900000", 0x444b1ae4d6e2ef50: "1e+21",
		0x3eb0c6f7a0b5ed8c: "9.999999999999997e-7", 0x3eb0c6f7a0b5ed8d: "0.000001",
		0x41b3de4355555553: "333333333.3333332", 0x41b3de4355555554: "333333333.33333325",
		0x41b3de4355555555: "333333333.3333333", 0x41b3de4355555556: "333333333.3333334",
		0x41b3de4355555557: "333333333.33333343", 0xbecbf647612f3696: "-0.0000033333333333333333",
		0x43143ff3c1cb0959: "1424953923781206.2",
	}
	for bits, expected := range samples {
		if text, err := JCSNumber(math.Float64frombits(bits)); err != nil || text != expected {
			t.Errorf("%016x: %q %v, want %q", bits, text, err, expected)
		}
	}
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := JCSNumber(value); !errors.Is(err, ErrJCS) {
			t.Errorf("%v: %v", value, err)
		}
	}
}

func TestJCSMemberOrderEscapesAndLimits(t *testing.T) {
	// Section 3.2.3: names are ordered by their UTF-16 code units, so U+1F600 (a surrogate pair)
	// comes after U+20AC and before U+FB33, which code-point order would put before it.
	ordered := map[string]any{
		"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
		"1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control",
		"ö": "Latin Small Letter O With Diaeresis",
	}
	data, err := JCS(ordered)
	expected := `{"\r":"Carriage Return","1":"One","` + "\u0080" + `":"Control","` + "ö" + `":"Latin Small Letter O With Diaeresis","` +
		"€" + `":"Euro Sign","` + "\U0001f600" + `":"Emoji: Grinning Face","` + "דּ" + `":"Hebrew Letter Dalet With Dagesh"}`
	if err != nil || string(data) != expected {
		t.Fatalf("%s %v", data, err)
	}
	data, err = JCS([]any{"\u0007\u001f\"\\/", 1.5, math.Copysign(0, -1), 1e21, json.Number("10000000000000000000000")})
	if err != nil || string(data) != `["\u0007\u001f\"\\/",1.5,0,1e+21,1e+22]` {
		t.Fatalf("%s %v", data, err)
	}
	// A lone surrogate (the WTF-8 form that ParseJWSJSON leaves) has no canonical form.
	if _, err := JCS("\xed\xa0\x80"); !errors.Is(err, ErrJCS) {
		t.Fatalf("lone surrogate: %v", err)
	}
	var deep any = json.Number("1")
	for level := 0; level < 257; level++ {
		deep = []any{deep}
	}
	if _, err := JCS(deep); !errors.Is(err, ErrJCS) {
		t.Fatalf("depth 257: %v", err)
	}
	if data, err := JCS(deep.([]any)[0]); err != nil || len(data) != 256*2+1 {
		t.Fatalf("depth 256: %d %v", len(data), err)
	}
}

func TestParseJWSJSONReadsAsPythonsJSONLoads(t *testing.T) {
	value, err := ParseJWSJSON([]byte(` {"a": 1, "b": 1.0, "c": 1e2, "d": NaN, "e": -Infinity, "f": 123456789012345678901234567890, "g": "\ud800x", "h": [true, null]} `))
	if err != nil {
		t.Fatal(err)
	}
	object := value.(map[string]any)
	if object["a"] != json.Number("1") || object["b"] != 1.0 || object["c"] != 100.0 || !math.IsNaN(object["d"].(float64)) ||
		object["e"] != math.Inf(-1) || object["f"] != json.Number("123456789012345678901234567890") || object["g"] != "\xed\xa0\x80x" {
		t.Fatalf("%#v", object)
	}
	if list := object["h"].([]any); len(list) != 2 || list[0] != true || list[1] != nil {
		t.Fatalf("%#v", object["h"])
	}
	if value, err := ParseJWSJSON([]byte(`"😀"`)); err != nil || value != "\U0001f600" {
		t.Fatalf("%q %v", value, err)
	}
	if value, err := ParseJWSJSON([]byte("1e400")); err != nil || value != math.Inf(1) {
		t.Fatalf("%v %v", value, err)
	}
	for _, bad := range []string{`{"a":1,"a":2}`, "\ufeff{}", "\"\x01\"", "[1,]", "{} x", "01", "1.", "-", "nul", `"\x"`, `"\u12"`, "[1 2]", `{"a" 1}`, "{1:2}", "", "\xff"} {
		if _, err := ParseJWSJSON([]byte(bad)); !errors.Is(err, errPyJSON) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	var python *PythonError
	if _, err := ParseJWSJSON([]byte(strings.Repeat("9", 4301))); !errors.As(err, &python) || python.Kind != "ValueError" {
		t.Fatalf("4301 digits: %v", err)
	}
	if _, err := ParseJWSJSON([]byte(strings.Repeat("9", 4300))); err != nil {
		t.Fatalf("4300 digits: %v", err)
	}
	nested := "1"
	for level := 0; level < 5000; level++ {
		nested = "[" + nested + "]"
	}
	if _, err := ParseJWSJSON([]byte(nested)); err != nil {
		t.Fatal(err)
	}
}

// OA1-007: a JWS segment is read under the strict JSON profile, with the reference's budgets.
func TestJWSSegmentsAreStrictJSON(t *testing.T) {
	for _, bad := range []string{`{"iat":1.5}`, `{"iat":1e3}`, `{"iat":-0}`, `{"iat":9007199254740992}`, `{"iat":NaN}`, `{"iat":-Infinity}`,
		`{"a":"\ud800"}`, "\ufeff{}", `{"iat":` + strings.Repeat("9", 5000) + `}`} {
		if _, err := ParseStrictSegment([]byte(bad)); !errors.Is(err, errNotStrict) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := ParseStrictSegment([]byte(`{"a":1,"a":1}`)); !errors.Is(err, errRepeatedMember) {
		t.Errorf("repeated member: %v", err)
	}
	// A number is refused when it is read, before its object closes with a repeated name.
	if _, err := ParseStrictSegment([]byte(`{"a":1,"a":1.5}`)); !errors.Is(err, errNotStrict) {
		t.Errorf("number before repeated member: %v", err)
	}
	if value, err := ParseStrictSegment([]byte(`{"a":"\ud83d\ude00","b":-9007199254740991}`)); err != nil || member(value, "a") != "\U0001f600" || member(value, "b") != json.Number("-9007199254740991") {
		t.Fatalf("%v %v", value, err)
	}
	nested := "1"
	for level := 0; level < 256; level++ {
		nested = "[" + nested + "]"
	}
	if _, err := ParseStrictSegment([]byte(nested)); err != nil {
		t.Fatalf("depth 256: %v", err)
	}
	if _, err := ParseStrictSegment([]byte("[" + nested + "]")); !errors.Is(err, errNotStrict) {
		t.Fatalf("depth 257: %v", err)
	}
	valid := record(t, "conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json")
	parts := strings.Split(valid["token"].(string), ".")
	for _, alg := range []string{`["ES256"]`, `{"a":"ES256"}`, "1", "null"} {
		header := B64URL([]byte(`{"alg":` + alg + `,"kid":"x","typ":"at+jwt"}`))
		var refusal *JoseError
		if _, _, err := VerifyJWS(header+"."+parts[1]+"."+parts[2], issuerKeys(valid), AccessType); !errors.As(err, &refusal) || refusal.Reason != "algorithm" {
			t.Errorf("alg %s: %v", alg, err)
		}
	}
}

func TestPythonEqualityAcrossClaimsAndRecords(t *testing.T) {
	cases := []struct {
		left, right any
		equal       bool
	}{
		{json.Number("1"), 1.0, true},
		{true, json.Number("1"), true},
		{map[string]any{"a": []any{1.0, "x"}}, map[string]any{"a": []any{json.Number("1"), "x"}}, true},
		{json.Number("9007199254740993"), 9007199254740992.0, false},
		{json.Number("9007199254740992"), 9007199254740992.0, true},
		{math.NaN(), math.NaN(), false},
		{"1", json.Number("1"), false},
		{nil, false, false},
	}
	for _, item := range cases {
		if pyjson.Equal(item.left, item.right) != item.equal {
			t.Errorf("%#v == %#v", item.left, item.right)
		}
	}
}

func TestBase64URLIsCanonicalAndUnpadded(t *testing.T) {
	if B64URL([]byte{0xfb, 0xff}) != "-_8" {
		t.Fatal(B64URL([]byte{0xfb, 0xff}))
	}
	if data, err := B64URLDecode("-_8"); err != nil || string(data) != "\xfb\xff" {
		t.Fatalf("%x %v", data, err)
	}
	for _, bad := range []string{"-_9", "a", "ab==", "a+b/", "ab c"} {
		var refusal *JoseError
		if _, err := B64URLDecode(bad); !errors.As(err, &refusal) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestRFC8037ThumbprintAndSignature(t *testing.T) {
	jwk := map[string]any{"crv": "Ed25519", "kty": "OKP", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	if thumbprint, err := Thumbprint(jwk); err != nil || thumbprint != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("%s %v", thumbprint, err)
	}
	input := []byte("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc")
	signature, err := B64URLDecode("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(EdDSA, jwk, input, signature); err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	var refusal *JoseError
	if err := verifySignature(EdDSA, jwk, input, signature); !errors.As(err, &refusal) || refusal.Reason != "signature" {
		t.Fatalf("changed signature: %v", err)
	}
	if err := verifySignature(ES256, jwk, input, signature); !errors.As(err, &refusal) || refusal.Reason != "algorithm" {
		t.Fatalf("algorithm and key type: %v", err)
	}
}

func record(t *testing.T, path string) map[string]any {
	t.Helper()
	value, err := strict.Parse(vectors.Read(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func TestOAuthTokensAndProofs(t *testing.T) {
	valid := record(t, "conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json")
	token := valid["token"].(string)
	keys := issuerKeys(valid)
	header, claims, err := VerifyJWS(token, keys, AccessType)
	if err != nil || header["alg"] != ES256 || claims["iss"] != "https://as.example.com" {
		t.Fatalf("%v %v %v", header, claims, err)
	}
	if _, isInteger := claims["iat"].(json.Number); !isInteger {
		t.Fatalf("iat: %#v", claims["iat"])
	}
	// JOSE does not require the low s of ECL-IE-1: n - s verifies too.
	parts := strings.Split(token, ".")
	signature, err := B64URLDecode(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	order, _ := new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	high := new(big.Int).Sub(order, new(big.Int).SetBytes(signature[32:])).FillBytes(make([]byte, 32))
	flipped := parts[0] + "." + parts[1] + "." + B64URL(append(append([]byte{}, signature[:32]...), high...))
	if _, _, err := VerifyJWS(flipped, keys, AccessType); err != nil {
		t.Fatalf("high s: %v", err)
	}
	var refusal *JoseError
	if _, _, err := VerifyJWS(token, map[string]map[string]any{}, AccessType); !errors.As(err, &refusal) || refusal.Reason != "kid" {
		t.Fatalf("no keys: %v", err)
	}
	for name, reason := range map[string]string{"oauth-invalid-alg-none-accepted": "algorithm", "oauth-invalid-header-key-accepted": "key-header"} {
		value := record(t, "conformance/suites/oauth-authority/"+name+".json")
		if _, _, err := VerifyJWS(value["token"], issuerKeys(value), AccessType); !errors.As(err, &refusal) || refusal.Reason != reason {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, proofClaims, key, err := VerifyDPoP(member(valid, "presentation", "dpop_proof"))
	if err != nil || proofClaims["htm"] != "POST" {
		t.Fatalf("%v %v", proofClaims, err)
	}
	decoded, err := DecodeJWS(token)
	if err != nil || key != member(decoded.Claims, "cnf", "jkt") {
		t.Fatalf("%s %v", key, err)
	}
}

// TestOAuthJTIBoundsAndTokenStringClaims: a DPoP proof's jti has 1 to 256 characters, counted as
// code points, so that a presentation record can show its replay, and a proof outside them fails
// check 4 of the presentation table (OA1-004, OA1-011); and the issuer's side reports a
// token without the iss, client_id or jti string that RFC 9068, Section 2.2 requires (OA1-001).
func TestOAuthJTIBoundsAndTokenStringClaims(t *testing.T) {
	valid := record(t, "conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json")
	encode := func(value map[string]any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return B64URL(data)
	}
	// The proof re-signed with another jti under the holder's published test key (seed bytes 2 to 33).
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 2)
	}
	holder := ed25519.NewKeyFromSeed(seed)
	proof, err := DecodeJWS(member(valid, "presentation", "dpop_proof"))
	if err != nil {
		t.Fatal(err)
	}
	withJTI := func(jti string) map[string]any {
		claims := map[string]any{}
		for name, value := range proof.Claims {
			claims[name] = value
		}
		claims["jti"] = jti
		signingInput := encode(proof.Header) + "." + encode(claims)
		changed := reparsed(t, valid)
		changed["presentation"].(map[string]any)["dpop_proof"] = signingInput + "." + B64URL(ed25519.Sign(holder, []byte(signingInput)))
		return changed
	}
	for _, jti := range []string{"", strings.Repeat("j", 257), strings.Repeat("\U0001F600", 257)} {
		value := withJTI(jti)
		problems := oauthPresentationChecks(value)
		if len(problems) != 1 || problems[0].message != "the proof carries no jti string of 1 to 256 characters" || problems[0].code != errorIntegrityInvalid {
			t.Errorf("jti of %d characters: %v", utf8.RuneCountInString(jti), problems)
		}
		value["result"] = map[string]any{"accepted": false, "error": errorReplay}
		found, err := Findings(value)
		if err != nil || len(found) != 1 || found[0].RuleID != RuleOAuthRefusal || found[0].Path != "/result/error" {
			t.Errorf("refused as a replay, jti of %d characters: %v %v", utf8.RuneCountInString(jti), found, err)
		}
	}
	for _, jti := range []string{"j", strings.Repeat("j", 256), strings.Repeat("\U0001F600", 256)} {
		value := withJTI(jti)
		if problems := oauthPresentationChecks(value); len(problems) != 0 {
			t.Errorf("jti of %d characters: %v", utf8.RuneCountInString(jti), problems)
		}
		value["presentation"].(map[string]any)["seen_dpop_jti"] = []any{jti}
		if problems := oauthPresentationChecks(value); len(problems) != 1 || problems[0].code != errorReplay {
			t.Errorf("seen jti of %d characters: %v", utf8.RuneCountInString(jti), problems)
		}
	}
	// The issuer's checks do not verify the signature, so a changed token keeps its own.
	token, err := DecodeJWS(valid["token"])
	if err != nil {
		t.Fatal(err)
	}
	request, response := valid["request"].(map[string]any), valid["response"].(map[string]any)
	parts := strings.Split(valid["token"].(string), ".")
	if problems := oauthIssue(valid, request, response, valid["token"].(string)); len(problems) != 0 {
		t.Fatalf("%v", problems)
	}
	for _, name := range []string{"client_id", "iss", "jti"} {
		for _, replacement := range []any{"absent", nil, json.Number("7")} {
			claims := map[string]any{}
			for key, value := range token.Claims {
				claims[key] = value
			}
			if replacement == "absent" {
				delete(claims, name)
			} else {
				claims[name] = replacement
			}
			changed := parts[0] + "." + encode(claims) + "." + parts[2]
			want := "[{/token/" + name + " the token carries no " + name + " string, which RFC 9068 requires}]"
			if got := fmt.Sprint(oauthIssue(valid, request, response, changed)); got != want {
				t.Errorf("%s %v: %s", name, replacement, got)
			}
		}
	}
}

func TestHTUIsPythonsURLUnsplitWithoutQueryAndFragment(t *testing.T) {
	for uri, expected := range map[string]string{
		"https://rs.example.com/payments/transfers?x=1#y": "https://rs.example.com/payments/transfers",
		"HTTPS://RS.example.com":                          "https://RS.example.com",
		"urn:example:a?b":                                 "urn:example:a",
		"https:/path":                                     "https:///path",
		"file:relative":                                   "file:relative",
	} {
		if got, ok := htu(uri); !ok || got != expected {
			t.Errorf("%s: %s, want %s", uri, got, expected)
		}
	}
	if _, ok := htu("https://[::1/"); ok {
		t.Fatal("an unclosed IPv6 bracket splits")
	}
	if _, ok := schema.SplitURI("https://[::1/"); ok {
		t.Fatal("an unclosed IPv6 bracket splits")
	}
}

// A presentation that the reference reports, rather than raising on: an accepted token whose
// header names its algorithm as a list breaks OA1-007.
func TestListAlgorithmIsAFinding(t *testing.T) {
	value := record(t, "conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json")
	parts := strings.Split(value["token"].(string), ".")
	value["token"] = B64URL([]byte(`{"alg":["ES256"],"typ":"at+jwt","kid":"x"}`)) + "." + parts[1] + "." + parts[2]
	findings, err := Findings(value)
	if err != nil {
		t.Fatal(err)
	}
	signature := false
	for _, item := range findings {
		signature = signature || item.RuleID == RuleOAuthSignature
	}
	if !signature {
		t.Fatalf("%v", findings)
	}
}

// OA1-011: a refusal names the code of the first check of the presentation table that fails.
func TestOAuthRefusalCodes(t *testing.T) {
	valid := record(t, "conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json")
	if problems := oauthRefusalProblems(valid); len(problems) != 0 {
		t.Fatalf("%v", problems)
	}
	refused := record(t, "conformance/suites/oauth-authority/oauth-valid-first-cause-refused.json")
	problems := oauthRefusalProblems(refused)
	if len(problems) == 0 || member(refused, "result", "error") != problems[0].code {
		t.Fatalf("%v", problems)
	}
	if found, err := Findings(refused); err != nil || len(found) != 0 {
		t.Fatalf("%v %v", found, err)
	}
	refused["result"].(map[string]any)["error"] = errorReplay
	found, err := Findings(refused)
	if err != nil || len(found) != 1 || found[0].RuleID != RuleOAuthRefusal || found[0].Path != "/result/error" {
		t.Fatalf("%v %v", found, err)
	}
}

func TestACSEffectiveParametersAndChain(t *testing.T) {
	arguments := map[string]any{"amount": json.Number("10"), "memo": map[string]any{"text": "secret", "tag": "t"}, "to": "acct-1"}
	cases := []struct {
		modifications any
		expected      string
	}{
		{map[string]any{"parameter_overrides": map[string]any{"amount": json.Number("5")}}, `{"amount":5,"memo":{"tag":"t","text":"secret"},"to":"acct-1"}`},
		{map[string]any{"redactions": []any{map[string]any{"path": "/memo/text"}}}, `{"amount":10,"memo":{"tag":"t","text":"[REDACTED]"},"to":"acct-1"}`},
		{map[string]any{"modified_content": `{"to":"acct-2"}`}, `{"to":"acct-2"}`},
	}
	for _, item := range cases {
		effective, ok := EffectiveParameters(arguments, item.modifications)
		data, err := JCS(effective)
		if !ok || err != nil || string(data) != item.expected {
			t.Errorf("%v: %s %v", item.modifications, data, err)
		}
	}
	for _, forbidden := range []any{
		map[string]any{"modified_content": "{}", "redactions": []any{}},
		map[string]any{"modified_content": "[1]"},
		map[string]any{"modified_content": `{"a":1.5}`},
		map[string]any{"redactions": []any{map[string]any{"path": "/memo/text"}}, "parameter_overrides": map[string]any{"memo": map[string]any{}}},
		map[string]any{"redactions": []any{map[string]any{"path": "/missing"}}},
		map[string]any{"redactions": []any{map[string]any{"path": "memo"}}},
		map[string]any{"redactions": []any{}, "parameter_overrides": map[string]any{}},
		map[string]any{"redactions": nil},
		"not an object",
	} {
		if effective, ok := EffectiveParameters(arguments, forbidden); ok {
			t.Errorf("%v: %v", forbidden, effective)
		}
	}
	chain := record(t, "conformance/suites/acs-binding/acs-valid-allow-released.json")["chain"].([]any)
	if len(chain) == 0 {
		t.Fatal("no chain")
	}
	for _, item := range chain {
		entry := item.(map[string]any)
		if hash, ok := EntryHash(entry); !ok || hash != entry["entry_hash"] {
			t.Fatalf("%v: %s", entry["entry_hash"], hash)
		}
	}
	if problems := chainProblems(chain); len(problems) != 0 {
		t.Fatalf("%v", problems)
	}
	rewritten := record(t, "conformance/suites/acs-binding/acs-invalid-chain-rewritten.json")["chain"].([]any)
	if len(chainProblems(rewritten)) == 0 {
		t.Fatal("a rewritten chain has no problem")
	}
}

func TestMCPTerminalStatesAndRefusals(t *testing.T) {
	states := []struct {
		response any
		state    string
	}{
		{nil, "unknown"},
		{map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "error": map[string]any{"code": json.Number("-1"), "message": "x"}}, "failed"},
		{map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "result": map[string]any{"isError": true}}, "failed"},
		{map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "result": map[string]any{}}, "succeeded"},
		{map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "result": map[string]any{"resultType": "input_required"}}, "unknown"},
		{map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "result": map[string]any{"resultType": nil}}, "unknown"},
	}
	for _, item := range states {
		if state := MCPTerminalState(item.response); state != item.state {
			t.Errorf("%v: %s, want %s", item.response, state, item.state)
		}
	}
	for name, cause := range map[string]string{
		"mcp-valid-denied-refused": "denied", "mcp-valid-held-refused": "held",
		"mcp-valid-challenged-refused": "challenged", "mcp-valid-decision-unavailable-refused": "decision-unavailable",
		"mcp-valid-decision-invalid-refused": "decision-invalid", "mcp-valid-authorization-expired-refused": "authorization-unusable",
		"mcp-valid-unmapped-tool-refused": "not-mapped", "mcp-valid-changed-tool-refused": "unreviewed-change",
	} {
		value := record(t, "conformance/suites/mcp-gateway/"+name+".json")
		refusal, refused := MCPRefusalCause(value)
		if !refused || refusal.Cause != cause {
			t.Errorf("%s: %v", name, refusal)
		}
		if code := member(value, "returned", "error", "code"); code != json.Number(strconv.FormatInt(MCPErrors[cause], 10)) {
			t.Errorf("%s: %v", name, code)
		}
	}
}

func TestOTelAttributesAndSeverity(t *testing.T) {
	object := record(t, "conformance/suites/otel-export/otel-valid-deny-response-exported.json")["object"].(map[string]any)
	if OTelSeverity(object) != SeverityWarn {
		t.Fatal(OTelSeverity(object))
	}
	attributes, err := OTelAttributes(object, nil, nil, nil)
	if err != nil || attributes["ecl.decision.outcome"] != "deny" || attributes["ecl.export.profile"] != OTelProfile {
		t.Fatalf("%v %v", attributes, err)
	}
	for name := range otelKeyed {
		if _, present := attributes[name]; present {
			t.Errorf("%s is exported without an export key (OE1-004)", name)
		}
	}
	key, err := NewExportKey("urn:example:export-key:test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := OTelAttributes(object, nil, &key, nil)
	if err != nil || keyed[OTelKeyID] != key.KeyID {
		t.Fatalf("%v %v", keyed, err)
	}
	digest, _ := key.Digest(object)
	unkeyed, _ := OTelUnkeyedDigests(object)
	if keyed[OTelObjectDigest] != digest || digest == unkeyed[OTelObjectDigest] || len(digest) != 64 {
		t.Fatalf("keyed digest %v, unkeyed %v", keyed[OTelObjectDigest], unkeyed[OTelObjectDigest])
	}
	for name := range keyed {
		if _, listed := OTelTable[name]; !listed {
			t.Errorf("%s is not in the attribute table", name)
		}
	}
	if OTelEventName(object) != "ecl.dcmp.decision_response" {
		t.Fatal(OTelEventName(object))
	}
}

// OE1-005, OE1-003 and OE1-008: declared identifiers, the observed time and the severity text.
func TestOTelDeclaredIdentifiersObservedTimeAndSeverityText(t *testing.T) {
	request := record(t, "conformance/suites/otel-export/otel-valid-request-exported.json")["object"].(map[string]any)
	plain, err := OTelAttributes(request, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name := range OTelDeclaredOnly {
		if _, present := plain[name]; present {
			t.Errorf("%s is exported without a declaration", name)
		}
	}
	declared, err := OTelAttributes(request, nil, nil, OTelDeclaredOnly)
	if err != nil || declared["ecl.actor.id"] != member(request, "actor", "id") {
		t.Fatalf("%v %v", declared, err)
	}
	for field, value := range map[string]string{"severityText": "WARNING", "observedTimeUnixNano": "0"} {
		changed := record(t, "conformance/suites/otel-export/otel-valid-deny-response-exported.json")
		changed["log_record"].(map[string]any)[field] = value
		found, err := Findings(changed)
		if err != nil || len(found) != 1 {
			t.Fatalf("%s: %v %v", field, found, err)
		}
	}
	long := record(t, "conformance/suites/otel-export/otel-valid-deny-response-exported.json")
	long["log_record"].(map[string]any)["observedTimeUnixNano"] = strings.Repeat("9", 5000)
	if found, err := Findings(long); err != nil || len(found) != 1 || found[0].RuleID != RuleOTelMatch {
		t.Fatalf("%v %v", found, err)
	}
}

// MG1-010 and MG1-012: a server error with a code of the error table is returned with -32603, and
// content outside the restricted profile is held in the encoded form.
func TestMCPReturnedForAndEncodedContent(t *testing.T) {
	answer := map[string]any{"jsonrpc": "2.0", "id": json.Number("7"), "error": map[string]any{"code": json.Number("-31004"), "message": "busy"}}
	returned := MCPReturnedFor(answer)
	if member(returned, "error", "code") != json.Number("-32603") || member(answer, "error", "code") != json.Number("-31004") || member(returned, "error", "message") != "busy" {
		t.Fatalf("%v %v", returned, answer)
	}
	other := map[string]any{"jsonrpc": "2.0", "id": json.Number("7"), "error": map[string]any{"code": json.Number("-32000"), "message": "busy"}}
	if !pyjson.Equal(MCPReturnedFor(other), other) {
		t.Fatal("a code outside the table is changed")
	}
	content := map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "params": map[string]any{"arguments": map[string]any{"weight": 0.5, "big": json.Number("9007199254740992")}}}
	held, err := EncodeContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if encoded, isEncodedForm := isEncoded(held); !isEncodedForm || len(encoded) != 1 {
		t.Fatalf("%v", held)
	}
	if decoded, err := DecodeContent(held); err != nil || !pyjson.Equal(decoded, content) {
		t.Fatalf("%v %v", decoded, err)
	}
	plain := map[string]any{"a": json.Number("1")}
	if same, err := EncodeContent(plain); err != nil || !pyjson.Equal(same, plain) {
		t.Fatalf("%v %v", same, err)
	}
	for _, bad := range []any{"not base64", "e30", "e31=", "WyJ4Il0=", "eyJhIjoxfQ==", "eyJhIjogMC41fQ==", "eyJhIjowLjUsImEiOjAuNX0=", json.Number("1")} {
		var refusal *contentError
		if _, err := DecodeContent(map[string]any{"rfc8785": bad}); !errors.As(err, &refusal) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	forwarded := record(t, "conformance/suites/mcp-gateway/mcp-valid-forwarded-on-admit.json")
	odd := map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "method": []any{"tools/call", 0.5}, "params": map[string]any{"x": 0.5}}
	encoded, err := EncodeContent(odd)
	if err != nil {
		t.Fatal(err)
	}
	forwarded["call"] = encoded
	forwarded["forwarded"].(map[string]any)["request"] = encoded
	// The record schema refuses a method that is not a string in either form (MG1-012);
	// MCPRefusalCause reads the decoded record without that check.
	found, err := Findings(forwarded)
	if err != nil || fmt.Sprint(rulesAndPaths(found)) != "[ecl.error.schema-invalid.v1 /call ecl.error.schema-invalid.v1 /forwarded/request]" {
		t.Fatalf("%v %v", found, err)
	}
	delete(forwarded, "forwarded")
	if refusal, refused := MCPRefusalCause(forwarded); !refused || refusal.Cause != "not-mapped" {
		t.Fatalf("%v", refusal)
	}
}

// AC1-012: a DCMP-2 rule that a held message fails is reported once, at
// the message's place in the record.
func TestMessageRuleReportedOnceAtTheMessage(t *testing.T) {
	value := record(t, "conformance/suites/acs-binding/acs-invalid-request-negative-debit.json")
	found, err := Findings(value)
	if err != nil || fmt.Sprint(found) != "[{ecl.rule.budget-debit-non-negative.v1 /request "+found[0].Detail+"}]" {
		t.Fatalf("%v %v", found, err)
	}
	response := value["response"].(map[string]any)
	extensions := response["extensions"].([]any)
	response["extensions"] = append(extensions, extensions[0], extensions[0])
	var paths []string
	for _, item := range messageFindings(value, []string{"response"}) {
		if item.RuleID == "ecl.rule.extension-identifiers-unique.v1" {
			paths = append(paths, item.Path)
		}
	}
	if fmt.Sprint(paths) != "[/response]" {
		t.Fatalf("%v", paths)
	}
}

// MG1-004: a request with a member other than jsonrpc, id, method and
// params, or a number in id or params beyond 2^53 - 1 in magnitude, binds to no decision.
func TestMCPUnboundCall(t *testing.T) {
	arguments := map[string]any{"n": []any{1e300, json.Number("-9007199254740991"), true, map[string]any{"k~/": json.Number("-9007199254740993")}}}
	call := map[string]any{"jsonrpc": "2.0", "id": json.Number("9007199254740992"), "method": "tools/call", "params": map[string]any{"name": "x", "arguments": arguments}}
	for name, value := range map[string]any{"z": json.Number("1"), "a/b": json.Number("2"), "~x": json.Number("3")} {
		call[name] = value
	}
	expected := "[{/call/a~1b no decision binds this member} {/call/z no decision binds this member} {/call/~0x no decision binds this member} " +
		"{/call/id the number's magnitude is greater than 2^53 - 1} {/call/params/arguments/n/0 the number's magnitude is greater than 2^53 - 1} " +
		"{/call/params/arguments/n/3/k~0~1 the number's magnitude is greater than 2^53 - 1}]"
	if found := fmt.Sprint(MCPUnboundProblems(call, "/call")); found != expected {
		t.Fatalf("%s", found)
	}
	forwarded := record(t, "conformance/suites/mcp-gateway/mcp-valid-forwarded-on-admit.json")
	delete(forwarded, "forwarded")
	if refusal, refused := MCPRefusalCause(forwarded); refused {
		t.Fatalf("%v", refusal)
	}
	forwarded["call"].(map[string]any)["trace"] = "x"
	if refusal, refused := MCPRefusalCause(forwarded); !refused || refusal.Cause != "not-mapped" {
		t.Fatalf("%v", refusal)
	}
}

// Every binding vector: the record schema first, then the profile's rules, with the vector's
// primary and secondary findings exactly.
func TestEveryBindingVector(t *testing.T) {
	rules := map[string]bool{}
	for _, rule := range Rules() {
		rules[rule] = true
	}
	if len(rules) != 30 || len(Rules()) != 30 {
		t.Fatalf("%d rules", len(rules))
	}
	// Each DCMP-2 message that a record holds is held to the semantic rules of DCMP-2 as well.
	messageRules := registry.RulesApplyingTo("DCMP-2")
	checked := 0
	for _, name := range []string{"aarm-binding", "acs-binding", "binding-basis", "mcp-gateway", "otel-export", "oauth-authority"} {
		manifest := vectors.Suite(t, name)
		var keys map[string]ExportKey
		if manifest.ExportKeysPath != "" {
			var err error
			if keys, err = LoadExportKeys(vectors.Read(t, manifest.ExportKeysPath)); err != nil || len(keys) == 0 {
				t.Fatalf("%s: %v", manifest.ExportKeysPath, err)
			}
		}
		for _, vector := range manifest.Vectors {
			if vector.Stage != "binding" {
				continue
			}
			value, err := strict.Parse(vectors.Read(t, vector.Path))
			if err != nil {
				t.Fatalf("%s: %v", vector.ID, err)
			}
			findings, err := EvaluateRecordWithKeys(vector.Schema, value, keys)
			if err != nil {
				t.Fatalf("%s: %v", vector.ID, err)
			}
			seen := map[string]bool{}
			found := []string{}
			for _, item := range findings {
				if !seen[item.RuleID] {
					seen[item.RuleID] = true
					found = append(found, item.RuleID)
				}
			}
			sort.Strings(found)
			expected := []string{}
			if vector.Expected == "fail" {
				expected = append(append(expected, vector.Primary), vector.Secondary...)
				sort.Strings(expected)
			}
			if strings.Join(found, " ") != strings.Join(expected, " ") {
				t.Errorf("%s: %v, want %v", vector.ID, found, expected)
			}
			if vector.Expected == "fail" && vector.Primary != schemaInvalid {
				for _, rule := range found {
					// A record's embedded decision response is held to DCMP2-053 under the
					// response's own rule, which is not one of the profiles' (AB1-013, AC1-012,
					// MG1-007), and each DCMP-2 message it holds to the rules of DCMP-2.
					if !rules[rule] && rule != ruleOneWay && !messageRules[rule] {
						t.Errorf("%s: %s is not a binding rule", vector.ID, rule)
					}
				}
			}
			checked++
		}
	}
	if checked < 130 {
		t.Fatalf("only %d vectors", checked)
	}
	findings, err := Findings(map[string]any{"schema_version": "something else"})
	if err != nil || len(findings) != 1 || findings[0].RuleID != schemaInvalid {
		t.Fatalf("%v %v", findings, err)
	}
}

// An export key file is exactly an ecl_otel_export_keys_v1 document: canonical base64 keys of at
// least 32 bytes under distinct identifiers of 1 to 256 characters (OE1-010).
func TestExportKeyFiles(t *testing.T) {
	key := strings.Repeat("A", 43) + "="
	valid := `{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"` + key + `"}]}`
	keys, err := LoadExportKeys([]byte(valid))
	if err != nil || len(keys["urn:k"].Key) != 32 {
		t.Fatalf("%v %v", keys, err)
	}
	for _, document := range []string{
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[]}`,
		`{"schema_version":"ecl_otel_export_keys_v0","keys":[{"key_id":"urn:k","key":"` + key + `"}]}`,
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"` + key + `"}],"x":1}`,
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"` + key + `","x":1}]}`,
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"` + strings.Repeat("A", 42) + `=="}]}`,
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"` + strings.Repeat("A", 42) + `B="}]}`,
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"","key":"` + key + `"}]}`,
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":1,"key":"` + key + `"}]}`,
		`{"schema_version":"ecl_otel_export_keys_v1","keys":[{"key_id":"urn:k","key":"` + key + `"},{"key_id":"urn:k","key":"` + key + `"}]}`,
		`[]`,
	} {
		if _, err := LoadExportKeys([]byte(document)); !errors.Is(err, ErrExportKeys) {
			t.Errorf("%s: %v", document, err)
		}
	}
}

// AB1-013 and AC1-012: a record's inputs, without the profile's member, equal the entries of the
// decision basis of its response.
func TestBasisProblems(t *testing.T) {
	digest := func(fill string) map[string]any {
		return map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": strings.Repeat(fill, 64)}
	}
	entry := func(name, class, fill string) map[string]any {
		return map[string]any{
			"input": "urn:example:input:" + name, "class": class, "required": false, "status": "available", "effect": "none",
			"reference": map[string]any{"uri": "urn:example:value:" + name, "digest": digest(fill)},
		}
	}
	with := func(value map[string]any, key string, member any) map[string]any {
		out := deepCopy(value).(map[string]any)
		if member == nil {
			delete(out, key)
		} else {
			out[key] = member
		}
		return out
	}
	record := func(inputs []any, bases ...[]any) map[string]any {
		var extensions []any
		for _, inputsOfBasis := range bases {
			extensions = append(extensions, map[string]any{"id": decisionBasis, "version": json.Number("1"), "critical": true,
				"value": map[string]any{"register": map[string]any{"uri": "urn:example:register:bindings", "digest": digest("9")}, "inputs": inputsOfBasis}})
		}
		return map[string]any{"inputs": inputs, "response": map[string]any{"extensions": extensions}}
	}
	text := func(found []problem) string {
		var out []string
		for _, item := range found {
			out = append(out, item.path+" "+item.message)
		}
		return strings.Join(out, "; ")
	}
	policy, score := entry("policy", "verifiable", "a"), entry("score", "judgment", "b")
	unavailable := with(with(entry("balance", "verifiable", "a"), "status", "unavailable"), "reference", nil)
	noArray := record([]any{policy}, []any{policy})
	noArray["response"].(map[string]any)["extensions"].([]any)[0].(map[string]any)["value"] = map[string]any{"inputs": "policy"}
	cases := []struct {
		record map[string]any
		want   string
	}{
		{record([]any{policy, with(score, "aarm_requirement", "R3")}, []any{score, policy}), ""},
		{record([]any{policy, entry("score", "judgment", "a")}, []any{entry("policy", "verifiable", "c"), with(entry("score", "verifiable", "a"), "effect", "restricts")}),
			"/inputs/0/reference the reference is not the one the response records; /inputs/1/class the class is not the one the response records; /inputs/1/effect the effect is not the one the response records"},
		{record([]any{deepCopy(unavailable)}, []any{unavailable}), ""},
		{record([]any{entry("balance", "verifiable", "a")}, []any{unavailable}),
			"/inputs/0/reference the reference is not the one the response records; /inputs/0/status the status is not the one the response records"},
		{record([]any{policy}, []any{with(policy, "source", "urn:example:system-of-record:payments")}), "/inputs/0/source the source is not the one the response records"},
		{record([]any{policy, entry("score", "verifiable", "a")}, []any{policy, entry("other", "verifiable", "a")}),
			"/inputs/1/input the response's decision basis does not record this input; /response/extensions/0/value/inputs/1/input the record does not list this input"},
		{record([]any{policy}, []any{policy, policy}), "/inputs/0/input the response's decision basis records this input more than once"},
		{record([]any{policy, policy}, []any{policy}), "/inputs/1/input the record lists this input more than once"},
		{record([]any{}), ""},
		{record([]any{policy}), "/inputs/0/input the response's decision basis does not record this input"},
		{record([]any{policy}, []any{policy}, []any{policy}), "/response/extensions the response records its decision basis more than once"},
		{noArray, "/response/extensions/0/value/inputs the decision basis has no inputs array"},
		{record([]any{}, []any{map[string]any{"class": "verifiable"}}), "/response/extensions/0/value/inputs/0 the decision-basis entry names no input"},
		{map[string]any{"inputs": []any{policy}}, ""},
		// A boolean never equals a number, nor an integer a float, as in the reference's comparison.
		{record([]any{with(policy, "required", json.Number("0"))}, []any{policy}), "/inputs/0/required the required is not the one the response records"},
		{record([]any{with(policy, "required", json.Number("1"))}, []any{with(policy, "required", json.Number("1.0"))}), "/inputs/0/required the required is not the one the response records"},
	}
	for index, item := range cases {
		if got := text(basisProblems(item.record, "aarm_requirement")); got != item.want {
			t.Errorf("case %d: %q, want %q", index, got, item.want)
		}
	}
}

// bindingVector is the parsed record of one vector of a binding suite.
func bindingVector(t *testing.T, suite, identifier string) map[string]any {
	t.Helper()
	for _, vector := range vectors.Suite(t, suite).Vectors {
		if vector.ID != identifier {
			continue
		}
		value, err := strict.Parse(vectors.Read(t, vector.Path))
		if err != nil {
			t.Fatalf("%s: %v", identifier, err)
		}
		return value.(map[string]any)
	}
	t.Fatalf("no vector %s in %s", identifier, suite)
	return nil
}

// rulesAndPaths is the sorted set of "rule path" of the findings.
func rulesAndPaths(found []Finding) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range found {
		key := item.RuleID + " " + item.Path
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// reparsed is a deep copy of a parsed record.
func reparsed(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := JCS(value)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := strict.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return copied.(map[string]any)
}

// AC1-004: a deterministic Guardian decision that a hook point carried is never verifiable; an
// agent or composite evaluator, or one that is not stated, makes a decision judgment.
func TestACSHookCarriedGuardianDecisionIsNeverVerifiable(t *testing.T) {
	cases := []struct {
		evaluator, channel any
		carried            []any
		want               string
	}{
		{"deterministic", "hook", nil, "actor_supplied"},
		{"deterministic", "hook", []any{"verifiable"}, "actor_supplied"},
		{"deterministic", nil, nil, "actor_supplied"},
		{"deterministic", "direct", nil, "verifiable"},
		{"deterministic", "signed", []any{"verifiable"}, "verifiable"},
		{"deterministic", "signed", []any{"judgment"}, "judgment"},
	}
	for _, channel := range ACSChannels {
		cases = append(cases, struct {
			evaluator, channel any
			carried            []any
			want               string
		}{nil, channel, nil, "judgment"}, struct {
			evaluator, channel any
			carried            []any
			want               string
		}{"composite", channel, nil, "judgment"})
	}
	for _, item := range cases {
		if got := GuardianClass(item.evaluator, item.carried, item.channel); got != item.want {
			t.Errorf("%v %v %v: %s, want %s", item.evaluator, item.channel, item.carried, got, item.want)
		}
	}
	valid := bindingVector(t, "acs-binding", "acs-valid-allow-released")
	if found := checkACS(valid); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	signed := reparsed(t, valid)
	signed["guardian"].(map[string]any)["channel"] = "signed"
	if found := checkACS(signed); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	hooked := reparsed(t, valid)
	hooked["guardian"].(map[string]any)["channel"] = "hook"
	if got := rulesAndPaths(checkACS(hooked)); strings.Join(got, ",") != RuleACSJudgment+" /inputs/1/class" {
		t.Fatalf("%v", got)
	}
}

// AC1-004: a response that records the Guardian decision marks exactly one input as it.
func TestACSResponseThatRecordsTheGuardianDecisionMarksOneInput(t *testing.T) {
	valid := bindingVector(t, "acs-binding", "acs-valid-allow-released")
	unmarked := reparsed(t, valid)
	delete(unmarked["inputs"].([]any)[1].(map[string]any), "guardian")
	if got := rulesAndPaths(checkACS(unmarked)); strings.Join(got, ",") != RuleACSJudgment+" /inputs" {
		t.Fatalf("%v", got)
	}
	twice := reparsed(t, valid)
	twice["inputs"].([]any)[0].(map[string]any)["guardian"] = true
	found := strings.Join(rulesAndPaths(checkACS(twice)), ",")
	if !strings.Contains(found, RuleACSJudgment+" /inputs/1/guardian") {
		t.Fatalf("%v", found)
	}
}

// AB1-006: the judgment-source role lists the AARM decision exactly once, as an R4 input.
func TestAARMJudgmentSourceListsTheAARMDecisionOnce(t *testing.T) {
	if found := checkAARM(bindingVector(t, "aarm-binding", "aarm-valid-judgment-source-admit")); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	unlabelled := bindingVector(t, "aarm-binding", "aarm-invalid-judgment-source-decision-unlabelled")
	if got := rulesAndPaths(checkAARM(unlabelled)); strings.Join(got, ",") != RuleAARMJudgment+" /inputs" {
		t.Fatalf("%v", got)
	}
	unlabelled["role"] = "decision-layer"
	if found := checkAARM(unlabelled); len(found) != 0 {
		t.Fatalf("%v", found)
	}
}

// MG1-004 and MG1-005: the decision request binds the call's complete params, and the forward
// is exactly the call.
func TestMCPForwardIsExactlyTheCallTheAdmitBinds(t *testing.T) {
	valid := bindingVector(t, "mcp-gateway", "mcp-valid-forwarded-on-admit")
	if found := checkMCP(valid); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	forwardedRequest := func(value map[string]any) map[string]any {
		return value["forwarded"].(map[string]any)["request"].(map[string]any)
	}
	task := reparsed(t, valid)
	forwardedRequest(task)["params"].(map[string]any)["task"] = map[string]any{"ttl": json.Number("86400000")}
	if got := rulesAndPaths(checkMCP(task)); strings.Join(got, ",") != RuleMCPForward+" /forwarded/request/params" {
		t.Fatalf("%v", got)
	}
	added := reparsed(t, valid)
	forwardedRequest(added)["trace"] = "gateway-1"
	if got := rulesAndPaths(checkMCP(added)); strings.Join(got, ",") != RuleMCPForward+" /forwarded/request" {
		t.Fatalf("%v", got)
	}
	unbound := reparsed(t, valid)
	for _, holder := range []map[string]any{unbound["call"].(map[string]any), forwardedRequest(unbound)} {
		holder["params"].(map[string]any)["_meta"].(map[string]any)["io.example/effect-mode"] = "live-production"
	}
	want := []string{RuleMCPForward + " /forwarded/request/params", RuleMCPRequest + " /decision_request/extensions"}
	sort.Strings(want)
	if got := rulesAndPaths(checkMCP(unbound)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", got)
	}
}

// AB1-013, AC1-012 and MG1-007: an embedded response is held to DCMP2-053 under the response's
// own rule, at the paths at which the response alone fails it.
func TestEmbeddedResponseIsHeldToTheOneWayRule(t *testing.T) {
	cases := []struct {
		suite, identifier string
		check             func(map[string]any) []Finding
	}{
		{"binding-basis", "aarm-basis-invalid-admit-required-input-unavailable", checkAARM},
		{"binding-basis", "aarm-basis-invalid-verifiable-derived-from-judgment", checkAARM},
		{"binding-basis", "aarm-basis-invalid-modification-admitted-on-judgment", checkAARM},
		{"binding-basis", "acs-basis-invalid-admit-required-input-unavailable", checkACS},
		{"mcp-gateway", "mcp-invalid-admit-on-judgment-forwarded", checkMCP},
		{"binding-basis", "aarm-basis-invalid-admit-after-verifiable-only-deny", checkAARM},
		{"binding-basis", "aarm-basis-invalid-input-obtained-after-decision", checkAARM},
		{"binding-basis", "acs-basis-invalid-received-after-decision", checkACS},
	}
	for _, item := range cases {
		value := bindingVector(t, item.suite, item.identifier)
		found := item.check(value)
		paths := map[string]bool{}
		for _, finding := range found {
			if finding.RuleID != ruleOneWay {
				t.Fatalf("%s: %v", item.identifier, finding)
			}
			paths[finding.Path] = true
		}
		// The paths at which the semantic rules fail each response on its own, below the response.
		expected := map[string]bool{}
		for _, path := range [][]string{{"response"}, {"modification_response"}, {"decision", "response"}} {
			response, isObject := object(value, path...)
			if !isObject {
				continue
			}
			alone, err := semantic.Validate(response, semantic.Registered())
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range alone {
				if finding.RuleID == ruleOneWay {
					expected["/"+strings.Join(path, "/")+finding.Path] = true
				}
			}
		}
		if len(expected) == 0 || len(paths) != len(expected) {
			t.Fatalf("%s: %v, want %v", item.identifier, paths, expected)
		}
		for path := range expected {
			if !paths[path] {
				t.Fatalf("%s: %s missing", item.identifier, path)
			}
		}
	}
}

// AC1-012 and MG1-007: the response is held to DCMP2-053 with the request that the record holds,
// so an input recorded as verifiable whose source is the requesting actor is refused under the
// one-way rule, at the paths at which an evidence verifier refuses it, while the response alone
// passes the rule.
func TestEmbeddedResponseIsCheckedWithTheRecordsRequest(t *testing.T) {
	cases := []struct {
		suite, identifier string
		check             func(map[string]any) []Finding
		request           string
		response          []string
	}{
		{"binding-basis", "acs-basis-invalid-verifiable-input-from-actor", checkACS, "request", []string{"response"}},
		{"mcp-gateway", "mcp-invalid-verifiable-input-from-actor", checkMCP, "decision_request", []string{"decision", "response"}},
	}
	for _, item := range cases {
		value := bindingVector(t, item.suite, item.identifier)
		found := item.check(value)
		paths := map[string]bool{}
		for _, finding := range found {
			if finding.RuleID != ruleOneWay {
				t.Fatalf("%s: %v", item.identifier, finding)
			}
			paths[finding.Path] = true
		}
		response, _ := object(value, item.response...)
		request, _ := object(value, item.request)
		alone, err := semantic.Validate(response, semantic.Registered())
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range alone {
			if finding.RuleID == ruleOneWay {
				t.Fatalf("%s: the response alone fails the rule: %v", item.identifier, finding)
			}
		}
		expected := map[string]bool{}
		for index, raw := range array(response, "extensions") {
			entry, _ := raw.(map[string]any)
			value, isValue := entry["value"].(map[string]any)
			if entry["id"] != decisionBasis || !isValue {
				continue
			}
			for _, problem := range evidence.ActorSourceProblems(value, request) {
				expected["/"+strings.Join(item.response, "/")+"/extensions/"+strconv.Itoa(index)+"/value"+problem[0]] = true
			}
		}
		if len(expected) == 0 || len(paths) != len(expected) {
			t.Fatalf("%s: %v, want %v", item.identifier, paths, expected)
		}
		for path := range expected {
			if !paths[path] {
				t.Fatalf("%s: %s missing", item.identifier, path)
			}
		}
	}
}

// basisValue is the value of the decision basis that a response of a parsed record carries.
func basisValue(t *testing.T, response any) map[string]any {
	t.Helper()
	for _, item := range array(response, "extensions") {
		if entry, isEntry := item.(map[string]any); isEntry && entry["id"] == decisionBasis {
			return entry["value"].(map[string]any)
		}
	}
	t.Fatal("no decision basis")
	return nil
}

// AB1-013 and AC1-012: the decision basis of the modification
// response carries the register reference of the response's basis, member for member, and records
// the record's inputs with their declarations; the status, effect and reference are the new
// decision's.
func TestModificationBasisProblems(t *testing.T) {
	valid := bindingVector(t, "acs-binding", "acs-valid-modify-new-request")
	if found := modificationBasisProblems(valid); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	prefix := "/modification_response/extensions/0/value"
	change := func(edit func(inputs []any, basis map[string]any)) string {
		value := reparsed(t, valid)
		basis := basisValue(t, value["modification_response"])
		edit(basis["inputs"].([]any), basis)
		var paths []string
		for _, item := range modificationBasisProblems(value) {
			paths = append(paths, item.path)
		}
		return strings.Join(paths, ",")
	}
	cases := []struct {
		edit func(inputs []any, basis map[string]any)
		want string
	}{
		{func(inputs []any, _ map[string]any) {
			inputs[0].(map[string]any)["effect"] = "none"
			inputs[1].(map[string]any)["effect"] = "supports"
			inputs[0].(map[string]any)["input"] = "URN:example:input:records-policy"
			inputs[1].(map[string]any)["source"] = "URN:Example:source:acs-guardian-decision"
		}, ""},
		{func(inputs []any, _ map[string]any) { inputs[1].(map[string]any)["class"] = "judgment" }, prefix + "/inputs/1/class"},
		{func(inputs []any, _ map[string]any) { inputs[0].(map[string]any)["required"] = false }, prefix + "/inputs/0/required"},
		{func(inputs []any, _ map[string]any) {
			inputs[0].(map[string]any)["source"] = "urn:example:source:elsewhere"
		}, prefix + "/inputs/0/source"},
		{func(inputs []any, _ map[string]any) {
			inputs[1].(map[string]any)["derived_from"] = []any{"urn:example:input:records-policy"}
		}, prefix + "/inputs/1/derived_from"},
		{func(inputs []any, _ map[string]any) { delete(inputs[1].(map[string]any), "derived_from") }, ""},
		{func(_ []any, basis map[string]any) { basis["inputs"] = basis["inputs"].([]any)[:1] }, prefix + "/inputs"},
		{func(_ []any, basis map[string]any) {
			basis["register"].(map[string]any)["version"] = "2026-10-01"
		}, prefix + "/register"},
		{func(_ []any, basis map[string]any) {
			delete(basis["register"].(map[string]any), "version")
		}, prefix + "/register"},
		{func(_ []any, basis map[string]any) {
			basis["register"].(map[string]any)["media_type"] = "application/json"
		}, prefix + "/register"},
	}
	for index, item := range cases {
		if got := change(item.edit); got != item.want {
			t.Errorf("case %d: %q, want %q", index, got, item.want)
		}
	}
	for _, item := range []struct{ suite, identifier, rule string }{
		{"acs-binding", "acs-invalid-modification-upgrades-session-context", RuleACSBasis},
		{"acs-binding", "acs-invalid-modification-drops-required-input", RuleACSBasis},
		{"acs-binding", "acs-invalid-modification-records-other-inputs", RuleACSBasis},
		{"aarm-binding", "aarm-invalid-modification-drops-required-input", RuleAARMBasis},
		{"acs-binding", "acs-invalid-modify-other-action-class", RuleACSModification},
		{"acs-binding", "acs-invalid-modify-other-target", RuleACSModification},
		{"aarm-binding", "aarm-invalid-modify-other-operation", RuleAARMModification},
		{"aarm-binding", "aarm-invalid-modify-other-actor", RuleAARMModification},
	} {
		found, err := Findings(bindingVector(t, item.suite, item.identifier))
		if err != nil {
			t.Fatal(err)
		}
		rules := map[string]bool{}
		for _, finding := range found {
			rules[finding.RuleID] = true
		}
		if len(rules) != 1 || !rules[item.rule] {
			t.Errorf("%s: %v", item.identifier, rules)
		}
	}
}

// AB1-004 and AC1-005: only a modification has a new request. A record of any other decision, or
// of a decision failure, that holds the new request of a modification, or its response alone, is
// refused under the modification rule, whatever the other rules find; the corpus vectors of this
// case have that rule as their only finding.
func TestNewRequestOnlyAfterAModification(t *testing.T) {
	held := [][]string{{"modification_request", "modification_response"}, {"modification_request"}, {"modification_response"}}
	for _, profile := range []struct {
		suite, modify, rule string
		others              []string
	}{
		{"acs-binding", "acs-valid-modify-new-request", RuleACSModification, []string{
			"acs-valid-allow-released", "acs-valid-deny", "acs-valid-ask-allow-timeout-challenged",
			"acs-valid-defer-held", "acs-valid-decision-failure-denied", "acs-valid-late-decision-denied",
		}},
		{"aarm-binding", "aarm-valid-modify-new-request", RuleAARMModification, []string{
			"aarm-valid-allow-released", "aarm-valid-deny-recorded", "aarm-valid-defer-held",
			"aarm-valid-step-up-challenged", "aarm-valid-judgment-source-admit",
		}},
	} {
		modified := bindingVector(t, profile.suite, profile.modify)
		for _, identifier := range profile.others {
			value := bindingVector(t, profile.suite, identifier)
			if found := newRequestProblems(value); len(found) != 0 {
				t.Fatalf("%s: %v", identifier, found)
			}
			for _, members := range held {
				changed := reparsed(t, value)
				for _, name := range members {
					changed[name] = reparsed(t, modified[name].(map[string]any))
				}
				found, err := Findings(changed)
				if err != nil {
					t.Fatal(err)
				}
				paths := map[string]bool{}
				for _, finding := range found {
					if finding.RuleID == profile.rule {
						paths[finding.Path] = true
					}
				}
				if len(paths) != len(members) {
					t.Errorf("%s %v: %v", identifier, members, paths)
				}
				for _, name := range members {
					if !paths["/"+name] {
						t.Errorf("%s %v: no finding at /%s", identifier, members, name)
					}
				}
			}
		}
	}
	for _, item := range []struct{ suite, identifier, rule string }{
		{"acs-binding", "acs-invalid-new-request-without-modify", RuleACSModification},
		{"aarm-binding", "aarm-invalid-new-request-without-modify", RuleAARMModification},
	} {
		value := bindingVector(t, item.suite, item.identifier)
		found, err := Findings(value)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, finding := range found {
			got = append(got, finding.RuleID+" "+finding.Path)
		}
		want := []string{item.rule + " /modification_request", item.rule + " /modification_response"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: %v", item.identifier, got)
		}
		for _, name := range []string{"modification_request", "modification_response", "release"} {
			delete(value, name)
		}
		if found, err := Findings(value); err != nil || len(found) != 0 {
			t.Errorf("%s without the new request: %v %v", item.identifier, found, err)
		}
	}
}

// AB1-004 and AC1-005: the new request of a modification keeps the
// original's members, and in its action changes only action_id, parameters and parameters_digest.
func TestModificationRequestDescribesTheOriginalAction(t *testing.T) {
	valid := bindingVector(t, "acs-binding", "acs-valid-modify-new-request")
	original := valid["request"].(map[string]any)
	modified := valid["modification_request"].(map[string]any)
	parameters := member(modified, "action", "parameters")
	if found := modificationProblems(original, modified, parameters); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	for _, item := range []struct {
		member, name string
		value        any
		want         string
	}{
		{"action", "operation", "records.delete", "modification_request/action/operation"},
		{"action", "action_class", "ecl.action.financial-transfer.v1", "modification_request/action/action_class"},
		{"action", "risk_class", "ecl.risk.low.v1", "modification_request/action/risk_class"},
		{"actor", "id", "urn:example:agent:other", "modification_request/actor"},
		{"subject", "id", "urn:example:tenant:other", "modification_request/subject"},
		{"authority_request", "requested_validity_seconds", json.Number("3600"), "modification_request/authority_request"},
		{"integrity_policy", "threshold", json.Number("2"), "modification_request/integrity_policy"},
	} {
		changed := reparsed(t, modified)
		changed[item.member].(map[string]any)[item.name] = item.value
		var paths []string
		for _, found := range modificationProblems(original, changed, parameters) {
			paths = append(paths, found.path)
		}
		if strings.Join(paths, ",") != item.want {
			t.Errorf("%s %s: %v", item.member, item.name, paths)
		}
	}
	own := reparsed(t, modified)
	own["issued_at"] = "2026-09-30T09:00:00.160000Z"
	own["extensions"] = []any{}
	own["workflow"].(map[string]any)["sequence"] = json.Number("9")
	if found := modificationProblems(original, own, parameters); len(found) != 0 {
		t.Fatalf("%v", found)
	}
}

// AC1-004: a Guardian decision's derived_from names an input of the record
// in another case form, compared as input names are.
func TestACSGuardianDerivedFromComparedAsInputNamesAre(t *testing.T) {
	valid := bindingVector(t, "acs-binding", "acs-valid-guardian-derived-from-case-variant")
	if found := checkACS(valid); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	unknown := reparsed(t, valid)
	for _, holder := range []any{unknown["inputs"].([]any)[1], basisValue(t, unknown["response"])["inputs"].([]any)[1]} {
		holder.(map[string]any)["derived_from"] = []any{"URN:example:input:records-polic"}
	}
	found := false
	for _, item := range rulesAndPaths(checkACS(unknown)) {
		found = found || item == RuleACSJudgment+" /inputs/1/derived_from/0"
	}
	if !found {
		t.Fatalf("%v", rulesAndPaths(checkACS(unknown)))
	}
}

// MG1-007: a response that the gateway refused and keeps as evidence is not
// held to DCMP-2's semantic rules; an answered one is.
func TestMCPRefusedResponseKeptAsEvidence(t *testing.T) {
	held := bindingVector(t, "mcp-gateway", "mcp-valid-decision-invalid-holds-refused-response")
	if found := checkMCP(held); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	answered := bindingVector(t, "mcp-gateway", "mcp-valid-forwarded-on-admit")
	response := answered["decision"].(map[string]any)["response"].(map[string]any)
	extensions := append(response["extensions"].([]any), map[string]any{"id": "ecl.ext.outcome-reason.v1", "version": json.Number("1"), "critical": false, "value": map[string]any{"unexpected": true}})
	sort.Slice(extensions, func(i, j int) bool {
		return extensions[i].(map[string]any)["id"].(string) < extensions[j].(map[string]any)["id"].(string)
	})
	response["extensions"] = extensions
	refused := false
	for _, item := range checkMCP(answered) {
		refused = refused || item.RuleID == "ecl.rule.extension-value-valid.v1"
	}
	if !refused {
		t.Fatal("an answered response is not held to DCMP-2")
	}
}

// MG1-012: content that holds a double with an integral value is held as
// RFC 8785 reads it, an integer, as every decoder reads it back.
func TestEncodeContentDecidesOnTheRFC8785Form(t *testing.T) {
	for _, number := range []float64{1.0, math.Copysign(0, -1), 100.0, 4503599627370496.0} {
		content := map[string]any{"jsonrpc": "2.0", "id": json.Number("1"), "params": map[string]any{"weight": number}}
		held, err := EncodeContent(content)
		if err != nil {
			t.Fatal(err)
		}
		if _, encoded := isEncoded(held); encoded {
			t.Fatalf("%v is held encoded: %v", number, held)
		}
		weight := member(held, "params", "weight")
		if numberKind(weight) != "int" {
			t.Fatalf("%v is held as %T %v", number, weight, weight)
		}
		if decoded, err := DecodeContent(held); err != nil || !pyjson.Equal(decoded, held) {
			t.Fatalf("%v %v", decoded, err)
		}
	}
	fraction, err := EncodeContent(map[string]any{"weight": 0.5})
	if err != nil {
		t.Fatal(err)
	}
	if _, encoded := isEncoded(fraction); !encoded {
		t.Fatalf("%v", fraction)
	}
}

// TestModificationEndingInDenyWithNoNewRequest: a modification that changes
// the target as the deployment derives it ends in deny of the original with no new request
// (AB1-004, AC1-005); its record holds neither a new request nor a release and is valid, while a
// modification response without its new request is still refused.
func TestModificationEndingInDenyWithNoNewRequest(t *testing.T) {
	for _, item := range []struct{ suite, identifier, rule string }{
		{"acs-binding", "acs-valid-modify-new-request", RuleACSModification},
		{"aarm-binding", "aarm-valid-modify-new-request", RuleAARMModification},
	} {
		value := bindingVector(t, item.suite, item.identifier)
		response := value["modification_response"]
		for _, name := range []string{"modification_request", "modification_response", "release"} {
			delete(value, name)
		}
		found, err := Findings(value)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 0 {
			t.Errorf("%s: %v", item.identifier, found)
		}
		value["modification_response"] = response
		found, err = Findings(value)
		if err != nil {
			t.Fatal(err)
		}
		refused := false
		for _, finding := range found {
			refused = refused || (finding.RuleID == item.rule && finding.Path == "/modification_response")
		}
		if !refused {
			t.Errorf("%s: a lone modification response is not refused: %v", item.identifier, found)
		}
	}
}

// TestModifiedParametersAreTheSameJSON: the new request carries the
// modified parameters as the same JSON (AB1-004, AC1-005), so a number where the modification
// sets a boolean is not the modified parameters.
func TestModifiedParametersAreTheSameJSON(t *testing.T) {
	original := map[string]any{"message_id": "urn:example:message:o", "action": map[string]any{"parameters": map[string]any{"a": 1.0}}}
	for _, pair := range [][2]any{{true, 1.0}, {false, 0.0}, {1.0, true}} {
		modified := map[string]any{"message_id": "urn:example:message:m", "action": map[string]any{"parameters": map[string]any{"dry_run": pair[1]}}}
		found := false
		for _, item := range modificationProblems(original, modified, map[string]any{"dry_run": pair[0]}) {
			found = found || item.path == "modification_request/action/parameters"
		}
		if !found {
			t.Errorf("%v %v: not refused", pair[0], pair[1])
		}
	}
}

// TestMCPRequestAndForwardAreComparedAsTheSameJSON: the decision request's
// parameters are the call's arguments, and the forwarded request is what the admitted request
// binds, each as the same JSON values (MG1-004, MG1-005), where Python's == equates true with 1.
func TestMCPRequestAndForwardAreComparedAsTheSameJSON(t *testing.T) {
	valid := bindingVector(t, "mcp-gateway", "mcp-valid-forwarded-on-admit")
	rebound := func(value map[string]any) map[string]any {
		request := value["decision_request"].(map[string]any)
		response := value["decision"].(map[string]any)["response"].(map[string]any)
		for _, item := range response["workflow"].(map[string]any)["causal_predecessors"].([]any) {
			if entry := item.(map[string]any); entry["relation"] == "ecl.relation.responds-to.v1" {
				entry["digest"] = digestOf(request)
			}
		}
		response["authorization"].(map[string]any)["scope_digest"] = digestOf(map[string]any{"request_id": request["message_id"], "action": request["action"]})
		return value
	}
	bindingOf := func(value map[string]any) map[string]any {
		for _, item := range value["decision_request"].(map[string]any)["extensions"].([]any) {
			if entry := item.(map[string]any); entry["id"] == mcpBinding {
				return entry["value"].(map[string]any)
			}
		}
		t.Fatal("no mcp-binding")
		return nil
	}
	contains := func(found []string, want string) bool {
		for _, item := range found {
			if item == want {
				return true
			}
		}
		return false
	}
	value := reparsed(t, valid)
	call := value["call"].(map[string]any)
	params := call["params"].(map[string]any)
	params["arguments"].(map[string]any)["draft"] = true
	value["forwarded"].(map[string]any)["request"] = deepCopy(call)
	digest, err := JCSDigest(params)
	if err != nil {
		t.Fatal(err)
	}
	bindingOf(value)["params_digest"] = digest
	action := value["decision_request"].(map[string]any)["action"].(map[string]any)
	parameters := deepCopy(params["arguments"]).(map[string]any)
	parameters["draft"] = json.Number("1")
	action["parameters"] = parameters
	action["parameters_digest"] = digestOf(parameters)
	found := rulesAndPaths(checkMCP(rebound(value)))
	for _, want := range []string{RuleMCPRequest + " /decision_request/action/parameters", RuleMCPForward + " /forwarded/request/params/arguments"} {
		if !contains(found, want) {
			t.Errorf("%s: %v", want, found)
		}
	}
	for _, item := range []struct {
		inParams      bool
		name, binding string
		written, held any
	}{
		{true, "name", "tool", json.Number("1"), true},
		{false, "method", "method", json.Number("0"), false},
	} {
		changed := reparsed(t, valid)
		changedCall := changed["call"].(map[string]any)
		holder := changedCall
		if item.inParams {
			holder = changedCall["params"].(map[string]any)
		}
		holder[item.name] = item.written
		changed["forwarded"].(map[string]any)["request"] = deepCopy(changedCall)
		bindingOf(changed)[item.binding] = item.held
		digest, err := JCSDigest(changedCall["params"])
		if err != nil {
			t.Fatal(err)
		}
		bindingOf(changed)["params_digest"] = digest
		where := "/forwarded/request/" + item.name
		if item.inParams {
			where = "/forwarded/request/params/" + item.name
		}
		if found := rulesAndPaths(checkMCP(rebound(changed))); !contains(found, RuleMCPForward+" "+where) {
			t.Errorf("%s: %v", item.name, found)
		}
	}
}

// TestOTelAttributesInTheKindTheTableGives: each attribute is held in the
// AnyValue kind that the attribute table gives and the export key's identifier is a string
// (OE1-003, OE1-010), so a bytesValue that holds the outcome's text is not the outcome and a key
// identifier that is not a string names no key. A digest that needs no key is still recognized in
// a bytesValue under a key the caller does not hold (OE1-004).
func TestOTelAttributesInTheKindTheTableGives(t *testing.T) {
	keys, err := LoadExportKeys(vectors.Read(t, vectors.Suite(t, "otel-export").ExportKeysPath))
	if err != nil {
		t.Fatal(err)
	}
	valid := bindingVector(t, "otel-export", "otel-valid-admit-response-exported")
	with := func(value map[string]any, key string, item map[string]any) map[string]any {
		changed := reparsed(t, value)
		log := changed["log_record"].(map[string]any)
		kept := []any{}
		for _, entry := range log["attributes"].([]any) {
			if entry.(map[string]any)["key"] != key {
				kept = append(kept, entry)
			}
		}
		log["attributes"] = append(kept, map[string]any{"key": key, "value": item})
		return changed
	}
	details := func(value map[string]any) []string {
		seen := map[string]bool{}
		out := []string{}
		for _, item := range checkOTel(value, keys) {
			if !seen[item.Detail] {
				seen[item.Detail] = true
				out = append(out, item.Detail)
			}
		}
		sort.Strings(out)
		return out
	}
	if found := checkOTel(valid, keys); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	if got := fmt.Sprint(details(with(valid, "ecl.decision.outcome", map[string]any{"bytesValue": "admit"}))); got != "[ecl.decision.outcome is not the object's value]" {
		t.Errorf("outcome as a bytesValue: %s", got)
	}
	for _, item := range []map[string]any{{"boolValue": true}, {"intValue": "5"}, {"bytesValue": "k1"}} {
		found := details(with(valid, OTelKeyID, item))
		reported := false
		for _, detail := range found {
			reported = reported || detail == OTelKeyID+" is not the identifier of a key"
		}
		if !reported {
			t.Errorf("key identifier %v: %v", item, found)
		}
	}
	// A string that names a key the caller does not hold is not compared, as OE1-010 intends.
	unknown := with(valid, OTelKeyID, map[string]any{"stringValue": "urn:example:export-key:unknown"})
	if found := checkOTel(unknown, keys); len(found) != 0 {
		t.Errorf("unknown key: %v", found)
	}
	unkeyed, err := OTelUnkeyedDigests(valid["object"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	reports := func(found []string, detail string) bool {
		for _, item := range found {
			if item == detail {
				return true
			}
		}
		return false
	}
	if got := fmt.Sprint(details(with(unknown, OTelObjectDigest, map[string]any{"stringValue": unkeyed[OTelObjectDigest]}))); got != "["+OTelObjectDigest+" is a digest that needs no export key]" {
		t.Errorf("unkeyed digest as a stringValue: %s", got)
	}
	// Under a key the caller does not hold, a digest is still the stringValue of an HMAC
	// in lowercase hexadecimal, so the SHA-256 that needs no key is refused in any other kind or form.
	// The check of OE1-004 reads the attribute in its own kind.
	if got := fmt.Sprint(details(with(unknown, OTelObjectDigest, map[string]any{"bytesValue": unkeyed[OTelObjectDigest]}))); got != "["+OTelObjectDigest+" is not an HMAC in lowercase hexadecimal]" {
		t.Errorf("unkeyed digest as a bytesValue: %s", got)
	}
	hexDigest := unkeyed[OTelObjectDigest].(string)
	rawDigest, err := hex.DecodeString(hexDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []map[string]any{
		{"bytesValue": base64.StdEncoding.EncodeToString(rawDigest)},
		{"arrayValue": map[string]any{"values": []any{map[string]any{"stringValue": hexDigest}}}},
		{"kvlistValue": map[string]any{"values": []any{map[string]any{"key": "sha256", "value": map[string]any{"stringValue": hexDigest}}}}},
		{"boolValue": true},
		{"stringValue": strings.ToUpper(hexDigest)},
	} {
		if found := details(with(unknown, OTelObjectDigest, item)); !reports(found, OTelObjectDigest+" is not an HMAC in lowercase hexadecimal") {
			t.Errorf("digest %v under an unknown key: %v", item, found)
		}
	}
	// A response has no parameters digest, so a record of it that carries one copies nothing, under a
	// key the caller does not hold as under one it holds: here the request's, which needs no key.
	request := bindingVector(t, "otel-export", "otel-valid-request-exported")
	requestDigests, err := OTelUnkeyedDigests(request["object"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	carried := with(unknown, OTelParametersDigest, map[string]any{"stringValue": requestDigests[OTelParametersDigest]})
	if got := fmt.Sprint(details(carried)); got != "["+OTelParametersDigest+" copies nothing in the object]" {
		t.Errorf("a response that carries a parameters digest: %s", got)
	}
	// A repeated attribute key hides the earlier attribute from every comparison.
	deny := bindingVector(t, "otel-export", "otel-valid-deny-response-exported")
	if found := checkOTel(deny, keys); len(found) != 0 {
		t.Fatalf("%v", found)
	}
	repeated := reparsed(t, deny)
	log := repeated["log_record"].(map[string]any)
	log["attributes"] = append([]any{map[string]any{"key": "ecl.decision.outcome", "value": map[string]any{"stringValue": "admit"}}}, log["attributes"].([]any)...)
	if got := fmt.Sprint(details(repeated)); got != "[an attribute key is repeated]" {
		t.Errorf("repeated outcome: %s", got)
	}
}

// TestOTelRowsApplyToTheObjectsTheyName: each row of the attribute table applies only to the
// objects it names: a challenge carries its request's
// identifier (OE1-004) and a control message no decision's safe state; a request event carries the
// identifier of the request it holds (OE1-004); under a key the caller does not hold, a request's
// record still carries the keyed parameters digest (OE1-010); and the observed time is a fixed64
// (OE1-007).
func TestOTelRowsApplyToTheObjectsTheyName(t *testing.T) {
	keys, err := LoadExportKeys(vectors.Read(t, vectors.Suite(t, "otel-export").ExportKeysPath))
	if err != nil {
		t.Fatal(err)
	}
	with := func(value map[string]any, key string, item map[string]any) map[string]any {
		changed := reparsed(t, value)
		log := changed["log_record"].(map[string]any)
		kept := []any{}
		for _, entry := range log["attributes"].([]any) {
			if entry.(map[string]any)["key"] != key {
				kept = append(kept, entry)
			}
		}
		if item != nil {
			kept = append(kept, map[string]any{"key": key, "value": item})
		}
		log["attributes"] = kept
		return changed
	}
	details := func(value map[string]any) string {
		seen := map[string]bool{}
		out := []string{}
		for _, item := range checkOTel(value, keys) {
			if !seen[item.Detail] {
				seen[item.Detail] = true
				out = append(out, item.Detail)
			}
		}
		sort.Strings(out)
		return fmt.Sprint(out)
	}
	request := bindingVector(t, "otel-export", "otel-valid-request-exported")
	unknown := with(request, OTelKeyID, map[string]any{"stringValue": "urn:example:export-key:unknown"})
	if got := details(unknown); got != "[]" {
		t.Errorf("unknown key: %s", got)
	}
	if got := details(with(unknown, OTelParametersDigest, nil)); got != "["+OTelKeyID+" is named without the keyed "+OTelParametersDigest+"]" {
		t.Errorf("parameters digest left out under an unknown key: %s", got)
	}
	if got := details(with(request, OTelParametersDigest, nil)); got != "["+OTelParametersDigest+" is not the object's value]" {
		t.Errorf("parameters digest left out under the suite's key: %s", got)
	}
	challenge := bindingVector(t, "otel-export", "otel-valid-challenge-exported")
	if got := details(challenge); got != "[]" {
		t.Errorf("challenge: %s", got)
	}
	if got := details(with(challenge, OTelRequestID, nil)); got != "["+OTelRequestID+" is not the object's value]" {
		t.Errorf("challenge without its request: %s", got)
	}
	halt := bindingVector(t, "otel-export", "otel-valid-halt-control-exported")
	if got := details(halt); got != "[]" {
		t.Errorf("halt: %s", got)
	}
	safeState := halt["object"].(map[string]any)["safe_state"]
	if got := details(with(halt, "ecl.decision.safe_state", map[string]any{"stringValue": safeState})); got != "[ecl.decision.safe_state copies nothing in the object]" {
		t.Errorf("halt with a safe state: %s", got)
	}
	received := bindingVector(t, "otel-export", "otel-valid-request-event-exported")
	if got := details(received); got != "[]" {
		t.Errorf("request event: %s", got)
	}
	if got := details(with(received, OTelRequestID, nil)); got != "["+OTelRequestID+" is not the object's value]" {
		t.Errorf("request event without its request: %s", got)
	}
	admit := reparsed(t, bindingVector(t, "otel-export", "otel-valid-admit-response-exported"))
	admit["log_record"].(map[string]any)["observedTimeUnixNano"] = "18446744073709551615"
	if got := details(admit); got != "[]" {
		t.Errorf("observed time 2^64 - 1: %s", got)
	}
	admit["log_record"].(map[string]any)["observedTimeUnixNano"] = "18446744073709551616"
	if got := details(admit); got != "[not a fixed64 time]" {
		t.Errorf("observed time 2^64: %s", got)
	}
}

// TestMCPForwardAndRefusalCarryTheCallIDAsTheSameJSON: a forward is exactly the call and a
// JSON-RPC error carries the call's id (MG1-005, MG1-006), as the same JSON value and with the same
// presence. The id 1 forwarded or answered as true is not the call's, and neither is a
// forward or an error that leaves out an id that the call holds as null. The
// record schema refuses an id of true or null in either form, so these records are held as
// themselves and checked directly.
func TestMCPForwardAndRefusalCarryTheCallIDAsTheSameJSON(t *testing.T) {
	for _, item := range []struct {
		callID, carried any
		omitted         bool
	}{{json.Number("1"), true, false}, {nil, nil, true}} {
		forwarded := bindingVector(t, "mcp-gateway", "mcp-valid-forwarded-on-admit")
		forwarded["call"].(map[string]any)["id"] = item.callID
		request := forwarded["forwarded"].(map[string]any)["request"].(map[string]any)
		if item.omitted {
			delete(request, "id")
		} else {
			request["id"] = item.carried
		}
		if found := rulesAndPaths(checkMCP(forwarded)); !strings.Contains(strings.Join(found, ";"), RuleMCPForward+" /forwarded/request/id") {
			t.Errorf("forward of the call id %v: %v", item.callID, found)
		}
		refused := bindingVector(t, "mcp-gateway", "mcp-valid-denied-refused")
		refused["call"].(map[string]any)["id"] = item.callID
		returned := refused["returned"].(map[string]any)
		if item.omitted {
			delete(returned, "id")
		} else {
			returned["id"] = item.carried
		}
		if found := rulesAndPaths(checkMCP(refused)); !strings.Contains(strings.Join(found, ";"), RuleMCPRefusal+" /returned/id") {
			t.Errorf("refusal of the call id %v: %v", item.callID, found)
		}
	}
}

// TestMCPDecodedContentSatisfiesItsDefinition: content held in the encoded
// form of MG1-012 satisfies the definition that the record schema gives the same content held as
// itself, so that encoding carries no call, request, response or tool definition that the schema
// refuses.
func TestMCPDecodedContentSatisfiesItsDefinition(t *testing.T) {
	valid := bindingVector(t, "mcp-gateway", "mcp-valid-float-content-forwarded")
	decoded, problems := decodedRecord(valid, mcpContentPaths)
	if len(problems) != 0 || len(decodedContentProblems(valid, decoded)) != 0 {
		t.Fatalf("%v %v", problems, decodedContentProblems(valid, decoded))
	}
	for _, item := range []struct {
		path   []string
		name   string
		change any
		member string
	}{
		{[]string{"call"}, "jsonRpcRequest", nil, "id"},
		{[]string{"call"}, "jsonRpcRequest", "1.0", "jsonrpc"},
		{[]string{"forwarded", "request"}, "jsonRpcRequest", true, "id"},
		{[]string{"server_response"}, "jsonRpcResponse", 0.5, "result"},
		{[]string{"returned"}, "jsonRpcResponse", map[string]any{"n": json.Number("1")}, "id"},
		{[]string{"tool_definition"}, "toolDefinition", "", "name"},
	} {
		value := reparsed(t, valid)
		content := deepCopy(member(decoded, item.path...)).(map[string]any)
		content[item.member] = item.change
		if last := item.path[len(item.path)-1]; last == "call" || last == "request" {
			params := deepCopy(content["params"]).(map[string]any)
			params["_meta"] = map[string]any{"example.org/sampling": 0.5}
			content["params"] = params
		}
		encoded, err := EncodeContent(content)
		if err != nil {
			t.Fatal(err)
		}
		if _, isEncodedForm := isEncoded(encoded); !isEncodedForm {
			t.Fatalf("%v is held as itself", item.path)
		}
		parent := value
		for _, step := range item.path[:len(item.path)-1] {
			parent = parent[step].(map[string]any)
		}
		parent[item.path[len(item.path)-1]] = encoded
		found := checkMCP(value)
		where := "/" + strings.Join(item.path, "/")
		if fmt.Sprint(rulesAndPaths(found)) != "[ecl.error.schema-invalid.v1 "+where+"]" || !strings.Contains(found[0].Detail, "does not satisfy "+item.name) {
			t.Errorf("%s: %v", where, found)
		}
	}
}

// TestNoncharacterContentIsHeldEncoded: content whose strings or member
// names hold a Unicode noncharacter lies outside the restricted profile (IE1-002), so it is held in
// the encoded form of MG1-012 and decodes from it, as the reference gateway writes it.
func TestNoncharacterContentIsHeldEncoded(t *testing.T) {
	for _, content := range []map[string]any{
		{"jsonrpc": "2.0", "id": "\uffff", "method": "tools/call", "params": map[string]any{}},
		{"jsonrpc": "2.0", "id": json.Number("7"), "method": "tools/call", "params": map[string]any{"_meta": map[string]any{"\ufdd0": "x"}}},
		{"jsonrpc": "2.0", "id": "\U0010ffff", "result": map[string]any{}},
	} {
		if digestOf(content) != nil {
			t.Errorf("%v has a restricted canonical digest", content)
		}
		held, err := EncodeContent(content)
		if err != nil {
			t.Fatal(err)
		}
		if _, encoded := isEncoded(held); !encoded {
			t.Fatalf("%v is held as itself", content)
		}
		if decoded, err := DecodeContent(held); err != nil || !pyjson.Equal(decoded, content) {
			t.Errorf("%v: %v %v", content, decoded, err)
		}
	}
}

// TestMCPNullArgumentsAreRefusedAsNotMapped: MG1-004 and MG1-006. A call whose
// arguments are null has arguments that are not an object, as a string is not, so it is refused
// with -31007, also under a mapping that gives a fixed target: a null is not an absent member.
func TestMCPNullArgumentsAreRefusedAsNotMapped(t *testing.T) {
	refused := bindingVector(t, "mcp-gateway", "mcp-valid-null-arguments-refused")
	if arguments, held := member(refused, "call", "params").(map[string]any)["arguments"]; !held || arguments != nil {
		t.Fatalf("the vector's call holds arguments %v", arguments)
	}
	if !holds(refused["mapping"], "target_uri") {
		t.Fatal("the vector's mapping gives no fixed target")
	}
	cause, refusedCall := MCPRefusalCause(refused)
	if !refusedCall || cause.Cause != "not-mapped" {
		t.Fatalf("cause %v %v", cause, refusedCall)
	}
	if found := checkMCP(refused); len(found) != 0 {
		t.Fatalf("findings %v", found)
	}
	absent := reparsed(t, refused)
	delete(member(absent, "call", "params").(map[string]any), "arguments")
	if cause, refusedCall := MCPRefusalCause(absent); refusedCall && cause.Cause == "not-mapped" {
		t.Fatalf("a call without arguments is refused as not mapped: %v", cause)
	}
}
