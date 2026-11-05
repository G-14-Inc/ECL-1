package bindings

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
)

// The JWS algorithms and header types of OAUTH-AUTHORITY-1 (OA1-007, RFC 9068, RFC 9449).
const (
	ES256         = "ES256"
	EdDSA         = "EdDSA"
	AccessType    = "at+jwt"
	DPoPType      = "dpop+jwt"
	MaxTokenBytes = 16 * 1024
)

var (
	jwsAlgorithms = map[string]bool{ES256: true, EdDSA: true}
	keyHeaders    = []string{"jwk", "jku", "x5u", "x5c"}
	base64URL     = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
)

// JoseError is a token, proof or key that is malformed or does not verify; Reason names the check.
type JoseError struct {
	Reason  string
	Message string
}

func (e *JoseError) Error() string { return e.Reason + ": " + e.Message }

// B64URL is base64url without padding (RFC 7515 section 2).
func B64URL(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// B64URLDecode returns the bytes of unpadded base64url text, refusing any other alphabet and a
// non-canonical tail.
func B64URLDecode(text string) ([]byte, error) {
	if !base64URL.MatchString(text) || len(text)%4 == 1 {
		return nil, &JoseError{"malformed", "the text is not unpadded base64url"}
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || B64URL(data) != text {
		return nil, &JoseError{"malformed", "the base64url text is not in canonical form"}
	}
	return data, nil
}

// JWS is the decoded parts of a compact JWS, unverified.
type JWS struct {
	Header       map[string]any
	Claims       map[string]any
	SigningInput []byte
	Signature    []byte
}

// segmentObject returns the JSON object of one segment, read under the strict JSON profile
// (IE1-002, OA1-007) as the reference reads it.
func segmentObject(segment string) (map[string]any, error) {
	data, err := B64URLDecode(segment)
	if err != nil {
		return nil, err
	}
	value, err := ParseStrictSegment(data)
	if errors.Is(err, errRepeatedMember) {
		return nil, &JoseError{"malformed", "a JWS segment repeats a member name"}
	}
	if err != nil {
		return nil, &JoseError{"malformed", "a JWS segment is not strict JSON"}
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, &JoseError{"malformed", "a JWS segment is not a JSON object"}
	}
	return object, nil
}

// DecodeJWS returns the header, the claims, the signing input and the signature of a compact
// JWS. It verifies nothing.
func DecodeJWS(token any) (*JWS, error) {
	text, ok := token.(string)
	if !ok || utf8.RuneCountInString(text) > MaxTokenBytes {
		return nil, &JoseError{"malformed", "the token is not a compact JWS within the size limit"}
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return nil, &JoseError{"malformed", "a compact JWS has three segments"}
	}
	header, err := segmentObject(parts[0])
	if err != nil {
		return nil, err
	}
	claims, err := segmentObject(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := B64URLDecode(parts[2])
	if err != nil {
		return nil, err
	}
	return &JWS{Header: header, Claims: claims, SigningInput: []byte(parts[0] + "." + parts[1]), Signature: signature}, nil
}

func checkedHeader(header map[string]any, expectedType string) (string, error) {
	name, isText := header["alg"].(string)
	if !isText || !jwsAlgorithms[name] {
		return "", &JoseError{"algorithm", "the algorithm is not in the declared asymmetric set"}
	}
	if !pyjson.Equal(header["typ"], expectedType) {
		return "", &JoseError{"type", "the header's typ is not " + expectedType}
	}
	if _, present := header["crit"]; present {
		return "", &JoseError{"crit", "the header has a crit member this verifier does not understand"}
	}
	return name, nil
}

func coordinate(jwk map[string]any, name string, size int) ([]byte, error) {
	var data []byte
	if text, isText := jwk[name].(string); isText {
		decoded, err := B64URLDecode(text)
		if err != nil {
			return nil, err
		}
		data = decoded
	}
	if len(data) != size {
		return nil, &JoseError{"key", fmt.Sprintf("the JWK member %s is not %d bytes of base64url", name, size)}
	}
	return data, nil
}

type joseKey struct {
	p256    *ecdsa.PublicKey
	ed25519 ed25519.PublicKey
}

func publicKey(jwk map[string]any) (joseKey, error) {
	if _, present := jwk["d"]; present {
		return joseKey{}, &JoseError{"key", "a verification key must not carry private key material"}
	}
	if pyjson.Equal(jwk["kty"], "EC") && pyjson.Equal(jwk["crv"], "P-256") {
		x, err := coordinate(jwk, "x", 32)
		if err != nil {
			return joseKey{}, err
		}
		y, err := coordinate(jwk, "y", 32)
		if err != nil {
			return joseKey{}, err
		}
		point := append(append([]byte{4}, x...), y...)
		// crypto/ecdh refuses coordinates at or above p and points off the curve.
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return joseKey{}, &JoseError{"key", "the JWK is not a point on P-256"}
		}
		return joseKey{p256: &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}}, nil
	}
	if pyjson.Equal(jwk["kty"], "OKP") && pyjson.Equal(jwk["crv"], "Ed25519") {
		x, err := coordinate(jwk, "x", ed25519.PublicKeySize)
		if err != nil {
			return joseKey{}, err
		}
		return joseKey{ed25519: ed25519.PublicKey(x)}, nil
	}
	return joseKey{}, &JoseError{"key", "the JWK is neither a P-256 nor an Ed25519 public key"}
}

// verifySignature checks a JOSE signature as the reference's backend checks it: ES256 is r || s,
// each from 1 to n - 1, of any s (crypto/ecdsa); EdDSA has S below the group order and meets the
// cofactorless equation, with the key decoded as crypto/ed25519 decodes it (a non-canonical
// encoding of a point is that point). The stricter key rules of ECL-IE-1 (package envelope) are
// for ECL's own evidence signatures and do not apply to a token another system signs.
func verifySignature(algorithm string, jwk map[string]any, signingInput, signature []byte) error {
	key, err := publicKey(jwk)
	if err != nil {
		return err
	}
	switch {
	case algorithm == ES256 && key.p256 != nil:
		if len(signature) != 64 {
			return &JoseError{"signature", "an ES256 signature is not 64 bytes"}
		}
		digest := sha256.Sum256(signingInput)
		r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(key.p256, digest[:], r, s) {
			return &JoseError{"signature", "the signature does not verify"}
		}
		return nil
	case algorithm == EdDSA && key.ed25519 != nil:
		if !ed25519.Verify(key.ed25519, signingInput, signature) {
			return &JoseError{"signature", "the signature does not verify"}
		}
		return nil
	}
	return &JoseError{"algorithm", "the algorithm does not match the key type"}
}

// VerifyJWS returns the header and claims of a token signed by one of keys (by kid), after every
// check of OA1-007: an asymmetric algorithm of the declared set, the expected typ, no crit, no
// header that carries or points to a key, a configured kid and a valid signature.
func VerifyJWS(token any, keys map[string]map[string]any, expectedType string) (map[string]any, map[string]any, error) {
	decoded, err := DecodeJWS(token)
	if err != nil {
		return nil, nil, err
	}
	algorithm, err := checkedHeader(decoded.Header, expectedType)
	if err != nil {
		return nil, nil, err
	}
	for _, name := range keyHeaders {
		if _, present := decoded.Header[name]; present {
			return nil, nil, &JoseError{"key-header", "the header carries or points to a key"}
		}
	}
	kid, isText := decoded.Header["kid"].(string)
	key, known := keys[kid]
	if !isText || !known {
		return nil, nil, &JoseError{"kid", "the header names no configured key"}
	}
	if err := verifySignature(algorithm, key, decoded.SigningInput, decoded.Signature); err != nil {
		return nil, nil, err
	}
	return decoded.Header, decoded.Claims, nil
}

// VerifyDPoP returns the header, claims and key thumbprint of a DPoP proof (RFC 9449), checked
// with the public key its header carries.
func VerifyDPoP(proof any) (map[string]any, map[string]any, string, error) {
	decoded, err := DecodeJWS(proof)
	if err != nil {
		return nil, nil, "", err
	}
	algorithm, err := checkedHeader(decoded.Header, DPoPType)
	if err != nil {
		return nil, nil, "", err
	}
	jwk, isObject := decoded.Header["jwk"].(map[string]any)
	for _, name := range []string{"jku", "x5u", "x5c"} {
		if _, present := decoded.Header[name]; present {
			isObject = false
		}
	}
	if !isObject {
		return nil, nil, "", &JoseError{"key-header", "a DPoP proof carries exactly its public key in jwk"}
	}
	if err := verifySignature(algorithm, jwk, decoded.SigningInput, decoded.Signature); err != nil {
		return nil, nil, "", err
	}
	thumbprint, err := Thumbprint(jwk)
	if err != nil {
		return nil, nil, "", err
	}
	return decoded.Header, decoded.Claims, thumbprint, nil
}

// pythonJSONString writes a string as Python's json.dumps(..., ensure_ascii=False) writes it.
func pythonJSONString(out *strings.Builder, value string) {
	out.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if character < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte("0123456789abcdef"[character>>4])
				out.WriteByte("0123456789abcdef"[character&0xf])
			} else {
				out.WriteRune(character)
			}
		}
	}
	out.WriteByte('"')
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of a public P-256 or Ed25519 JWK, in
// base64url.
func Thumbprint(jwk map[string]any) (string, error) {
	kty := jwk["kty"]
	names := []string{"crv", "kty", "x"}
	if pyjson.Equal(kty, "EC") {
		names = []string{"crv", "kty", "x", "y"}
	}
	if !pyjson.Equal(kty, "EC") && !pyjson.Equal(kty, "OKP") {
		return "", &JoseError{"key", "a thumbprint needs an EC or OKP public key with its members"}
	}
	var out strings.Builder
	out.WriteByte('{')
	for index, name := range names {
		text, isText := jwk[name].(string)
		if !isText {
			return "", &JoseError{"key", "a thumbprint needs an EC or OKP public key with its members"}
		}
		if !utf8.ValidString(text) {
			return "", &PythonError{Kind: "ValueError", Message: "surrogates not allowed"}
		}
		if index > 0 {
			out.WriteByte(',')
		}
		pythonJSONString(&out, name)
		out.WriteByte(':')
		pythonJSONString(&out, text)
	}
	out.WriteByte('}')
	sum := sha256.Sum256([]byte(out.String()))
	return B64URL(sum[:]), nil
}

// TokenHash is the ath of RFC 9449: base64url SHA-256 of the token's ASCII bytes.
func TokenHash(token string) (string, error) {
	for index := 0; index < len(token); index++ {
		if token[index] > 0x7f {
			return "", &PythonError{Kind: "ValueError", Message: "the token is not ASCII"}
		}
	}
	sum := sha256.Sum256([]byte(token))
	return B64URL(sum[:]), nil
}
