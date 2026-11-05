package envelope

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// The signature suites of ECL-IE-1.
const (
	Ed25519Suite = "ecl.sig.ed25519.v1"
	P256Suite    = "ecl.sig.ecdsa-p256-sha256.v1"
	MLDSA65Suite = "ecl.sig.ml-dsa-65.v1"
)

// ErrUnsupportedSuite is returned for ML-DSA-65, which this module recognizes but does not
// implement: this verifier does not enable ML-DSA.
var ErrUnsupportedSuite = errors.New("signature suite ecl.sig.ml-dsa-65.v1 is not implemented by this module")

// EncodingError is a signature or key that its suite's encoding rules refuse outright, such as
// a P-256 signature that is not minimal DER or not low-S. The envelope verifier reports it as an
// integrity failure.
type EncodingError struct{ Message string }

func (e *EncodingError) Error() string { return e.Message }

var (
	edField = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD     = edMod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), edField)))
	p256N   = elliptic.P256().Params().N
	p256Mid = new(big.Int).Rsh(p256N, 1)
)

type edPoint struct{ x, y *big.Int }

func edMod(value *big.Int) *big.Int { return new(big.Int).Mod(value, edField) }

func littleEndian(data []byte) *big.Int {
	reversed := make([]byte, len(data))
	for index, value := range data {
		reversed[len(data)-1-index] = value
	}
	return new(big.Int).SetBytes(reversed)
}

func edAdd(a, b edPoint) edPoint {
	product := edMod(new(big.Int).Mul(edD, new(big.Int).Mul(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y))))
	xNumerator := new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x))
	yNumerator := new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x))
	x := edMod(new(big.Int).Mul(xNumerator, new(big.Int).ModInverse(edMod(new(big.Int).Add(big.NewInt(1), product)), edField)))
	y := edMod(new(big.Int).Mul(yNumerator, new(big.Int).ModInverse(edMod(new(big.Int).Sub(big.NewInt(1), product)), edField)))
	return edPoint{x, y}
}

// Ed25519KeyProblem returns why an Ed25519 public key is refused, or "" when it is acceptable:
// 32 bytes, a canonical encoding (y below p, no x of 0 with the sign bit set), a point on the
// curve, and not of small order (TP1-008).
func Ed25519KeyProblem(raw []byte) string {
	if len(raw) != 32 {
		return fmt.Sprintf("a public key for %s is 32 bytes, not %d", Ed25519Suite, len(raw))
	}
	data := append([]byte{}, raw...)
	sign := data[31] >> 7
	data[31] &= 0x7f
	y := littleEndian(data)
	if y.Cmp(edField) >= 0 {
		return "the public key is not a canonical Ed25519 encoding: y is not below p"
	}
	yy := edMod(new(big.Int).Mul(y, y))
	numerator := edMod(new(big.Int).Sub(yy, big.NewInt(1)))
	denominator := edMod(new(big.Int).Add(new(big.Int).Mul(edD, yy), big.NewInt(1)))
	inverse := new(big.Int).ModInverse(denominator, edField)
	if inverse == nil {
		return "the public key is not a point on Ed25519"
	}
	squared := edMod(new(big.Int).Mul(numerator, inverse))
	x := new(big.Int).Exp(squared, new(big.Int).Rsh(new(big.Int).Add(edField, big.NewInt(3)), 3), edField)
	if edMod(new(big.Int).Mul(x, x)).Cmp(squared) != 0 {
		x = edMod(new(big.Int).Mul(x, new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edField, big.NewInt(1)), 2), edField)))
	}
	if edMod(new(big.Int).Mul(x, x)).Cmp(squared) != 0 {
		return "the public key is not a point on Ed25519"
	}
	if x.Sign() == 0 && sign == 1 {
		return "the public key is not a point on Ed25519: x is 0 and the sign bit is 1"
	}
	if x.Bit(0) != uint(sign) {
		x = new(big.Int).Sub(edField, x)
	}
	point := edPoint{x, y}
	for range 3 {
		point = edAdd(point, point)
	}
	if point.x.Sign() == 0 && point.y.Cmp(big.NewInt(1)) == 0 {
		return "the public key is a point of small order on Ed25519: a signature made without a private key verifies under it"
	}
	return ""
}

// VerifyEd25519 checks an Ed25519 signature with the cofactorless equation [S]B = R + [k]A,
// S below the group order, by encoding [S]B - [k]A and comparing it with the signature's R
// (IE1-016). This is how Go's crypto/ed25519 verifies; a cofactored equation, which some
// libraries use, accepts signatures this profile refuses.
func VerifyEd25519(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	// Go's decoder also accepts the non-canonical encodings of a point; this profile does not.
	data := append([]byte{}, publicKey...)
	sign := data[31] >> 7
	data[31] &= 0x7f
	y := littleEndian(data)
	if y.Cmp(edField) >= 0 || (sign == 1 && (y.Cmp(big.NewInt(1)) == 0 || y.Cmp(new(big.Int).Sub(edField, big.NewInt(1))) == 0)) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// P256KeyProblem returns why a P-256 public key is refused, or "" when it is acceptable: 65
// bytes in the uncompressed SEC 1 form (0x04 || x || y), coordinates below p, on the curve.
func P256KeyProblem(raw []byte) string {
	if len(raw) != 65 {
		return fmt.Sprintf("a public key for %s is 65 bytes, not %d", P256Suite, len(raw))
	}
	if raw[0] != 0x04 {
		return "the public key is not a point on P-256"
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return "the public key is not a point on P-256"
	}
	return ""
}

func derError() error {
	return &EncodingError{Message: "ECDSA signature is not minimally encoded DER"}
}

func derLength(der []byte, offset int) (int, int, error) {
	if offset >= len(der) {
		return 0, 0, derError()
	}
	first := der[offset]
	if first < 0x80 {
		return int(first), offset + 1, nil
	}
	count := int(first & 0x7f)
	if count == 0 || count > 2 || offset+1+count > len(der) {
		return 0, 0, derError()
	}
	length := 0
	for index := 0; index < count; index++ {
		length = length*256 + int(der[offset+1+index])
	}
	if length < 0x80 || (count == 2 && length < 0x100) || der[offset+1] == 0 {
		return 0, 0, derError()
	}
	return length, offset + 1 + count, nil
}

func derInteger(der []byte, offset int) (*big.Int, int, error) {
	if offset >= len(der) || der[offset] != 0x02 {
		return nil, 0, derError()
	}
	length, start, err := derLength(der, offset+1)
	if err != nil {
		return nil, 0, err
	}
	end := start + length
	if length == 0 || end > len(der) {
		return nil, 0, derError()
	}
	if der[start]&0x80 != 0 || (der[start] == 0 && length > 1 && der[start+1]&0x80 == 0) {
		return nil, 0, derError()
	}
	return new(big.Int).SetBytes(der[start:end]), end, nil
}

// ParseDERSignature returns the r and s of a minimally encoded DER ECDSA-Sig-Value, or an
// *EncodingError.
func ParseDERSignature(der []byte) (*big.Int, *big.Int, error) {
	if len(der) == 0 || der[0] != 0x30 {
		return nil, nil, derError()
	}
	length, start, err := derLength(der, 1)
	if err != nil {
		return nil, nil, err
	}
	if start+length != len(der) {
		return nil, nil, derError()
	}
	r, afterR, err := derInteger(der, start)
	if err != nil {
		return nil, nil, err
	}
	s, afterS, err := derInteger(der, afterR)
	if err != nil {
		return nil, nil, err
	}
	if afterS != len(der) {
		return nil, nil, derError()
	}
	return r, s, nil
}

// VerifyP256 checks an ECDSA P-256 SHA-256 signature (IE1-017). Non-minimal DER and a high s are
// an *EncodingError, refused before the curve check; a signature that does not verify is false.
func VerifyP256(publicKey, message, signature []byte) (bool, error) {
	r, s, err := ParseDERSignature(signature)
	if err != nil {
		return false, err
	}
	if s.Cmp(p256Mid) > 0 {
		return false, &EncodingError{Message: "ECDSA signature is not low-S"}
	}
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(p256N) >= 0 || s.Cmp(p256N) >= 0 {
		return false, nil
	}
	if P256KeyProblem(publicKey) != "" {
		return false, nil
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(publicKey[1:33]), Y: new(big.Int).SetBytes(publicKey[33:65])}
	digest := sha256.Sum256(message)
	return ecdsa.Verify(key, digest[:], r, s), nil
}

// KeyProblem returns why a public key is refused under its suite, or "" when it is acceptable.
func KeyProblem(suiteID string, raw []byte) string {
	switch suiteID {
	case Ed25519Suite:
		return Ed25519KeyProblem(raw)
	case P256Suite:
		return P256KeyProblem(raw)
	default:
		return suiteID + " is not supported by trust policy v1 (Ed25519 and ECDSA P-256)"
	}
}

// VerifySignature checks signature over message under a key of suiteID. It returns false when
// the signature does not verify, an *EncodingError for an encoding the suite refuses outright,
// ErrUnsupportedSuite for ML-DSA-65, and an *EncodingError for an unknown suite.
func VerifySignature(suiteID string, publicKey, message, signature []byte) (bool, error) {
	switch suiteID {
	case Ed25519Suite:
		return VerifyEd25519(publicKey, message, signature), nil
	case P256Suite:
		return VerifyP256(publicKey, message, signature)
	case MLDSA65Suite:
		return false, ErrUnsupportedSuite
	default:
		return false, &EncodingError{Message: "unsupported signature suite: " + suiteID}
	}
}
