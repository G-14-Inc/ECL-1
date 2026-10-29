package bindings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrJCS is the cause of every value that has no RFC 8785 canonical form.
var ErrJCS = errors.New("no RFC 8785 canonical form")

const jcsMaxDepth = 256

// exactDouble is 2^53: every integer up to this magnitude is a double exactly.
var exactDouble = new(big.Int).Lsh(big.NewInt(1), 53)

// JCSNumber writes a finite double as ECMAScript's Number.prototype.toString writes it (RFC 8785
// section 3.2.2.3): the shortest digits that read back as the same double, in plain notation for
// decimal exponents from -6 to 21 and in exponent notation otherwise.
func JCSNumber(value float64) (string, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", fmt.Errorf("%w: NaN and the infinities have no JSON form", ErrJCS)
	}
	if value == 0 {
		return "0", nil
	}
	sign := ""
	if value < 0 {
		sign = "-"
		value = -value
	}
	// Shortest round-trip digits d1.d2...dk and exponent e: value = 0.d1...dk * 10^(e+1).
	text := strconv.FormatFloat(value, 'e', -1, 64)
	mantissa, power, _ := strings.Cut(text, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exponent, err := strconv.Atoi(power)
	if err != nil {
		return "", err
	}
	n := exponent + 1
	k := len(digits)
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	}
	written := digits[:1]
	if k > 1 {
		written += "." + digits[1:]
	}
	if n-1 >= 0 {
		return sign + written + "e+" + strconv.Itoa(n-1), nil
	}
	return sign + written + "e-" + strconv.Itoa(1-n), nil
}

// jcsJSONNumber writes a json.Number: an integer up to 2^53 in magnitude as its digits, any other
// number as the double that a parser reads it as.
func jcsJSONNumber(number json.Number) (string, error) {
	text := number.String()
	if integer, ok := new(big.Int).SetString(text, 10); ok {
		if new(big.Int).Abs(integer).Cmp(exactDouble) <= 0 {
			return integer.String(), nil
		}
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return "", fmt.Errorf("%w: %q is not a JSON number", ErrJCS, text)
	}
	return JCSNumber(value)
}

func jcsString(out *strings.Builder, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: a string is not Unicode text (a lone surrogate)", ErrJCS)
	}
	out.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if character < 0x20 {
				fmt.Fprintf(out, `\u%04x`, character)
			} else {
				out.WriteRune(character)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

// utf16Less orders member names by their UTF-16 code units (RFC 8785 section 3.2.3).
func utf16Less(left, right string) bool {
	a, b := utf16.Encode([]rune(left)), utf16.Encode([]rune(right))
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] != b[index] {
			return a[index] < b[index]
		}
	}
	return len(a) < len(b)
}

func jcsWrite(out *strings.Builder, value any, depth int) error {
	if depth > jcsMaxDepth {
		return fmt.Errorf("%w: the value nests deeper than %d levels", ErrJCS, jcsMaxDepth)
	}
	switch current := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(current))
	case json.Number:
		text, err := jcsJSONNumber(current)
		if err != nil {
			return err
		}
		out.WriteString(text)
	case float64:
		text, err := JCSNumber(current)
		if err != nil {
			return err
		}
		out.WriteString(text)
	case int:
		return jcsWrite(out, json.Number(strconv.Itoa(current)), depth)
	case int64:
		return jcsWrite(out, json.Number(strconv.FormatInt(current, 10)), depth)
	case string:
		return jcsString(out, current)
	case []any:
		out.WriteByte('[')
		for index, item := range current {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := jcsWrite(out, item, depth+1); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(current))
		for name := range current {
			if !utf8.ValidString(name) {
				return fmt.Errorf("%w: a member name is not Unicode text", ErrJCS)
			}
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool { return utf16Less(names[i], names[j]) })
		out.WriteByte('{')
		for index, name := range names {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := jcsString(out, name); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := jcsWrite(out, current[name], depth+1); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("%w: no JSON form for a %T", ErrJCS, value)
	}
	return nil
}

// JCS returns the RFC 8785 canonical bytes of a JSON value: the values that strict.Parse returns,
// and doubles (float64), which content that ECL binds but does not make can carry. An integer
// beyond 2^53 in magnitude is the double nearest to it. For strictly parsed values the result is
// the restricted canonical form of canon.Marshal.
func JCS(value any) ([]byte, error) {
	var out strings.Builder
	if err := jcsWrite(&out, value, 0); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

// JCSDigest returns the ecl.digest.sha-256.v1 digest object of the RFC 8785 bytes of value.
func JCSDigest(value any) (map[string]any, error) {
	data, err := JCS(value)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return map[string]any{"algorithm": digestSuite, "value": hex.EncodeToString(sum[:])}, nil
}
