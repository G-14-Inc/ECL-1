// Package strictjson implements the bounded ECL restricted JSON input profile.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	RuleNoDuplicateMembers = "ecl.rule.json-no-duplicate-members.v1"
	RuleRestrictedNumbers  = "ecl.rule.json-restricted-numbers.v1"
	RuleRestrictedUnicode  = "ecl.rule.json-restricted-unicode.v1"
	RuleSyntaxValid        = "ecl.rule.json-syntax-valid.v1"

	maxInputBytes = 16 * 1024 * 1024
	maxDepth      = 128
	maxEntries    = 100_000
)

var maxExactInteger = func() *big.Int {
	value, ok := new(big.Int).SetString("9007199254740991", 10)
	if !ok {
		panic("invalid exact-integer bound")
	}
	return value
}()

// Error is a deterministic restricted-JSON rejection.
type Error struct {
	RuleID string
	Path   string
	Reason string
}

func (e *Error) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("%s: %s", e.RuleID, e.Reason)
	}
	return fmt.Sprintf("%s at %s: %s", e.RuleID, e.Path, e.Reason)
}

type parser struct {
	decoder *json.Decoder
	entries int
}

// Parse decodes one complete JSON value while enforcing the ECL restricted
// number, duplicate-member, Unicode, nesting, and input-size boundaries.
func Parse(data []byte) (any, error) {
	if len(data) > maxInputBytes {
		return nil, &Error{
			RuleID: RuleSyntaxValid,
			Path:   "/",
			Reason: "input exceeds the 16 MiB parser budget",
		}
	}
	if !utf8.Valid(data) {
		return nil, &Error{
			RuleID: RuleRestrictedUnicode,
			Path:   "/",
			Reason: "input is not valid UTF-8",
		}
	}
	if err := validateUnicodeEscapes(data); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	instance := &parser{decoder: decoder}
	value, err := instance.value("", 0)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, syntaxError("/", err)
		}
		return nil, &Error{
			RuleID: RuleSyntaxValid,
			Path:   "/",
			Reason: fmt.Sprintf("trailing JSON token %v", token),
		}
	}
	return value, nil
}

func (p *parser) value(path string, depth int) (any, error) {
	if depth > maxDepth {
		return nil, &Error{
			RuleID: RuleSyntaxValid,
			Path:   displayPath(path),
			Reason: "nesting exceeds the 128-level parser budget",
		}
	}
	token, err := p.decoder.Token()
	if err != nil {
		return nil, syntaxError(displayPath(path), err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for p.decoder.More() {
				keyToken, err := p.decoder.Token()
				if err != nil {
					return nil, syntaxError(displayPath(path), err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, &Error{
						RuleID: RuleSyntaxValid,
						Path:   displayPath(path),
						Reason: "object member name is not a string",
					}
				}
				memberPath := path + "/" + escapePointer(key)
				if _, exists := object[key]; exists {
					return nil, &Error{
						RuleID: RuleNoDuplicateMembers,
						Path:   displayPath(memberPath),
						Reason: "duplicate object member",
					}
				}
				if err := p.count(memberPath); err != nil {
					return nil, err
				}
				member, err := p.value(memberPath, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = member
			}
			closing, err := p.decoder.Token()
			if err != nil {
				return nil, syntaxError(displayPath(path), err)
			}
			if closing != json.Delim('}') {
				return nil, &Error{
					RuleID: RuleSyntaxValid,
					Path:   displayPath(path),
					Reason: "object has no closing delimiter",
				}
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for p.decoder.More() {
				itemPath := path + "/" + strconv.Itoa(len(array))
				if err := p.count(itemPath); err != nil {
					return nil, err
				}
				item, err := p.value(itemPath, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			closing, err := p.decoder.Token()
			if err != nil {
				return nil, syntaxError(displayPath(path), err)
			}
			if closing != json.Delim(']') {
				return nil, &Error{
					RuleID: RuleSyntaxValid,
					Path:   displayPath(path),
					Reason: "array has no closing delimiter",
				}
			}
			return array, nil
		default:
			return nil, &Error{
				RuleID: RuleSyntaxValid,
				Path:   displayPath(path),
				Reason: fmt.Sprintf("unexpected delimiter %q", value),
			}
		}
	case json.Number:
		if err := validateNumber(value.String(), displayPath(path)); err != nil {
			return nil, err
		}
		return value, nil
	case string, bool, nil:
		return value, nil
	default:
		return nil, &Error{
			RuleID: RuleSyntaxValid,
			Path:   displayPath(path),
			Reason: fmt.Sprintf("unsupported token type %T", value),
		}
	}
}

func (p *parser) count(path string) error {
	p.entries++
	if p.entries > maxEntries {
		return &Error{
			RuleID: RuleSyntaxValid,
			Path:   displayPath(path),
			Reason: "container entries exceed the 100,000-entry parser budget",
		}
	}
	return nil
}

func validateNumber(raw, path string) error {
	if strings.ContainsAny(raw, ".eE") {
		return &Error{
			RuleID: RuleRestrictedNumbers,
			Path:   path,
			Reason: "floating-point and exponent forms are prohibited",
		}
	}
	if raw == "-0" {
		return &Error{
			RuleID: RuleRestrictedNumbers,
			Path:   path,
			Reason: "negative zero is prohibited",
		}
	}
	integer, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return &Error{
			RuleID: RuleRestrictedNumbers,
			Path:   path,
			Reason: "number is not a base-10 integer",
		}
	}
	if new(big.Int).Abs(new(big.Int).Set(integer)).Cmp(maxExactInteger) > 0 {
		return &Error{
			RuleID: RuleRestrictedNumbers,
			Path:   path,
			Reason: "integer exceeds the interoperable exact range",
		}
	}
	return nil
}

func syntaxError(path string, err error) error {
	return &Error{RuleID: RuleSyntaxValid, Path: path, Reason: err.Error()}
}

func displayPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func escapePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func validateUnicodeEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			if i+1 >= len(data) {
				return &Error{
					RuleID: RuleSyntaxValid,
					Path:   "/",
					Reason: "truncated string escape",
				}
			}
			i++
			if data[i] != 'u' {
				continue
			}
			code, ok := hex4(data, i+1)
			if !ok {
				return &Error{
					RuleID: RuleSyntaxValid,
					Path:   "/",
					Reason: "invalid Unicode escape",
				}
			}
			switch {
			case code >= 0xD800 && code <= 0xDBFF:
				nextSlash := i + 5
				if nextSlash+5 >= len(data) ||
					data[nextSlash] != '\\' ||
					data[nextSlash+1] != 'u' {
					return &Error{
						RuleID: RuleRestrictedUnicode,
						Path:   "/",
						Reason: "unpaired high-surrogate escape",
					}
				}
				low, ok := hex4(data, nextSlash+2)
				if !ok || low < 0xDC00 || low > 0xDFFF {
					return &Error{
						RuleID: RuleRestrictedUnicode,
						Path:   "/",
						Reason: "high surrogate is not followed by a low surrogate",
					}
				}
				i += 10
			case code >= 0xDC00 && code <= 0xDFFF:
				return &Error{
					RuleID: RuleRestrictedUnicode,
					Path:   "/",
					Reason: "unpaired low-surrogate escape",
				}
			default:
				i += 4
			}
		}
	}
	return nil
}

func hex4(data []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(data) {
		return 0, false
	}
	var value uint16
	for _, current := range data[start : start+4] {
		value <<= 4
		switch {
		case current >= '0' && current <= '9':
			value |= uint16(current - '0')
		case current >= 'a' && current <= 'f':
			value |= uint16(current-'a') + 10
		case current >= 'A' && current <= 'F':
			value |= uint16(current-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
