// Package canonical emits the restricted canonical JSON used by ECL-1 RC-3.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Marshal returns deterministic restricted canonical JSON. Objects use UTF-16
// code-unit key ordering, arrays retain order, strings use the shortest JSON
// escapes required by the profile, and only integer json.Number values are
// accepted.
func Marshal(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := appendValue(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// Digest returns the lowercase SHA-256 digest of Marshal(value).
func Digest(value any) (string, error) {
	encoded, err := Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func appendValue(output *bytes.Buffer, value any) error {
	switch current := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if current {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		if !utf8.ValidString(current) {
			return fmt.Errorf("canonical string is not valid UTF-8")
		}
		appendString(output, current)
	case json.Number:
		raw := current.String()
		if raw == "" || raw == "-0" {
			return fmt.Errorf("canonical number is not an allowed integer: %q", raw)
		}
		for index, character := range raw {
			if character == '-' && index == 0 {
				continue
			}
			if character < '0' || character > '9' {
				return fmt.Errorf("canonical number is not an integer: %q", raw)
			}
		}
		output.WriteString(raw)
	case int:
		output.WriteString(strconv.FormatInt(int64(current), 10))
	case int8:
		output.WriteString(strconv.FormatInt(int64(current), 10))
	case int16:
		output.WriteString(strconv.FormatInt(int64(current), 10))
	case int32:
		output.WriteString(strconv.FormatInt(int64(current), 10))
	case int64:
		output.WriteString(strconv.FormatInt(current, 10))
	case uint:
		output.WriteString(strconv.FormatUint(uint64(current), 10))
	case uint8:
		output.WriteString(strconv.FormatUint(uint64(current), 10))
	case uint16:
		output.WriteString(strconv.FormatUint(uint64(current), 10))
	case uint32:
		output.WriteString(strconv.FormatUint(uint64(current), 10))
	case uint64:
		output.WriteString(strconv.FormatUint(current, 10))
	case []any:
		output.WriteByte('[')
		for index, item := range current {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendValue(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			if !utf8.ValidString(key) {
				return fmt.Errorf("canonical object key is not valid UTF-8")
			}
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			return utf16Less(keys[i], keys[j])
		})
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			appendString(output, key)
			output.WriteByte(':')
			if err := appendValue(output, current[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", value)
	}
	return nil
}

func appendString(output *bytes.Buffer, value string) {
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			output.WriteString(`\"`)
		case '\\':
			output.WriteString(`\\`)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if character >= 0 && character <= 0x1f {
				output.WriteString(`\u00`)
				const digits = "0123456789abcdef"
				output.WriteByte(digits[(character>>4)&0xf])
				output.WriteByte(digits[character&0xf])
			} else {
				output.WriteRune(character)
			}
		}
	}
	output.WriteByte('"')
}

func utf16Less(left, right string) bool {
	a := utf16.Encode([]rune(left))
	b := utf16.Encode([]rune(right))
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for index := 0; index < limit; index++ {
		if a[index] != b[index] {
			return a[index] < b[index]
		}
	}
	return len(a) < len(b)
}
