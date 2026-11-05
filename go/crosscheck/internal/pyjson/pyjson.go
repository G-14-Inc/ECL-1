// Package pyjson reads JSON values as the strict parser returns them (map[string]any, []any,
// string, bool, nil and json.Number) with the comparisons that the ECL rules need.
//
// Several rules of the Python reference compare values with Python's own semantics, where
// true == 1, while JSON Schema keeps booleans and numbers apart. Both comparisons are here, named
// for what they mirror, so that every rule states which one it uses. An absent member reads as
// nil, the same as JSON null, as Python's dict.get reads None.
package pyjson

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Object returns value as a JSON object.
func Object(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

// Array returns value as a JSON array.
func Array(value any) ([]any, bool) {
	array, ok := value.([]any)
	return array, ok
}

// Text returns value as a string.
func Text(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok
}

// Has reports whether value is an object holding key.
func Has(value any, key string) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	_, present := object[key]
	return present
}

// Get returns the member key of value when value is an object, else nil (Python's dict.get).
func Get(value any, key string) any {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return object[key]
}

// Path returns the member at path when every step is an object holding the next key.
func Path(value any, path ...string) (any, bool) {
	current := value
	for _, step := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[step]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// TextAt returns the string at path, if there is one.
func TextAt(value any, path ...string) (string, bool) {
	found, ok := Path(value, path...)
	if !ok {
		return "", false
	}
	text, ok := found.(string)
	return text, ok
}

// ObjectAt returns the object at path, if there is one.
func ObjectAt(value any, path ...string) (map[string]any, bool) {
	found, ok := Path(value, path...)
	if !ok {
		return nil, false
	}
	object, ok := found.(map[string]any)
	return object, ok
}

// Int returns value as an integer when it is one, never a boolean (Python's type(x) is int).
func Int(value any) (int64, bool) {
	switch number := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(number.String(), 10, 64)
		return parsed, err == nil
	case int:
		return int64(number), true
	case int64:
		return number, true
	default:
		return 0, false
	}
}

// PythonInt returns value as Python's isinstance(x, int) reads it: an integer, or a boolean as
// 0 or 1, since bool subclasses int there.
func PythonInt(value any) (int64, bool) {
	if flag, ok := value.(bool); ok {
		if flag {
			return 1, true
		}
		return 0, true
	}
	return Int(value)
}

// Number returns a numeric value (not a boolean) as an exact rational.
func Number(value any) (*big.Rat, bool) {
	switch number := value.(type) {
	case json.Number:
		return new(big.Rat).SetString(number.String())
	case int:
		return new(big.Rat).SetInt64(int64(number)), true
	case int64:
		return new(big.Rat).SetInt64(number), true
	case float64:
		rational := new(big.Rat)
		if rational.SetFloat64(number) == nil {
			return nil, false
		}
		return rational, true
	default:
		return nil, false
	}
}

// Truthy is Python truthiness: nil, false, 0, "", [] and {} are false.
func Truthy(value any) bool {
	switch current := value.(type) {
	case nil:
		return false
	case bool:
		return current
	case string:
		return current != ""
	case []any:
		return len(current) > 0
	case map[string]any:
		return len(current) > 0
	default:
		if number, ok := Number(value); ok {
			return number.Sign() != 0
		}
		return true
	}
}

func numeric(value any) (*big.Rat, bool) {
	if flag, ok := value.(bool); ok {
		if flag {
			return big.NewRat(1, 1), true
		}
		return new(big.Rat), true
	}
	return Number(value)
}

// Equal is Python's == on JSON values: numbers and booleans compare by value (true == 1),
// strings only with strings, arrays element by element and objects by keys and values.
func Equal(left, right any) bool {
	leftNumber, leftNumeric := numeric(left)
	rightNumber, rightNumeric := numeric(right)
	if leftNumeric || rightNumeric {
		return leftNumeric && rightNumeric && leftNumber.Cmp(rightNumber) == 0
	}
	return structural(left, right, Equal)
}

// SchemaEqual is JSON Schema equality as python-jsonschema implements it: like Equal, except
// that a boolean never equals a number.
func SchemaEqual(left, right any) bool {
	leftFlag, leftBool := left.(bool)
	rightFlag, rightBool := right.(bool)
	if leftBool || rightBool {
		return leftBool && rightBool && leftFlag == rightFlag
	}
	leftNumber, leftNumeric := Number(left)
	rightNumber, rightNumeric := Number(right)
	if leftNumeric || rightNumeric {
		return leftNumeric && rightNumeric && leftNumber.Cmp(rightNumber) == 0
	}
	return structural(left, right, SchemaEqual)
}

func structural(left, right any, equal func(any, any) bool) bool {
	switch a := left.(type) {
	case nil:
		return right == nil
	case string:
		b, ok := right.(string)
		return ok && a == b
	case []any:
		b, ok := right.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for index := range a {
			if !equal(a[index], b[index]) {
				return false
			}
		}
		return true
	case map[string]any:
		b, ok := right.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for key, item := range a {
			other, present := b[key]
			if !present || !equal(item, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// TypeError is Python's TypeError: an operation was given a value it cannot handle, such as an
// object or array in a set-membership test. The reference turns it into a schema-invalid finding.
type TypeError struct {
	Message string
}

func (e *TypeError) Error() string { return e.Message }

// InSet is Python's value in a_set_of_strings: an object or array is unhashable, so it panics
// with a *TypeError that the caller's guard recovers, as the reference raises.
func InSet(value any, set map[string]bool) bool {
	switch current := value.(type) {
	case map[string]any, []any:
		panic(&TypeError{Message: "unhashable type in a set membership test"})
	case string:
		return set[current]
	default:
		return false
	}
}

// InList is Python's value in a_list, which compares with ==.
func InList(value any, list []any) bool {
	for _, item := range list {
		if Equal(item, value) {
			return true
		}
	}
	return false
}

// Str is Python's str() of a JSON value: a string is itself, anything else its repr.
func Str(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return Repr(value)
}

// Repr is Python's repr() of a JSON value.
func Repr(value any) string {
	switch current := value.(type) {
	case nil:
		return "None"
	case bool:
		if current {
			return "True"
		}
		return "False"
	case string:
		return stringRepr(current)
	case json.Number:
		return current.String()
	case []any:
		parts := make([]string, len(current))
		for index, item := range current {
			parts[index] = Repr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		// Go maps keep no member order; the sorted order keeps the text deterministic.
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for index, key := range keys {
			parts[index] = stringRepr(key) + ": " + Repr(current[key])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprint(current)
	}
}

func stringRepr(value string) string {
	quote := '\''
	if strings.ContainsRune(value, '\'') && !strings.ContainsRune(value, '"') {
		quote = '"'
	}
	var out strings.Builder
	out.WriteRune(quote)
	for _, character := range value {
		switch {
		case character == quote || character == '\\':
			out.WriteRune('\\')
			out.WriteRune(character)
		case character == '\t':
			out.WriteString(`\t`)
		case character == '\n':
			out.WriteString(`\n`)
		case character == '\r':
			out.WriteString(`\r`)
		case character < 0x20 || character == 0x7f:
			fmt.Fprintf(&out, `\x%02x`, character)
		case character < 0x7f:
			out.WriteRune(character)
		case !unicode.IsPrint(character):
			switch {
			case character <= 0xff:
				fmt.Fprintf(&out, `\x%02x`, character)
			case character <= 0xffff:
				fmt.Fprintf(&out, `\u%04x`, character)
			default:
				fmt.Fprintf(&out, `\U%08x`, character)
			}
		default:
			out.WriteRune(character)
		}
	}
	out.WriteRune(quote)
	return out.String()
}

// Keys returns the keys of an object in byte order, which for UTF-8 is code-point order, the
// order in which Python sorts str.
func Keys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
