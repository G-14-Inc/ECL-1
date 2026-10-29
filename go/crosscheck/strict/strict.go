// Package strict parses the restricted JSON in which ECL-1 objects are exchanged: one UTF-8
// value, no repeated member name, integers only (within plus or minus 2^53 - 1, without a
// fraction, exponent or negative zero), no surrogate code point or noncharacter in a string or
// member name, and bounded size and nesting.
//
// The checks run in the order of IE1-037 (INTEGRITY-ENVELOPE-1), and the first that fails decides
// the one finding of a refusal: the byte limit; UTF-8, the byte order mark and the JSON grammar;
// the nesting and value limits; the Unicode scalar values of every string and member name;
// repeated member names; numbers. Checks 3 to 6 read every value of the input, so the order of
// the checks, not the position of a defect in the text, decides the finding. This order is
// repository code, and so is the builder that makes the value once every check has passed; the
// imported core (internal/strictjson, provenance/go/GO-IMPORT.json) supplies the error type and
// the rule identifiers. The declared limits (IE1-028) are those of the reference: 256 levels of
// nesting and 1,000,000 values by default, 16 MiB of input, and a configured limit is an exact
// positive integer within its ceiling (2,147,483,647 bytes, 4,096 levels, 100,000,000 values);
// any other configured limit is refused with ecl.error.configuration-invalid.v1 before the input
// is read.
//
// The grammar and the limits are checked in one pass over the bytes that counts values and
// nesting as it reads them (IE1-029). While the input is within the limits the pass notes each
// object's member names and the first repeated name and number outside the profile; at the first
// value beyond a limit it drops them and reads the rest of the text for the grammar alone, keeping
// only the kind of each open container, so the memory that a refusal costs follows the limits, not
// the size of the input.
//
// A parsed value is built from map[string]any, []any, string, bool, nil and json.Number; every
// json.Number holds an integer.
package strict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/strictjson"
)

// The registered findings that a refusal names (IE1-037): three rules, the error of a declared
// limit, and the error of a configured limit that is not an exact positive integer within its
// ceiling (IE1-028).
const (
	RuleStrictSyntax       = "ecl.rule.json-strict-syntax.v1"
	RuleNoDuplicateMembers = strictjson.RuleNoDuplicateMembers
	RuleRestrictedNumbers  = strictjson.RuleRestrictedNumbers
	ResourceLimitExceeded  = "ecl.error.resource-limit-exceeded.v1"
	ConfigurationInvalid   = "ecl.error.configuration-invalid.v1"
)

// The limits this library declares (IE1-028), and the ceilings of the configured ones.
const (
	// MaxInputBytes bounds the encoded input.
	MaxInputBytes = 16 * 1024 * 1024
	// MaxDepth bounds the nesting depth of a value; the top-level value is at depth 0.
	MaxDepth = 256
	// MaxNodes bounds the number of values, containers included.
	MaxNodes = 1_000_000
	// MaxEntries bounds the object members and array items of the whole input: the values below
	// the top-level one.
	MaxEntries = MaxNodes - 1
	// The ceilings: a configured limit above its ceiling is a configuration error.
	MaxBytesCeiling = 2_147_483_647
	MaxDepthCeiling = 4_096
	MaxNodesCeiling = 100_000_000
	// GrammarNestingBound is the nesting depth (the top-level value at 0) to which the grammar
	// check reads an input that is beyond the limits: a value nested deeper than this and than the
	// nesting limit ends the check with a resource-limit refusal (IE1-037, check 2). The reference
	// has the same bound (ecl_reference.canonical.GRAMMAR_NESTING_BOUND).
	GrammarNestingBound = 10_000
)

// Limits are the declared limits of one parse (IE1-028). Every limit is an exact integer from 1
// to its ceiling; a parse under other limits is refused before the input is read, with
// ConfigurationInvalid.
type Limits struct {
	// MaxBytes bounds the encoded input.
	MaxBytes int
	// MaxDepth bounds the nesting depth; the top-level value is at depth 0.
	MaxDepth int
	// MaxNodes bounds the number of values, containers included.
	MaxNodes int
}

// DefaultLimits are the limits this library declares.
var DefaultLimits = Limits{MaxBytes: MaxInputBytes, MaxDepth: MaxDepth, MaxNodes: MaxNodes}

// Ceilings are the largest limits a caller may configure (IE1-028).
var Ceilings = Limits{MaxBytes: MaxBytesCeiling, MaxDepth: MaxDepthCeiling, MaxNodes: MaxNodesCeiling}

func (l Limits) check() error {
	for _, item := range []struct {
		name         string
		value, upper int
	}{{"MaxBytes", l.MaxBytes, Ceilings.MaxBytes}, {"MaxDepth", l.MaxDepth, Ceilings.MaxDepth}, {"MaxNodes", l.MaxNodes, Ceilings.MaxNodes}} {
		if item.value < 1 {
			return refuse(ConfigurationInvalid, "/", fmt.Sprintf("the limit %s must be at least 1, not %d", item.name, item.value))
		}
		if item.value > item.upper {
			return refuse(ConfigurationInvalid, "/", fmt.Sprintf("the limit %s must be at most %d, its ceiling, not %d", item.name, item.upper, item.value))
		}
	}
	return nil
}

// LimitFromJSON reads a configured limit from a JSON value (IE1-028): a json.Number or Go integer
// whose text is an exact integer from 1 to the ceiling named by `name` (MaxBytes, MaxDepth or
// MaxNodes). null, a floating-point number, a number with a fraction or an exponent, a string, a
// boolean, zero, a negative number and a value above the ceiling are refused with
// ConfigurationInvalid, so that every lane reads a configuration the same way.
func LimitFromJSON(name string, value any) (int, error) {
	upper, known := map[string]int{"MaxBytes": Ceilings.MaxBytes, "MaxDepth": Ceilings.MaxDepth, "MaxNodes": Ceilings.MaxNodes}[name]
	if !known {
		return 0, refuse(ConfigurationInvalid, "/", "unknown limit "+name)
	}
	var text string
	switch number := value.(type) {
	case json.Number:
		text = number.String()
	case int:
		text = strconv.Itoa(number)
	case int64:
		text = strconv.FormatInt(number, 10)
	default:
		return 0, refuse(ConfigurationInvalid, "/", fmt.Sprintf("the limit %s must be an integer, not %T", name, value))
	}
	if strings.ContainsAny(text, ".eE") {
		return 0, refuse(ConfigurationInvalid, "/", fmt.Sprintf("the limit %s must be an integer, not %s", name, text))
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil || parsed < 1 || parsed > int64(upper) {
		return 0, refuse(ConfigurationInvalid, "/", fmt.Sprintf("the limit %s must be an integer from 1 to %d, its ceiling", name, upper))
	}
	return int(parsed), nil
}

// maxExactInteger is 2^53 - 1, the largest integer that every JSON implementation reads exactly.
const maxExactInteger = 9007199254740991

// Error is a refusal: the finding, a JSON Pointer to where, and the reason.
type Error = strictjson.Error

func refuse(rule, path, reason string) error {
	return &Error{RuleID: rule, Path: path, Reason: reason}
}

// Parse decodes one complete JSON value under the ECL restrictions and the library's declared
// limits. A refusal is an *Error whose RuleID is the finding of the first check of IE1-037 that
// fails.
func Parse(data []byte) (any, error) {
	return ParseLimited(data, DefaultLimits)
}

// ParseLimited is Parse under the declared limits `limits`, which are checked first: a limit that
// is below 1, or above its ceiling, is refused with ConfigurationInvalid.
func ParseLimited(data []byte, limits Limits) (any, error) {
	if err := limits.check(); err != nil {
		return nil, err
	}
	// Check 1: the byte limit.
	if len(data) > limits.MaxBytes {
		return nil, refuse(ResourceLimitExceeded, "/", fmt.Sprintf("input exceeds the %d-byte parser budget", limits.MaxBytes))
	}
	// Check 2: UTF-8 without a byte order mark, then one value under the grammar of RFC 8259,
	// read in one pass with check 3, the nesting and value limits.
	if !utf8.Valid(data) {
		return nil, refuse(RuleStrictSyntax, "/", "input is not valid UTF-8")
	}
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		return nil, refuse(RuleStrictSyntax, "/", "input begins with a byte order mark")
	}
	survey, err := scan(data, limits)
	if err != nil {
		return nil, err
	}
	if survey.budget != "" {
		return nil, refuse(ResourceLimitExceeded, "/", survey.budget)
	}
	// Check 4: Unicode scalar values that are not noncharacters, in every string and member name.
	if reason := scalarProblem(data); reason != "" {
		return nil, refuse(RuleStrictSyntax, "/", reason)
	}
	// Check 5: no repeated member name.
	if survey.duplicate != "" {
		return nil, refuse(RuleNoDuplicateMembers, survey.duplicate, "duplicate object member")
	}
	// Check 6: integers within the exact range.
	if survey.number != "" {
		return nil, refuse(RuleRestrictedNumbers, survey.number, survey.numberReason)
	}
	// Every check has passed: build the value, within the limits the scan enforced.
	return build(data)
}

// build decodes text that every check of IE1-037 has passed into the parsed value:
// map[string]any, []any, string, bool, nil and json.Number, which holds an integer.
func build(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := buildValue(decoder)
	if err != nil {
		return nil, refuse(RuleStrictSyntax, "/", "invalid strict JSON: "+err.Error())
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, refuse(RuleStrictSyntax, "/", "invalid strict JSON: trailing JSON token")
	}
	return value, nil
}

func buildValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, isString := keyToken.(string)
				if !isString {
					return nil, errors.New("object member name is not a string")
				}
				member, err := buildValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = member
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				item, err := buildValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return array, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", value)
	default:
		return value, nil
	}
}

type frame struct {
	object bool
	// names holds the member names read so far, decoded, as UTF-16 code units.
	names map[string]bool
	// key is the member name being read, for a JSON Pointer.
	key string
	// next is the index of the array item being read.
	next int
}

type survey struct {
	budget       string
	duplicate    string
	number       string
	numberReason string
}

// scanner makes checks 2 and 3 of IE1-037 over grammatical UTF-8 in one pass, noting the first
// repeated member name and the first number outside the profile while the input is within the
// limits. kinds holds the open containers for the grammar (true for an object); frames holds them
// while the input is within the limits and is dropped at the first value beyond one.
type scanner struct {
	data     []byte
	at       int
	limits   Limits
	bound    int
	building bool
	nodes    int
	kinds    []bool
	frames   []*frame
	result   survey
}

func (s *scanner) peek() byte {
	if s.at < len(s.data) {
		return s.data[s.at]
	}
	return 0
}

func (s *scanner) skip() {
	for s.at < len(s.data) {
		switch s.data[s.at] {
		case ' ', '\t', '\n', '\r':
			s.at++
		default:
			return
		}
	}
}

func (s *scanner) word(word string) bool {
	return bytes.HasPrefix(s.data[s.at:], []byte(word))
}

func (s *scanner) syntax(reason string) error {
	return refuse(RuleStrictSyntax, "/", fmt.Sprintf("invalid strict JSON: %s (byte %d)", reason, s.at))
}

// path is the JSON Pointer of the value being read.
func (s *scanner) path() string {
	var out strings.Builder
	for _, open := range s.frames {
		out.WriteByte('/')
		if open.object {
			out.WriteString(escapePointer(open.key))
		} else {
			out.WriteString(strconv.Itoa(open.next))
		}
	}
	return displayPath(out.String())
}

// escapeEnd is the end of the escape at index (a backslash), or -1 when it is not a valid escape.
func (s *scanner) escapeEnd(index int) int {
	if index+1 >= len(s.data) {
		return -1
	}
	switch s.data[index+1] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return index + 2
	case 'u':
		if index+6 <= len(s.data) {
			if _, ok := hexValue(s.data[index+2 : index+6]); ok {
				return index + 6
			}
		}
	}
	return -1
}

// skipString reads the string at the current position for the grammar alone.
func (s *scanner) skipString() error {
	index := s.at + 1
	for {
		if index >= len(s.data) {
			s.at = index
			return s.syntax("unterminated string")
		}
		switch current := s.data[index]; {
		case current == '"':
			s.at = index + 1
			return nil
		case current < 0x20:
			s.at = index
			return s.syntax("invalid control character in a string")
		case current == '\\':
			next := s.escapeEnd(index)
			if next < 0 {
				s.at = index
				return s.syntax("invalid escape in a string")
			}
			index = next
		default:
			index++
		}
	}
}

// decodeString reads the string at the current position and returns its UTF-16 code units, as a
// comparable key, and its text for a JSON Pointer (a lone surrogate there is U+FFFD).
func (s *scanner) decodeString() (string, string, error) {
	start := s.at
	if err := s.skipString(); err != nil {
		return "", "", err
	}
	body := s.data[start+1 : s.at-1]
	units := []uint16{}
	for index := 0; index < len(body); {
		if body[index] != '\\' {
			code, size := utf8.DecodeRune(body[index:])
			units = utf16.AppendRune(units, code)
			index += size
			continue
		}
		switch escape := body[index+1]; escape {
		case 'u':
			value, _ := hexValue(body[index+2 : index+6])
			units = append(units, uint16(value))
			index += 6
			continue
		case 'b':
			units = append(units, '\b')
		case 'f':
			units = append(units, '\f')
		case 'n':
			units = append(units, '\n')
		case 'r':
			units = append(units, '\r')
		case 't':
			units = append(units, '\t')
		default:
			units = append(units, uint16(escape))
		}
		index += 2
	}
	key := make([]byte, 0, 2*len(units))
	for _, unit := range units {
		key = append(key, byte(unit>>8), byte(unit))
	}
	return string(key), string(utf16.Decode(units)), nil
}

// memberName reads a member name, a colon and the whitespace before the member's value.
func (s *scanner) memberName() error {
	if s.peek() != '"' {
		return s.syntax("expecting a property name enclosed in double quotes")
	}
	if s.building {
		key, text, err := s.decodeString()
		if err != nil {
			return err
		}
		top := s.frames[len(s.frames)-1]
		top.key = text
		if top.names[key] && s.result.duplicate == "" {
			s.result.duplicate = s.path()
		}
		top.names[key] = true
	} else if err := s.skipString(); err != nil {
		return err
	}
	s.skip()
	if s.peek() != ':' {
		return s.syntax("expecting ':' delimiter")
	}
	s.at++
	s.skip()
	return nil
}

// number reads a number of the grammar of RFC 8259 and reports whether there was one.
func (s *scanner) number() bool {
	index := s.at
	if index < len(s.data) && s.data[index] == '-' {
		index++
	}
	digit := func(at int) bool { return at < len(s.data) && s.data[at] >= '0' && s.data[at] <= '9' }
	if !digit(index) {
		return false
	}
	if s.data[index] == '0' {
		index++
	} else {
		for digit(index) {
			index++
		}
	}
	if index < len(s.data) && s.data[index] == '.' && digit(index+1) {
		index += 2
		for digit(index) {
			index++
		}
	}
	if index < len(s.data) && (s.data[index] == 'e' || s.data[index] == 'E') {
		after := index + 1
		if after < len(s.data) && (s.data[after] == '+' || s.data[after] == '-') {
			after++
		}
		if digit(after) {
			index = after
			for digit(index) {
				index++
			}
		}
	}
	s.at = index
	return true
}

// NodeBudgetReason is the reason of a refusal at the value limit maxNodes, by which a caller that
// passes a remaining budget as the limit tells that refusal from the others (EBMP2-062).
func NodeBudgetReason(maxNodes int) string {
	return fmt.Sprintf("the input holds more than the %d values of the parser budget", maxNodes)
}

func scan(data []byte, limits Limits) (survey, error) {
	s := &scanner{data: data, limits: limits, bound: max(GrammarNestingBound, limits.MaxDepth), building: true}
	s.skip()
	for {
		// A value begins at the current position, nested in the open containers.
		depth := len(s.kinds)
		s.nodes++
		if s.building && (s.nodes > limits.MaxNodes || depth > limits.MaxDepth) {
			if s.nodes > limits.MaxNodes {
				s.result.budget = NodeBudgetReason(limits.MaxNodes)
			} else {
				s.result.budget = fmt.Sprintf("nesting exceeds the %d-level parser budget", limits.MaxDepth)
			}
			s.building = false
			s.frames = nil
		}
		if depth > s.bound {
			return s.result, refuse(ResourceLimitExceeded, "/", "nesting exceeds the grammar parser's bound")
		}
		switch current := s.peek(); {
		case current == '{' || current == '[':
			object := current == '{'
			closing := byte(']')
			if object {
				closing = '}'
			}
			s.at++
			s.skip()
			if s.peek() == closing {
				s.at++
				break
			}
			s.kinds = append(s.kinds, object)
			if s.building {
				s.frames = append(s.frames, &frame{object: object, names: map[string]bool{}})
			}
			if object {
				if err := s.memberName(); err != nil {
					return s.result, err
				}
			}
			continue
		case current == '"':
			if err := s.skipString(); err != nil {
				return s.result, err
			}
		case s.word("null"), s.word("true"):
			s.at += 4
		case s.word("false"):
			s.at += 5
		default:
			start := s.at
			if !s.number() {
				if s.word("NaN") || s.word("Infinity") || s.word("-Infinity") {
					return s.result, refuse(RuleStrictSyntax, "/", "non-JSON numeric constant is prohibited")
				}
				return s.result, s.syntax("expecting a value")
			}
			if s.building && s.result.number == "" {
				if reason := numberProblem(data[start:s.at]); reason != "" {
					s.result.number, s.result.numberReason = s.path(), reason
				}
			}
		}
		// The value is read: close each container that ends after it.
		for {
			s.skip()
			if len(s.kinds) == 0 {
				if s.at != len(data) {
					return s.result, s.syntax("extra data after the JSON value")
				}
				return s.result, nil
			}
			object := s.kinds[len(s.kinds)-1]
			if s.building && !object {
				s.frames[len(s.frames)-1].next++
			}
			closing := byte(']')
			if object {
				closing = '}'
			}
			if s.peek() == ',' {
				s.at++
				s.skip()
				if object {
					if err := s.memberName(); err != nil {
						return s.result, err
					}
				}
				break
			}
			if s.peek() != closing {
				if object {
					return s.result, s.syntax("expecting ',' or '}'")
				}
				return s.result, s.syntax("expecting ',' or ']'")
			}
			s.at++
			s.kinds = s.kinds[:len(s.kinds)-1]
			if s.building {
				s.frames = s.frames[:len(s.frames)-1]
			}
		}
	}
}

// numberProblem describes why a number of the grammar is outside the profile, or "" when it is
// an integer within the exact range. It reads the bytes without converting them.
func numberProblem(raw []byte) string {
	if bytes.ContainsAny(raw, ".eE") {
		return "floating-point and exponent forms are prohibited"
	}
	if string(raw) == "-0" {
		return "negative zero is prohibited"
	}
	digits := bytes.TrimPrefix(raw, []byte("-"))
	if len(digits) > 16 {
		return "integer exceeds the interoperable exact range"
	}
	var value uint64
	for _, digit := range digits {
		value = value*10 + uint64(digit-'0')
	}
	if value > maxExactInteger {
		return "integer exceeds the interoperable exact range"
	}
	return ""
}

// noncharacter reports whether a code point is one of the 66 Unicode noncharacters (IE1-002).
func noncharacter(code rune) bool {
	return (code >= 0xFDD0 && code <= 0xFDEF) || code&0xFFFE == 0xFFFE
}

// scalarProblem scans the strings and member names of grammatical UTF-8 JSON and describes the
// first surrogate code point or noncharacter it holds, raw or escaped; "" when there is none.
func scalarProblem(data []byte) string {
	inString := false
	for index := 0; index < len(data); {
		current := data[index]
		if !inString {
			if current == '"' {
				inString = true
			}
			index++
			continue
		}
		switch {
		case current == '"':
			inString = false
			index++
		case current == '\\' && data[index+1] == 'u':
			code := hex4(data[index+2 : index+6])
			index += 6
			if code >= 0xD800 && code <= 0xDBFF {
				if index+6 <= len(data) && data[index] == '\\' && data[index+1] == 'u' {
					low := hex4(data[index+2 : index+6])
					if low >= 0xDC00 && low <= 0xDFFF {
						index += 6
						combined := 0x10000 + (code-0xD800)<<10 + (low - 0xDC00)
						if noncharacter(combined) {
							return fmt.Sprintf("Unicode noncharacter U+%X is prohibited", combined)
						}
						continue
					}
				}
				return "lone Unicode surrogate is prohibited"
			}
			if code >= 0xDC00 && code <= 0xDFFF {
				return "lone Unicode surrogate is prohibited"
			}
			if noncharacter(code) {
				return fmt.Sprintf("Unicode noncharacter U+%04X is prohibited", code)
			}
		case current == '\\':
			index += 2
		default:
			code, size := utf8.DecodeRune(data[index:])
			if noncharacter(code) {
				return fmt.Sprintf("Unicode noncharacter U+%04X is prohibited", code)
			}
			index += size
		}
	}
	return ""
}

func hex4(digits []byte) rune {
	value, _ := hexValue(digits)
	return value
}

// hexValue is the value of four hexadecimal digits.
func hexValue(digits []byte) (rune, bool) {
	if len(digits) != 4 {
		return 0, false
	}
	var value rune
	for _, current := range digits {
		value <<= 4
		switch {
		case current >= '0' && current <= '9':
			value |= rune(current - '0')
		case current >= 'a' && current <= 'f':
			value |= rune(current-'a') + 10
		case current >= 'A' && current <= 'F':
			value |= rune(current-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
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
