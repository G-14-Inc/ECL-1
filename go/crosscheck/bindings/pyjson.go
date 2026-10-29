package bindings

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	// errPyJSON is the cause of JSON text that Python's json.loads refuses, or of an object that
	// repeats a member name.
	errPyJSON = errors.New("not JSON as Python's json.loads reads it")
	// errRepeatedMember is the cause of an object that repeats a member name.
	errRepeatedMember = fmt.Errorf("%w: an object repeats a member name", errPyJSON)
	// errNotStrict is the cause of JSON text outside the strict profile of ECL objects (IE1-002).
	errNotStrict = errors.New("not strict JSON")
)

// The budgets and the integer range of the reference's strict JSON profile (IE1-002).
const (
	maxStrictDepth  = 256
	maxStrictNodes  = 1_000_000
	maxSafeInteger  = 9007199254740991
	maxSafeDigits   = 16
	negativeZeroInt = "-0"
)

// PythonError is an exception that the reference raises out of a check rather than reporting a
// finding (Kind is the Python exception, such as TypeError or ValueError). A checker returns it
// as its error, so that an input on which the reference fails fails here too.
type PythonError struct {
	Kind    string
	Message string
}

func (e *PythonError) Error() string { return e.Kind + ": " + e.Message }

// maxIntegerDigits is the number of digits beyond which Python 3.12 refuses to read an integer.
const maxIntegerDigits = 4300

// ParseJWSJSON reads JSON text as Python's json.loads (its C scanner) reads it with a hook that
// refuses a repeated member name. Unlike strict ECL input, a number with a fraction or an exponent
// is a float64 (an overflow is an infinity), NaN, Infinity and -Infinity are accepted, an integer
// of any size is a json.Number of its digits, and a \u escape may leave a lone surrogate, which the
// string holds in the WTF-8 form that no Unicode text has. Raw control characters, a byte-order
// mark and anything after the value are refused. The text must be UTF-8; an integer of more than
// 4300 digits is a *PythonError, as there. A JWS segment is read with ParseStrictSegment instead.
func ParseJWSJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errPyJSON
	}
	if strings.HasPrefix(string(data), "\ufeff") {
		return nil, errPyJSON
	}
	parser := &pyParser{text: string(data)}
	return parser.document()
}

// ParseStrictSegment reads a JWS segment as the reference reads it (OA1-007): under the strict
// JSON profile of ECL objects (IE1-002), with the reference's budgets. A number with a fraction
// or an exponent, NaN, Infinity, -Infinity, -0 or an integer beyond plus or minus 2^53 - 1, a lone
// surrogate, a byte-order mark, more than 256 levels of nesting or more than a million values is
// errNotStrict; an object that repeats a member name is errRepeatedMember; other text that is not
// JSON is errPyJSON. The refusals come in the order in which the reference meets them: a number
// when it is read, a repeated name when its object closes, and the rest after the whole value.
func ParseStrictSegment(data []byte) (any, error) {
	if !utf8.Valid(data) || strings.HasPrefix(string(data), "\ufeff") {
		return nil, errNotStrict
	}
	parser := &pyParser{text: string(data), strict: true}
	value, err := parser.document()
	if err != nil {
		return nil, err
	}
	if !withinStrictLimits(value) {
		return nil, errNotStrict
	}
	return value, nil
}

// withinStrictLimits reports whether a parsed value keeps the reference's budgets of depth (the
// value itself at depth 0) and values, and holds no lone surrogate in a string or a member name.
func withinStrictLimits(value any) bool {
	type pending struct {
		value any
		depth int
	}
	stack := []pending{{value, 0}}
	nodes := 0
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > maxStrictNodes || current.depth > maxStrictDepth {
			return false
		}
		switch typed := current.value.(type) {
		case string:
			if !utf8.ValidString(typed) {
				return false
			}
		case []any:
			for _, item := range typed {
				stack = append(stack, pending{item, current.depth + 1})
			}
		case map[string]any:
			for name, item := range typed {
				if !utf8.ValidString(name) {
					return false
				}
				stack = append(stack, pending{item, current.depth + 1})
			}
		}
	}
	return true
}

type pyFrame struct {
	array []any
	names []string
	items []any
	isMap bool
	key   string
}

type pyParser struct {
	text  string
	index int
	// strict refuses each number and constant outside the strict profile when it is read.
	strict bool
}

func (p *pyParser) skip() {
	for p.index < len(p.text) {
		switch p.text[p.index] {
		case ' ', '\t', '\n', '\r':
			p.index++
		default:
			return
		}
	}
}

func hexDigit(character byte) int {
	switch {
	case character >= '0' && character <= '9':
		return int(character - '0')
	case character >= 'a' && character <= 'f':
		return int(character-'a') + 10
	case character >= 'A' && character <= 'F':
		return int(character-'A') + 10
	}
	return -1
}

// appendUnit writes one UTF-16 code unit; a surrogate alone is written in WTF-8.
func appendUnit(out *strings.Builder, unit rune) {
	if unit >= 0xd800 && unit <= 0xdfff {
		out.WriteByte(byte(0xe0 | unit>>12))
		out.WriteByte(byte(0x80 | (unit>>6)&0x3f))
		out.WriteByte(byte(0x80 | unit&0x3f))
		return
	}
	out.WriteRune(unit)
}

func (p *pyParser) hex4(at int) (rune, bool) {
	var value rune
	for offset := 0; offset < 4; offset++ {
		digit := hexDigit(p.text[at+offset])
		if digit < 0 {
			return 0, false
		}
		value = value<<4 | rune(digit)
	}
	return value, true
}

// string reads a string; p.index is just after its opening quotation mark.
func (p *pyParser) string() (string, error) {
	var out strings.Builder
	start := p.index
	for {
		if p.index >= len(p.text) {
			return "", errPyJSON
		}
		character := p.text[p.index]
		switch {
		case character == '"':
			out.WriteString(p.text[start:p.index])
			p.index++
			return out.String(), nil
		case character < 0x20:
			return "", errPyJSON
		case character != '\\':
			p.index++
			continue
		}
		out.WriteString(p.text[start:p.index])
		p.index++
		if p.index >= len(p.text) {
			return "", errPyJSON
		}
		escape := p.text[p.index]
		if escape != 'u' {
			mapped, known := map[byte]string{'"': `"`, '\\': `\`, '/': "/", 'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t"}[escape]
			if !known {
				return "", errPyJSON
			}
			out.WriteString(mapped)
			p.index++
			start = p.index
			continue
		}
		if p.index+5 >= len(p.text) {
			return "", errPyJSON
		}
		unit, ok := p.hex4(p.index + 1)
		if !ok {
			return "", errPyJSON
		}
		p.index += 5
		if unit >= 0xd800 && unit <= 0xdbff && p.index+6 < len(p.text) && p.text[p.index] == '\\' && p.text[p.index+1] == 'u' {
			low, ok := p.hex4(p.index + 2)
			if !ok {
				return "", errPyJSON
			}
			if low >= 0xdc00 && low <= 0xdfff {
				out.WriteRune(0x10000 + (unit-0xd800)<<10 + (low - 0xdc00))
				p.index += 6
				start = p.index
				continue
			}
		}
		appendUnit(&out, unit)
		start = p.index
	}
}

func isDigit(character byte) bool { return character >= '0' && character <= '9' }

func (p *pyParser) number() (any, error) {
	begin := p.index
	last := len(p.text) - 1
	if p.text[p.index] == '-' {
		p.index++
		if p.index > last {
			return nil, errPyJSON
		}
	}
	switch first := p.text[p.index]; {
	case first >= '1' && first <= '9':
		p.index++
		for p.index <= last && isDigit(p.text[p.index]) {
			p.index++
		}
	case first == '0':
		p.index++
	default:
		return nil, errPyJSON
	}
	float := false
	if p.index < last && p.text[p.index] == '.' && isDigit(p.text[p.index+1]) {
		float = true
		p.index += 2
		for p.index <= last && isDigit(p.text[p.index]) {
			p.index++
		}
	}
	if p.index < last && (p.text[p.index] == 'e' || p.text[p.index] == 'E') {
		exponentStart := p.index
		p.index++
		if p.index < last && (p.text[p.index] == '-' || p.text[p.index] == '+') {
			p.index++
		}
		for p.index <= last && isDigit(p.text[p.index]) {
			p.index++
		}
		if isDigit(p.text[p.index-1]) {
			float = true
		} else {
			p.index = exponentStart
		}
	}
	literal := p.text[begin:p.index]
	if p.strict && (float || !safeInteger(literal)) {
		return nil, errNotStrict
	}
	if float {
		value, err := strconv.ParseFloat(literal, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, errPyJSON
		}
		return value, nil
	}
	if len(strings.TrimPrefix(literal, "-")) > maxIntegerDigits {
		return nil, &PythonError{Kind: "ValueError", Message: "Exceeds the limit (4300 digits) for integer string conversion"}
	}
	return json.Number(literal), nil
}

// safeInteger reports whether an integer literal is within plus or minus 2^53 - 1 and is not -0.
func safeInteger(literal string) bool {
	if literal == negativeZeroInt || len(strings.TrimPrefix(literal, "-")) > maxSafeDigits {
		return false
	}
	value, err := strconv.ParseInt(literal, 10, 64)
	return err == nil && value >= -maxSafeInteger && value <= maxSafeInteger
}

// scalar reads the scalar at p.index; container is true when an object or array starts there.
func (p *pyParser) scalar() (value any, container bool, err error) {
	if p.index >= len(p.text) {
		return nil, false, errPyJSON
	}
	rest := p.text[p.index:]
	switch p.text[p.index] {
	case '"':
		p.index++
		text, err := p.string()
		return text, false, err
	case '{', '[':
		return nil, true, nil
	case 'n':
		if strings.HasPrefix(rest, "null") {
			p.index += 4
			return nil, false, nil
		}
	case 't':
		if strings.HasPrefix(rest, "true") {
			p.index += 4
			return true, false, nil
		}
	case 'f':
		if strings.HasPrefix(rest, "false") {
			p.index += 5
			return false, false, nil
		}
	case 'N':
		if strings.HasPrefix(rest, "NaN") {
			if p.strict {
				return nil, false, errNotStrict
			}
			p.index += 3
			return math.NaN(), false, nil
		}
	case 'I':
		if strings.HasPrefix(rest, "Infinity") {
			if p.strict {
				return nil, false, errNotStrict
			}
			p.index += 8
			return math.Inf(1), false, nil
		}
	case '-':
		if strings.HasPrefix(rest, "-Infinity") {
			if p.strict {
				return nil, false, errNotStrict
			}
			p.index += 9
			return math.Inf(-1), false, nil
		}
	}
	number, err := p.number()
	return number, false, err
}

// memberName reads `"name":` and the whitespace after it.
func (p *pyParser) memberName() (string, error) {
	if p.index >= len(p.text) || p.text[p.index] != '"' {
		return "", errPyJSON
	}
	p.index++
	name, err := p.string()
	if err != nil {
		return "", err
	}
	p.skip()
	if p.index >= len(p.text) || p.text[p.index] != ':' {
		return "", errPyJSON
	}
	p.index++
	p.skip()
	return name, nil
}

func closeFrame(frame *pyFrame) (any, error) {
	if !frame.isMap {
		if frame.array == nil {
			return []any{}, nil
		}
		return frame.array, nil
	}
	object := make(map[string]any, len(frame.names))
	for index, name := range frame.names {
		if _, repeated := object[name]; repeated {
			return nil, errRepeatedMember
		}
		object[name] = frame.items[index]
	}
	return object, nil
}

// document reads one value with an explicit stack, since a 16 KiB token can nest thousands of
// levels.
func (p *pyParser) document() (any, error) {
	var stack []*pyFrame
	var result any
	p.skip()
reading:
	for {
		value, container, err := p.scalar()
		if err != nil {
			return nil, err
		}
		if container {
			opening := p.text[p.index]
			p.index++
			p.skip()
			if opening == '[' {
				if p.index < len(p.text) && p.text[p.index] == ']' {
					p.index++
					value = []any{}
				} else {
					stack = append(stack, &pyFrame{})
					continue
				}
			} else {
				if p.index < len(p.text) && p.text[p.index] == '}' {
					p.index++
					value = map[string]any{}
				} else {
					name, err := p.memberName()
					if err != nil {
						return nil, err
					}
					stack = append(stack, &pyFrame{isMap: true, key: name})
					continue
				}
			}
		}
		for {
			if len(stack) == 0 {
				result = value
				break reading
			}
			frame := stack[len(stack)-1]
			if frame.isMap {
				frame.names = append(frame.names, frame.key)
				frame.items = append(frame.items, value)
			} else {
				frame.array = append(frame.array, value)
			}
			p.skip()
			if p.index >= len(p.text) {
				return nil, errPyJSON
			}
			character := p.text[p.index]
			if character == ',' {
				p.index++
				p.skip()
				if frame.isMap {
					if frame.key, err = p.memberName(); err != nil {
						return nil, err
					}
				}
				continue reading
			}
			closing := byte(']')
			if frame.isMap {
				closing = '}'
			}
			if character != closing {
				return nil, errPyJSON
			}
			p.index++
			stack = stack[:len(stack)-1]
			if value, err = closeFrame(frame); err != nil {
				return nil, err
			}
		}
	}
	p.skip()
	if p.index != len(p.text) {
		return nil, errPyJSON
	}
	return result, nil
}
