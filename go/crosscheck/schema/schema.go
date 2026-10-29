// Package schema validates JSON values against JSON Schema Draft 2020-12, for the keywords that
// the ECL-1 schemas use, and embeds those schemas. It is written to reach the same decisions as
// the reference (python-jsonschema 4.25 with the ECL format checker):
//
//   - pattern is an ECMA-262 regular expression searched anywhere in the string: $ is the end of
//     the string and . matches any code point except the four line terminators;
//   - lengths count Unicode code points, and const, enum and uniqueItems never equate a boolean
//     with a number;
//   - unevaluatedProperties treats as evaluated the members that the reference's annotation
//     collection finds: declared properties, members valid under additionalProperties, and those
//     of every allOf, anyOf and oneOf branch, if/then/else arm and $ref that the value satisfies;
//   - the date-time and uri formats are asserted, and fail for anything that is not a string;
//   - contains needs one item that its schema accepts (the default minContains of 1);
//   - a negative lookahead is matched when it follows the start anchor and a literal prefix, as
//     in ^(?!/)(?!.*\\).+$ or ^P(?!$).+$: the pattern without the lookahead must match, and the
//     lookahead's own pattern, anchored at the same place, must not.
//
// Any other keyword, any other format and any pattern that this package cannot match as
// ECMA-262 does are refused when a Set is built, so a schema that needs more than this validator
// implements fails loudly instead of being half-checked.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/generated"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/pyjson"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/strictjson"
)

// Error is one way a value fails a schema. The path is a JSON Pointer into the value; the
// message is informative.
type Error struct {
	Path    string
	Keyword string
	Message string
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Path, e.Keyword, e.Message)
}

var validationKeywords = map[string]bool{
	"$ref": true, "type": true, "required": true, "properties": true, "patternProperties": true,
	"additionalProperties": true, "unevaluatedProperties": true, "propertyNames": true,
	"dependentRequired": true, "dependentSchemas": true, "minProperties": true,
	"maxProperties": true, "items": true, "prefixItems": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "contains": true, "const": true, "enum": true, "minLength": true, "maxLength": true,
	"pattern": true, "format": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "allOf": true, "anyOf": true, "oneOf": true, "not": true, "if": true,
	"then": true, "else": true,
}

var annotationKeywords = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$comment": true, "title": true,
	"description": true, "default": true, "examples": true, "deprecated": true, "readOnly": true,
	"writeOnly": true, "contentEncoding": true, "contentMediaType": true,
}

var formats = map[string]func(any) bool{
	"date-time": IsDateTime,
	"uri":       IsURI,
}

type resolved struct {
	schema any
	base   string
}

// Set is a set of schema documents, by $id, with every reference resolvable within the set. A
// Set is safe for concurrent use.
type Set struct {
	documents map[string]map[string]any
	patterns  map[string]matcher
	cache     map[string]resolved
}

// matcher matches a string against one ECMA-262 pattern.
type matcher interface {
	MatchString(text string) bool
}

// lookahead is a pattern with negative lookaheads after its start anchor and a literal prefix:
// the text must match the pattern without them and match none of them at that place.
type lookahead struct {
	positive  *regexp.Regexp
	negatives []*regexp.Regexp
}

func (l lookahead) MatchString(text string) bool {
	if !l.positive.MatchString(text) {
		return false
	}
	for _, negative := range l.negatives {
		if negative.MatchString(text) {
			return false
		}
	}
	return true
}

// NewSet checks the documents (a map of $id to schema) and returns them as a Set.
func NewSet(documents map[string]any) (*Set, error) {
	set := &Set{
		documents: map[string]map[string]any{},
		patterns:  map[string]matcher{},
		cache:     map[string]resolved{},
	}
	for identifier, document := range documents {
		object, ok := document.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("schema %s is not an object", identifier)
		}
		set.documents[identifier] = object
	}
	for _, identifier := range pyjson.Keys(documents) {
		if err := set.prepare(set.documents[identifier], identifier, identifier); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// Identifiers returns the $ids of the set, sorted.
func (s *Set) Identifiers() []string {
	identifiers := make([]string, 0, len(s.documents))
	for identifier := range s.documents {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)
	return identifiers
}

func (s *Set) prepare(node any, base, where string) error {
	if _, ok := node.(bool); ok {
		return nil
	}
	schema, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: a schema is an object or a boolean", where)
	}
	for _, keyword := range pyjson.Keys(schema) {
		if !validationKeywords[keyword] && !annotationKeywords[keyword] {
			return fmt.Errorf("%s: unsupported schema keyword %s", where, keyword)
		}
	}
	if format, present := schema["format"]; present {
		name, ok := format.(string)
		if !ok || formats[name] == nil {
			return fmt.Errorf("%s: unsupported format %v", where, format)
		}
	}
	if pattern, ok := schema["pattern"].(string); ok {
		if err := s.compile(pattern); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	}
	if reference, ok := schema["$ref"].(string); ok {
		target, err := s.resolve(reference, base)
		if err != nil {
			return err
		}
		s.cache[base+" "+reference] = target
	}
	for _, keyword := range []string{"properties", "patternProperties", "dependentSchemas", "$defs"} {
		if children, ok := schema[keyword].(map[string]any); ok {
			for _, name := range pyjson.Keys(children) {
				if keyword == "patternProperties" {
					if err := s.compile(name); err != nil {
						return fmt.Errorf("%s: %w", where, err)
					}
				}
				if err := s.prepare(children[name], base, where); err != nil {
					return err
				}
			}
		}
	}
	for _, keyword := range []string{"additionalProperties", "unevaluatedProperties", "propertyNames", "items", "contains", "not", "if", "then", "else"} {
		if child, present := schema[keyword]; present {
			if err := s.prepare(child, base, where); err != nil {
				return err
			}
		}
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		if list, ok := schema[keyword].([]any); ok {
			for _, item := range list {
				if err := s.prepare(item, base, where); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ecmaPattern rewrites an ECMA-262 pattern for Go's regexp package. Go already reads ^ and $ as
// the start and end of the text; ECMA-262's . excludes \n, \r, U+2028 and U+2029, where Go's
// excludes only \n. Lookarounds and backreferences do not compile in Go and are refused there;
// the class escapes whose meaning differs between the two engines are refused here.
func ecmaPattern(pattern string) (string, error) {
	var out strings.Builder
	inClass := false
	for index := 0; index < len(pattern); index++ {
		character := pattern[index]
		switch {
		case character == '\\':
			if index+1 >= len(pattern) {
				return "", errors.New("pattern ends with a backslash")
			}
			next := pattern[index+1]
			if strings.IndexByte("sSwWbB", next) >= 0 {
				return "", fmt.Errorf("pattern escape \\%c differs between ECMA-262 and Go", next)
			}
			out.WriteByte(character)
			out.WriteByte(next)
			index++
		case character == '[' && !inClass:
			inClass = true
			out.WriteByte(character)
		case character == ']' && inClass:
			inClass = false
			out.WriteByte(character)
		case character == '.' && !inClass:
			out.WriteString(`[^\n\r\x{2028}\x{2029}]`)
		default:
			out.WriteByte(character)
		}
	}
	return out.String(), nil
}

func (s *Set) compile(pattern string) error {
	if _, done := s.patterns[pattern]; done {
		return nil
	}
	if strings.Contains(pattern, "(?!") {
		compiled, err := compileLookahead(pattern)
		if err != nil {
			return fmt.Errorf("unsupported pattern %q: %w", pattern, err)
		}
		s.patterns[pattern] = compiled
		return nil
	}
	compiled, err := compileECMA(pattern)
	if err != nil {
		return fmt.Errorf("unsupported pattern %q: %w", pattern, err)
	}
	s.patterns[pattern] = compiled
	return nil
}

func compileECMA(pattern string) (*regexp.Regexp, error) {
	translated, err := ecmaPattern(pattern)
	if err != nil {
		return nil, err
	}
	return regexp.Compile(translated)
}

// compileLookahead reads ^ L (?!A1)...(?!An) R, with L a literal prefix and no lookaround in R
// or any Ai, as the conjunction of ^LR with the negation of each ^L(?:Ai). The lookaheads are
// tested where the literal prefix ends, as ECMA-262 tests them; Go's regexp has no lookaround.
func compileLookahead(pattern string) (matcher, error) {
	if !strings.HasPrefix(pattern, "^") {
		return nil, errors.New("a lookahead is matched only after the start anchor")
	}
	index := 1
	for index < len(pattern) && !strings.ContainsRune(`\.+*?()|[]{}^$`, rune(pattern[index])) {
		index++
	}
	prefix := pattern[1:index]
	var negatives []string
	for strings.HasPrefix(pattern[index:], "(?!") {
		end, err := groupEnd(pattern, index)
		if err != nil {
			return nil, err
		}
		negatives = append(negatives, pattern[index+3:end])
		index = end + 1
	}
	rest := pattern[index:]
	if len(negatives) == 0 || strings.Contains(rest, "(?") {
		return nil, errors.New("a lookahead is matched only right after the start anchor and a literal prefix")
	}
	positive, err := compileECMA("^" + prefix + rest)
	if err != nil {
		return nil, err
	}
	result := lookahead{positive: positive}
	for _, inner := range negatives {
		if strings.Contains(inner, "(?=") || strings.Contains(inner, "(?!") || strings.Contains(inner, "(?<") {
			return nil, errors.New("a lookaround inside a lookahead is not supported")
		}
		negative, err := compileECMA("^" + prefix + "(?:" + inner + ")")
		if err != nil {
			return nil, err
		}
		result.negatives = append(result.negatives, negative)
	}
	return result, nil
}

// groupEnd returns the index of the parenthesis that closes the group opening at start, skipping
// escapes and character classes.
func groupEnd(pattern string, start int) (int, error) {
	depth := 0
	inClass := false
	for index := start; index < len(pattern); index++ {
		switch character := pattern[index]; {
		case character == '\\':
			index++
		case inClass:
			if character == ']' {
				inClass = false
			}
		case character == '[':
			inClass = true
		case character == '(':
			depth++
		case character == ')':
			depth--
			if depth == 0 {
				return index, nil
			}
		}
	}
	return 0, errors.New("unbalanced parentheses")
}

func (s *Set) regex(pattern string) matcher {
	return s.patterns[pattern]
}

// resolve resolves a reference (absolute, or a fragment of the base document) to its schema.
func (s *Set) resolve(reference, base string) (resolved, error) {
	if found, ok := s.cache[base+" "+reference]; ok {
		return found, nil
	}
	target, fragment, _ := strings.Cut(reference, "#")
	identifier := target
	if identifier == "" {
		identifier = base
	}
	document, ok := s.documents[identifier]
	if !ok {
		return resolved{}, fmt.Errorf("unresolvable schema reference %s", reference)
	}
	var node any = document
	if fragment != "" {
		if !strings.HasPrefix(fragment, "/") {
			return resolved{}, fmt.Errorf("unsupported schema reference %s", reference)
		}
		for _, raw := range strings.Split(fragment[1:], "/") {
			decoded, err := url.PathUnescape(raw)
			if err != nil {
				return resolved{}, fmt.Errorf("unresolvable schema reference %s", reference)
			}
			step := strings.ReplaceAll(strings.ReplaceAll(decoded, "~1", "/"), "~0", "~")
			switch current := node.(type) {
			case map[string]any:
				child, present := current[step]
				if !present {
					return resolved{}, fmt.Errorf("unresolvable schema reference %s", reference)
				}
				node = child
			case []any:
				index, err := strconv.Atoi(step)
				if err != nil || index < 0 || index >= len(current) || (len(step) > 1 && step[0] == '0') {
					return resolved{}, fmt.Errorf("unresolvable schema reference %s", reference)
				}
				node = current[index]
			default:
				return resolved{}, fmt.Errorf("unresolvable schema reference %s", reference)
			}
		}
	}
	switch node.(type) {
	case bool, map[string]any:
	default:
		return resolved{}, fmt.Errorf("schema reference %s does not name a schema", reference)
	}
	return resolved{schema: node, base: identifier}, nil
}

// Errors returns up to limit ways in which value fails the schema named by reference (an $id,
// optionally with a fragment). An unknown reference is an error.
func (s *Set) Errors(reference string, value any, limit int) ([]Error, error) {
	base, _, _ := strings.Cut(reference, "#")
	target, err := s.resolve(reference, base)
	if err != nil {
		return nil, err
	}
	out := []Error{}
	s.evaluate(target.schema, target.base, value, "", &out, limit)
	return out, nil
}

// Valid reports whether value satisfies the schema named by reference. An unknown reference is
// an error.
func (s *Set) Valid(reference string, value any) (bool, error) {
	base, _, _ := strings.Cut(reference, "#")
	target, err := s.resolve(reference, base)
	if err != nil {
		return false, err
	}
	return s.evaluate(target.schema, target.base, value, "", nil, 0), nil
}

func (s *Set) valid(schema any, base string, value any) bool {
	return s.evaluate(schema, base, value, "", nil, 0)
}

func push(out *[]Error, limit int, path, keyword, message string) {
	if len(*out) < limit {
		if path == "" {
			path = "/"
		}
		*out = append(*out, Error{Path: path, Keyword: keyword, Message: message})
	}
}

func number(value any) (int, bool) {
	if integer, ok := pyjson.Int(value); ok {
		return int(integer), true
	}
	return 0, false
}

// evaluate checks one schema node. With out nil it stops at the first failure and only answers
// validity; otherwise it records up to limit errors.
func (s *Set) evaluate(node any, base string, value any, path string, out *[]Error, limit int) bool {
	if flag, ok := node.(bool); ok {
		if !flag && out != nil {
			push(out, limit, path, "false", "no value is valid here")
		}
		return flag
	}
	schema := node.(map[string]any)
	ok := true
	// fail records a failure and reports whether evaluation stops (only when not collecting).
	fail := func(keyword, message string) bool {
		ok = false
		if out != nil {
			push(out, limit, path, keyword, message)
		}
		return out == nil
	}
	descend := func(child any, childBase string, childValue any, childPath string) bool {
		if !s.evaluate(child, childBase, childValue, childPath, out, limit) {
			ok = false
			return out == nil
		}
		return false
	}

	if reference, isText := schema["$ref"].(string); isText {
		target, err := s.resolve(reference, base)
		if err != nil {
			panic(err) // NewSet resolved every reference.
		}
		if descend(target.schema, target.base, value, path) {
			return false
		}
	}
	if kind, present := schema["type"]; present {
		types, isList := kind.([]any)
		if !isList {
			types = []any{kind}
		}
		matched := false
		for _, item := range types {
			if name, isText := item.(string); isText && hasType(value, name) {
				matched = true
				break
			}
		}
		if !matched && fail("type", fmt.Sprintf("%s is not of type %s", describe(value), describe(kind))) {
			return false
		}
	}
	if constant, present := schema["const"]; present && !pyjson.SchemaEqual(value, constant) {
		if fail("const", describe(value)+" is not the required constant") {
			return false
		}
	}
	if enumeration, isList := schema["enum"].([]any); isList {
		found := false
		for _, item := range enumeration {
			if pyjson.SchemaEqual(item, value) {
				found = true
				break
			}
		}
		if !found && fail("enum", describe(value)+" is not one of the permitted values") {
			return false
		}
	}
	if text, isText := value.(string); isText {
		length := utf8.RuneCountInString(text)
		if minimum, has := number(schema["minLength"]); has && length < minimum {
			if fail("minLength", fmt.Sprintf("string is shorter than %d characters", minimum)) {
				return false
			}
		}
		if maximum, has := number(schema["maxLength"]); has && length > maximum {
			if fail("maxLength", fmt.Sprintf("string is longer than %d characters", maximum)) {
				return false
			}
		}
		if pattern, has := schema["pattern"].(string); has && !s.regex(pattern).MatchString(text) {
			if fail("pattern", "string does not match "+pattern) {
				return false
			}
		}
	}
	if format, has := schema["format"].(string); has {
		if check := formats[format]; check != nil && !check(value) {
			if fail("format", describe(value)+" is not a "+format) {
				return false
			}
		}
	}
	if _, isBool := value.(bool); !isBool {
		if amount, isNumber := pyjson.Number(value); isNumber {
			bound := func(keyword string, refused func(int) bool, message string) bool {
				limitValue, present := pyjson.Number(schema[keyword])
				if present && refused(amount.Cmp(limitValue)) {
					return fail(keyword, fmt.Sprintf("%s %s %s", amount.RatString(), message, limitValue.RatString()))
				}
				return false
			}
			if bound("minimum", func(c int) bool { return c < 0 }, "is less than the minimum of") ||
				bound("maximum", func(c int) bool { return c > 0 }, "is greater than the maximum of") ||
				bound("exclusiveMinimum", func(c int) bool { return c <= 0 }, "is not greater than") ||
				bound("exclusiveMaximum", func(c int) bool { return c >= 0 }, "is not less than") {
				return false
			}
		}
	}
	if items, isArray := value.([]any); isArray {
		if minimum, has := number(schema["minItems"]); has && len(items) < minimum {
			if fail("minItems", fmt.Sprintf("array has fewer than %d items", minimum)) {
				return false
			}
		}
		if maximum, has := number(schema["maxItems"]); has && len(items) > maximum {
			if fail("maxItems", fmt.Sprintf("array has more than %d items", maximum)) {
				return false
			}
		}
		if schema["uniqueItems"] == true && !unique(items) {
			if fail("uniqueItems", "array has repeated items") {
				return false
			}
		}
		if contains, present := schema["contains"]; present {
			found := false
			for _, item := range items {
				if s.valid(contains, base, item) {
					found = true
					break
				}
			}
			if !found && fail("contains", "array does not contain an item that the given schema accepts") {
				return false
			}
		}
		prefix, _ := schema["prefixItems"].([]any)
		for index := 0; index < len(prefix) && index < len(items); index++ {
			if descend(prefix[index], base, items[index], path+"/"+strconv.Itoa(index)) {
				return false
			}
		}
		if itemSchema, present := schema["items"]; present && len(items) > len(prefix) {
			if itemSchema == false {
				if fail("items", fmt.Sprintf("array has more than %d items", len(prefix))) {
					return false
				}
			} else {
				for index := len(prefix); index < len(items); index++ {
					if descend(itemSchema, base, items[index], path+"/"+strconv.Itoa(index)) {
						return false
					}
				}
			}
		}
	}
	if object, isObject := value.(map[string]any); isObject {
		names := pyjson.Keys(object)
		if minimum, has := number(schema["minProperties"]); has && len(names) < minimum {
			if fail("minProperties", fmt.Sprintf("object has fewer than %d members", minimum)) {
				return false
			}
		}
		if maximum, has := number(schema["maxProperties"]); has && len(names) > maximum {
			if fail("maxProperties", fmt.Sprintf("object has more than %d members", maximum)) {
				return false
			}
		}
		if required, isList := schema["required"].([]any); isList {
			for _, item := range required {
				if name, isText := item.(string); isText {
					if _, present := object[name]; !present && fail("required", strconv.Quote(name)+" is a required member") {
						return false
					}
				}
			}
		}
		if dependent, isMap := schema["dependentRequired"].(map[string]any); isMap {
			for _, name := range pyjson.Keys(dependent) {
				needed, isList := dependent[name].([]any)
				if _, present := object[name]; !present || !isList {
					continue
				}
				for _, item := range needed {
					if other, isText := item.(string); isText {
						if _, present := object[other]; !present && fail("dependentRequired", strconv.Quote(other)+" is required when "+strconv.Quote(name)+" is present") {
							return false
						}
					}
				}
			}
		}
		properties, hasProperties := schema["properties"].(map[string]any)
		if hasProperties {
			for _, name := range pyjson.Keys(properties) {
				if member, present := object[name]; present {
					if descend(properties[name], base, member, path+"/"+escapePointer(name)) {
						return false
					}
				}
			}
		}
		patternProperties, hasPatterns := schema["patternProperties"].(map[string]any)
		if hasPatterns {
			for _, pattern := range pyjson.Keys(patternProperties) {
				for _, name := range names {
					if s.regex(pattern).MatchString(name) {
						if descend(patternProperties[pattern], base, object[name], path+"/"+escapePointer(name)) {
							return false
						}
					}
				}
			}
		}
		if additional, present := schema["additionalProperties"]; present {
			extras := []string{}
			for _, name := range names {
				if _, declared := properties[name]; declared {
					continue
				}
				matched := false
				for pattern := range patternProperties {
					if s.regex(pattern).MatchString(name) {
						matched = true
						break
					}
				}
				if !matched {
					extras = append(extras, name)
				}
			}
			if additional == false {
				if len(extras) > 0 && fail("additionalProperties", "additional members are not allowed ("+quoteAll(extras)+")") {
					return false
				}
			} else {
				for _, name := range extras {
					if descend(additional, base, object[name], path+"/"+escapePointer(name)) {
						return false
					}
				}
			}
		}
		if propertyNames, present := schema["propertyNames"]; present {
			for _, name := range names {
				if descend(propertyNames, base, name, path) {
					return false
				}
			}
		}
		if dependentSchemas, isMap := schema["dependentSchemas"].(map[string]any); isMap {
			for _, name := range pyjson.Keys(dependentSchemas) {
				if _, present := object[name]; present && descend(dependentSchemas[name], base, value, path) {
					return false
				}
			}
		}
	}
	if allOf, isList := schema["allOf"].([]any); isList {
		for _, item := range allOf {
			if descend(item, base, value, path) {
				return false
			}
		}
	}
	if anyOf, isList := schema["anyOf"].([]any); isList {
		matched := false
		for _, item := range anyOf {
			if s.valid(item, base, value) {
				matched = true
				break
			}
		}
		if !matched {
			s.branchErrors(anyOf, base, value, path, out, limit)
			if fail("anyOf", describe(value)+" is not valid under any of the given schemas") {
				return false
			}
		}
	}
	if oneOf, isList := schema["oneOf"].([]any); isList {
		matching := 0
		for _, item := range oneOf {
			if s.valid(item, base, value) {
				matching++
			}
		}
		if matching == 0 {
			s.branchErrors(oneOf, base, value, path, out, limit)
			if fail("oneOf", describe(value)+" is not valid under any of the given schemas") {
				return false
			}
		} else if matching > 1 {
			if fail("oneOf", describe(value)+" is valid under more than one of the given schemas") {
				return false
			}
		}
	}
	if not, present := schema["not"]; present && s.valid(not, base, value) {
		if fail("not", describe(value)+" matches a schema it must not match") {
			return false
		}
	}
	if condition, present := schema["if"]; present {
		if s.valid(condition, base, value) {
			if then, has := schema["then"]; has && descend(then, base, value, path) {
				return false
			}
		} else if otherwise, has := schema["else"]; has && descend(otherwise, base, value, path) {
			return false
		}
	}
	if unevaluated, present := schema["unevaluatedProperties"]; present {
		if object, isObject := value.(map[string]any); isObject {
			evaluated := map[string]bool{}
			for _, name := range s.evaluatedKeys(schema, base, object) {
				evaluated[name] = true
			}
			refused := []string{}
			for _, name := range pyjson.Keys(object) {
				if !evaluated[name] && !s.valid(unevaluated, base, object[name]) {
					refused = append(refused, name)
				}
			}
			if len(refused) > 0 && fail("unevaluatedProperties", "unevaluated members are not allowed ("+quoteAll(refused)+")") {
				return false
			}
		}
	}
	return ok
}

// branchErrors reports, for a failed anyOf or oneOf, the errors of the branch with the fewest.
func (s *Set) branchErrors(branches []any, base string, value any, path string, out *[]Error, limit int) {
	if out == nil {
		return
	}
	var best []Error
	for index, branch := range branches {
		errorsOfBranch := []Error{}
		s.evaluate(branch, base, value, path, &errorsOfBranch, limit)
		if index == 0 || len(errorsOfBranch) < len(best) {
			best = errorsOfBranch
		}
	}
	for _, item := range best {
		push(out, limit, item.Path, item.Keyword, item.Message)
	}
}

// evaluatedKeys returns the members that the reference's unevaluatedProperties counts as
// evaluated.
func (s *Set) evaluatedKeys(node any, base string, object map[string]any) []string {
	schema, isObject := node.(map[string]any)
	if !isObject {
		return nil
	}
	found := []string{}
	if reference, isText := schema["$ref"].(string); isText {
		target, err := s.resolve(reference, base)
		if err != nil {
			panic(err)
		}
		found = append(found, s.evaluatedKeys(target.schema, target.base, object)...)
	}
	if properties, isMap := schema["properties"].(map[string]any); isMap {
		for _, name := range pyjson.Keys(properties) {
			if _, present := object[name]; present {
				found = append(found, name)
			}
		}
	}
	for _, keyword := range []string{"additionalProperties", "unevaluatedProperties"} {
		if child, present := schema[keyword]; present && child != nil {
			for _, name := range pyjson.Keys(object) {
				if s.valid(child, base, object[name]) {
					found = append(found, name)
				}
			}
		}
	}
	if patternProperties, isMap := schema["patternProperties"].(map[string]any); isMap {
		for _, name := range pyjson.Keys(object) {
			for pattern := range patternProperties {
				if s.regex(pattern).MatchString(name) {
					found = append(found, name)
				}
			}
		}
	}
	if dependentSchemas, isMap := schema["dependentSchemas"].(map[string]any); isMap {
		for _, name := range pyjson.Keys(dependentSchemas) {
			if _, present := object[name]; present {
				found = append(found, s.evaluatedKeys(dependentSchemas[name], base, object)...)
			}
		}
	}
	for _, keyword := range []string{"allOf", "oneOf", "anyOf"} {
		if list, isList := schema[keyword].([]any); isList {
			for _, item := range list {
				if s.valid(item, base, object) {
					found = append(found, s.evaluatedKeys(item, base, object)...)
				}
			}
		}
	}
	if condition, present := schema["if"]; present {
		if s.valid(condition, base, object) {
			found = append(found, s.evaluatedKeys(condition, base, object)...)
			if then, has := schema["then"]; has {
				found = append(found, s.evaluatedKeys(then, base, object)...)
			}
		} else if otherwise, has := schema["else"]; has {
			found = append(found, s.evaluatedKeys(otherwise, base, object)...)
		}
	}
	return found
}

func hasType(value any, kind string) bool {
	switch kind {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "integer":
		if _, isBool := value.(bool); isBool {
			return false
		}
		amount, ok := pyjson.Number(value)
		return ok && amount.IsInt()
	case "number":
		if _, isBool := value.(bool); isBool {
			return false
		}
		_, ok := pyjson.Number(value)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	default:
		return false
	}
}

// unique reports whether no two items are equal; equal items have the same stable text, which
// keeps booleans and numbers apart.
func unique(items []any) bool {
	seen := map[string]bool{}
	for _, item := range items {
		key := stableText(item)
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func stableText(value any) string {
	switch current := value.(type) {
	case []any:
		parts := make([]string, len(current))
		for index, item := range current {
			parts[index] = stableText(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := pyjson.Keys(current)
		parts := make([]string, len(keys))
		for index, key := range keys {
			parts[index] = strconv.Quote(key) + ":" + stableText(current[key])
		}
		return "{" + strings.Join(parts, ",") + "}"
	case string:
		return strconv.Quote(current)
	case bool, nil:
		return fmt.Sprint(current)
	default:
		if amount, ok := pyjson.Number(value); ok {
			return "#" + amount.RatString()
		}
		return fmt.Sprintf("%T:%v", value, value)
	}
}

func escapePointer(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}

func quoteAll(names []string) string {
	quoted := make([]string, len(names))
	for index, name := range names {
		quoted[index] = strconv.Quote(name)
	}
	return strings.Join(quoted, ", ")
}

func describe(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	text := string(encoded)
	if utf8.RuneCountInString(text) > 60 {
		return string([]rune(text)[:59]) + "…"
	}
	return text
}

var (
	eclOnce sync.Once
	eclSet  *Set
)

// ECL returns the schemas embedded in this module: the ECL-1 wire schemas (DCMP-2, EBMP-2, the
// integrity envelope, the evidence bundle, the time attestation, the trust policy, the
// safe-state profile and the adapter binding), the registered extension value schemas, the
// records of the five binding profiles, the claim and assessment documents and every schema they
// reference.
func ECL() *Set {
	eclOnce.Do(func() {
		value, err := strictjson.Parse(generated.Schemas)
		if err != nil {
			panic(fmt.Sprintf("embedded schemas: %v", err))
		}
		documents, _ := value.(map[string]any)
		eclSet, err = NewSet(documents)
		if err != nil {
			panic(fmt.Sprintf("embedded schemas: %v", err))
		}
	})
	return eclSet
}

// Validate returns every way value fails the embedded schema named by reference (up to 1000).
// An unknown reference is an error.
func Validate(reference string, value any) ([]Error, error) {
	return ECL().Errors(reference, value, 1000)
}
