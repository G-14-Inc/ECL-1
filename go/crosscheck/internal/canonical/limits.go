package canonical

import (
	"encoding/json"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// The finite producer limits match the reference canonicalizer. The top-level value
// is at depth zero; object member names do not count as additional JSON values.
const (
	MaxDepth      = 256
	MaxNodes      = 1_000_000
	MaxBytes      = 64 * 1024 * 1024
	resourceLimit = "ecl.error.resource-limit-exceeded.v1"
)

type valueBudget struct {
	depthLimit, nodeLimit, byteLimit int
	nodes, bytes                     int
}

func (b *valueBudget) addBytes(size int) error {
	if size > b.byteLimit-b.bytes {
		return fmt.Errorf("%s: canonical JSON exceeds the %d-byte budget", resourceLimit, b.byteLimit)
	}
	b.bytes += size
	return nil
}

// string accounts for the exact UTF-8 bytes of the shortest JSON escapes, without
// allocating a quoted copy. An input larger than the remaining output is refused first.
func (b *valueBudget) string(value string) error {
	if err := b.addBytes(2); err != nil {
		return err
	}
	if err := b.addBytes(len(value)); err != nil {
		return err
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("canonical string is not valid UTF-8")
	}
	for _, code := range value {
		if (code >= 0xFDD0 && code <= 0xFDEF) || code&0xFFFE == 0xFFFE {
			return fmt.Errorf("canonical string holds the Unicode noncharacter U+%04X", code)
		}
		extra := 0
		switch code {
		case '"', '\\', '\b', '\t', '\n', '\f', '\r':
			extra = 1
		default:
			if code < 0x20 {
				extra = 5
			}
		}
		if err := b.addBytes(extra); err != nil {
			return err
		}
	}
	return nil
}

func integerText(value any) (string, bool) {
	switch n := value.(type) {
	case json.Number:
		return n.String(), true
	case int:
		return strconv.FormatInt(int64(n), 10), true
	case int8:
		return strconv.FormatInt(int64(n), 10), true
	case int16:
		return strconv.FormatInt(int64(n), 10), true
	case int32:
		return strconv.FormatInt(int64(n), 10), true
	case int64:
		return strconv.FormatInt(n, 10), true
	case uint:
		return strconv.FormatUint(uint64(n), 10), true
	case uint8:
		return strconv.FormatUint(uint64(n), 10), true
	case uint16:
		return strconv.FormatUint(uint64(n), 10), true
	case uint32:
		return strconv.FormatUint(uint64(n), 10), true
	case uint64:
		return strconv.FormatUint(n, 10), true
	default:
		return "", false
	}
}

func checkInteger(raw string) error {
	digits := raw
	if len(digits) > 0 && digits[0] == '-' {
		digits = digits[1:]
	}
	// Bound both lexical checking and error formatting for caller-supplied json.Number.
	const exact = "9007199254740991"
	if len(digits) > len(exact) {
		return fmt.Errorf("canonical integer is outside the exact range")
	}
	if digits == "" || raw == "-0" || (len(digits) > 1 && digits[0] == '0') {
		return fmt.Errorf("canonical number is not an allowed integer: %q", raw)
	}
	for _, code := range digits {
		if code < '0' || code > '9' {
			return fmt.Errorf("canonical number is not an integer: %q", raw)
		}
	}
	if len(digits) == len(exact) && digits > exact {
		return fmt.Errorf("canonical integer is outside the exact range: %s", raw)
	}
	return nil
}

// visit is bounded before serialization or key sorting. Its recursion is at most
// depthLimit+1, including for cyclic caller-owned maps and slices.
func (b *valueBudget) visit(value any, depth int) error {
	if depth > b.depthLimit {
		return fmt.Errorf("%s: canonical JSON exceeds depth %d", resourceLimit, b.depthLimit)
	}
	if b.nodes >= b.nodeLimit {
		return fmt.Errorf("%s: canonical JSON exceeds %d nodes", resourceLimit, b.nodeLimit)
	}
	b.nodes++
	if raw, ok := integerText(value); ok {
		if err := checkInteger(raw); err != nil {
			return err
		}
		return b.addBytes(len(raw))
	}
	switch v := value.(type) {
	case nil:
		return b.addBytes(4)
	case bool:
		if v {
			return b.addBytes(4)
		}
		return b.addBytes(5)
	case string:
		return b.string(v)
	case []any:
		if len(v) > b.nodeLimit-b.nodes {
			return fmt.Errorf("%s: canonical JSON exceeds %d nodes", resourceLimit, b.nodeLimit)
		}
		punctuation := 2
		if len(v) > 0 {
			punctuation += len(v) - 1
		}
		if err := b.addBytes(punctuation); err != nil {
			return err
		}
		for _, item := range v {
			if err := b.visit(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if len(v) > b.nodeLimit-b.nodes {
			return fmt.Errorf("%s: canonical JSON exceeds %d nodes", resourceLimit, b.nodeLimit)
		}
		punctuation := 2
		if len(v) > 0 {
			punctuation += 2*len(v) - 1
		}
		if err := b.addBytes(punctuation); err != nil {
			return err
		}
		for key, item := range v {
			if err := b.string(key); err != nil {
				return err
			}
			if err := b.visit(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", value)
	}
}

func validateValue(value any) error {
	budget := valueBudget{depthLimit: MaxDepth, nodeLimit: MaxNodes, byteLimit: MaxBytes}
	return budget.visit(value, 0)
}
