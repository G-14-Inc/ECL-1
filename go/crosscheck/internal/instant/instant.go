// Package instant reads ECL instants: RFC 3339 UTC times with Z, whole seconds or one to nine
// fractional digits, on a calendar day that exists (years 0001 to 9999). Instants compare
// exactly, to the nanosecond.
package instant

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var pattern = regexp.MustCompile(`^([0-9]{4})-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(\.[0-9]{1,9})?Z$`)

// ErrInvalid is returned for a value that is not an ECL instant.
var ErrInvalid = errors.New("timestamp must be an ECL RFC 3339 UTC instant on a calendar date that exists")

// Instant is a time as whole seconds since 1970-01-01T00:00:00Z and nanoseconds within the second.
type Instant struct {
	Seconds int64
	Nanos   int64
}

func daysInMonth(year, month int64) int64 {
	switch month {
	case 2:
		if (year%4 == 0 && year%100 != 0) || year%400 == 0 {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	default:
		return 31
	}
}

// daysFromCivil counts days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
// algorithm).
func daysFromCivil(year, month, day int64) int64 {
	if month <= 2 {
		year--
	}
	era := year / 400
	if year < 0 && year%400 != 0 {
		era--
	}
	yearOfEra := year - era*400
	shifted := month - 3
	if month <= 2 {
		shifted = month + 9
	}
	dayOfYear := (153*shifted+2)/5 + day - 1
	dayOfEra := yearOfEra*365 + yearOfEra/4 - yearOfEra/100 + dayOfYear
	return era*146097 + dayOfEra - 719468
}

// Parse reads an ECL instant. Anything that is not a string, or not an instant, is ErrInvalid.
func Parse(value any) (Instant, error) {
	text, ok := value.(string)
	if !ok {
		return Instant{}, ErrInvalid
	}
	match := pattern.FindStringSubmatch(text)
	if match == nil {
		return Instant{}, ErrInvalid
	}
	number := func(index int) int64 {
		parsed, _ := strconv.ParseInt(match[index], 10, 64)
		return parsed
	}
	year, month, day := number(1), number(2), number(3)
	if year < 1 || day > daysInMonth(year, month) {
		return Instant{}, ErrInvalid
	}
	seconds := daysFromCivil(year, month, day)*86400 + number(4)*3600 + number(5)*60 + number(6)
	var nanos int64
	if fraction := strings.TrimPrefix(match[7], "."); fraction != "" {
		nanos, _ = strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
	}
	return Instant{Seconds: seconds, Nanos: nanos}, nil
}

// Valid reports whether value is an ECL instant (the date-time format of the ECL schemas).
func Valid(value any) bool {
	_, err := Parse(value)
	return err == nil
}

// Compare returns -1, 0 or +1 as a is before, equal to or after b.
func Compare(a, b Instant) int {
	switch {
	case a.Seconds < b.Seconds:
		return -1
	case a.Seconds > b.Seconds:
		return 1
	case a.Nanos < b.Nanos:
		return -1
	case a.Nanos > b.Nanos:
		return 1
	default:
		return 0
	}
}

// Micro returns the instant with any digit after the microsecond dropped, as the reference's
// datetime comparisons floor them.
func (i Instant) Micro() Instant {
	return Instant{Seconds: i.Seconds, Nanos: i.Nanos - i.Nanos%1000}
}

// AddSeconds returns the instant moved by whole seconds.
func (i Instant) AddSeconds(seconds int64) Instant {
	return Instant{Seconds: i.Seconds + seconds, Nanos: i.Nanos}
}

// AddNanoseconds returns the instant moved forward by a non-negative number of nanoseconds.
func (i Instant) AddNanoseconds(nanoseconds int64) Instant {
	total := i.Nanos + nanoseconds%1_000_000_000
	return Instant{Seconds: i.Seconds + nanoseconds/1_000_000_000 + total/1_000_000_000, Nanos: total % 1_000_000_000}
}
