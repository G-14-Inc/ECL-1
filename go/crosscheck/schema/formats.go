package schema

import (
	"regexp"
	"strings"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/instant"
)

var (
	uriCharacters = regexp.MustCompile(`^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$`)
	percentEscape = regexp.MustCompile(`^%[0-9A-Fa-f]{2}`)
	futureHost    = regexp.MustCompile(`^v[a-fA-F0-9]+\..+$`)
	hextet        = regexp.MustCompile(`^[0-9a-fA-F]{1,4}$`)
	octet         = regexp.MustCompile(`^[0-9]{1,3}$`)
)

// IsDateTime is the date-time format: an ECL RFC 3339 UTC instant. Anything that is not a
// string fails.
func IsDateTime(value any) bool {
	return instant.Valid(value)
}

// IsURI is the uri format of IE1-038 as the reference checks it: printable ASCII whose percent
// signs start escapes, with a scheme and a non-empty authority or path as Python 3.12's
// urllib.parse.urlsplit divides it, including its checks of bracketed IPv6 hosts, and brackets
// only around an IP literal host. Anything that is not a string fails.
func IsURI(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, character := range text {
		if character <= 0x20 || character >= 0x7f || character == '\\' {
			return false
		}
	}
	if !uriCharacters.MatchString(text) {
		return false
	}
	for index := strings.IndexByte(text, '%'); index >= 0; {
		if !percentEscape.MatchString(text[index:]) {
			return false
		}
		next := strings.IndexByte(text[index+1:], '%')
		if next < 0 {
			break
		}
		index += 1 + next
	}
	parts, ok := SplitURI(text)
	if !ok {
		return false
	}
	// IE1-038: brackets in an authority enclose its host. urlsplit checks a bracketed host, but
	// accepts brackets in the user information before a host that has none.
	host := parts.Netloc[strings.LastIndexByte(parts.Netloc, '@')+1:]
	if strings.ContainsAny(parts.Netloc, "[]") && !strings.HasPrefix(host, "[") {
		return false
	}
	return parts.Scheme != "" && (parts.Netloc != "" || parts.Path != "")
}

// URIParts are the five parts of a URI as Python's urllib.parse.urlsplit divides it.
type URIParts struct {
	Scheme, Netloc, Path, Query, Fragment string
}

// usesNetloc lists the schemes that Python 3.12's urlunsplit writes with an empty authority.
var usesNetloc = map[string]bool{"": true, "ftp": true, "http": true, "gopher": true, "nntp": true,
	"telnet": true, "imap": true, "wais": true, "file": true, "mms": true, "https": true,
	"shttp": true, "snews": true, "prospero": true, "rtsp": true, "rtsps": true, "rtspu": true,
	"rsync": true, "svn": true, "svn+ssh": true, "sftp": true, "nfs": true, "git": true,
	"git+ssh": true, "ws": true, "wss": true, "itms-services": true}

// String is Python 3.12's urlunsplit of the parts.
func (p URIParts) String() string {
	url := p.Path
	switch {
	case p.Netloc != "":
		if url != "" && !strings.HasPrefix(url, "/") {
			url = "/" + url
		}
		url = "//" + p.Netloc + url
	case strings.HasPrefix(url, "//"):
		url = "//" + url
	case p.Scheme != "" && usesNetloc[p.Scheme] && (url == "" || strings.HasPrefix(url, "/")):
		url = "//" + url
	}
	if p.Scheme != "" {
		url = p.Scheme + ":" + url
	}
	if p.Query != "" {
		url += "?" + p.Query
	}
	if p.Fragment != "" {
		url += "#" + p.Fragment
	}
	return url
}

func isSchemeCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' || character == '+' || character == '.' || character == '-'
}

// SplitURI is Python 3.12's urlsplit for printable ASCII input, which it neither strips nor
// filters; ok is false where it raises ValueError.
func SplitURI(input string) (parts URIParts, ok bool) {
	url := input
	var scheme, netloc string
	if colon := strings.IndexByte(url, ':'); colon > 0 && (url[0] >= 'a' && url[0] <= 'z' || url[0] >= 'A' && url[0] <= 'Z') {
		all := true
		for index := 0; index < colon; index++ {
			if !isSchemeCharacter(url[index]) {
				all = false
				break
			}
		}
		if all {
			scheme = strings.ToLower(url[:colon])
			url = url[colon+1:]
		}
	}
	if strings.HasPrefix(url, "//") {
		delimiter := len(url)
		for _, character := range "/?#" {
			if found := strings.IndexRune(url[2:], character); found >= 0 && found+2 < delimiter {
				delimiter = found + 2
			}
		}
		netloc = url[2:delimiter]
		url = url[delimiter:]
		open, closing := strings.Contains(netloc, "["), strings.Contains(netloc, "]")
		if open != closing {
			return URIParts{}, false
		}
		if open && closing && !bracketedNetlocValid(netloc) {
			return URIParts{}, false
		}
	}
	var query, fragment string
	if hash := strings.IndexByte(url, '#'); hash >= 0 {
		url, fragment = url[:hash], url[hash+1:]
	}
	if question := strings.IndexByte(url, '?'); question >= 0 {
		url, query = url[:question], url[question+1:]
	}
	return URIParts{Scheme: scheme, Netloc: netloc, Path: url, Query: query, Fragment: fragment}, true
}

func partition(text, separator string) (string, bool, string) {
	before, after, found := strings.Cut(text, separator)
	return before, found, after
}

func bracketedNetlocValid(netloc string) bool {
	hostAndPort := netloc
	if at := strings.LastIndexByte(netloc, '@'); at >= 0 {
		hostAndPort = netloc[at+1:]
	}
	before, hasOpen, bracketed := partition(hostAndPort, "[")
	var hostname string
	if hasOpen {
		if before != "" {
			return false
		}
		host, _, port := partition(bracketed, "]")
		if port != "" && !strings.HasPrefix(port, ":") {
			return false
		}
		hostname = host
	} else {
		hostname, _, _ = partition(hostAndPort, ":")
	}
	if strings.HasPrefix(hostname, "v") {
		return futureHost.MatchString(hostname)
	}
	// Python's ipaddress.ip_address: an IPv4 address is refused in brackets, so only IPv6 passes.
	return !isIPv4(hostname) && isIPv6(hostname)
}

func isIPv4(text string) bool {
	if text == "" || strings.Contains(text, "/") {
		return false
	}
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if !octet.MatchString(part) || (part != "0" && strings.HasPrefix(part, "0")) {
			return false
		}
		value := 0
		for _, digit := range part {
			value = value*10 + int(digit-'0')
		}
		if value > 255 {
			return false
		}
	}
	return true
}

func isIPv6(text string) bool {
	if strings.Contains(text, "/") {
		return false
	}
	address, hasScope, scope := partition(text, "%")
	if hasScope && (scope == "" || strings.Contains(scope, "%")) {
		return false
	}
	if address == "" {
		return false
	}
	parts := strings.Split(address, ":")
	if len(parts) < 3 {
		return false
	}
	if strings.Contains(parts[len(parts)-1], ".") {
		last := parts[len(parts)-1]
		if !isIPv4(last) {
			return false
		}
		parts = append(parts[:len(parts)-1], "0", "0")
	}
	if len(parts) > 9 {
		return false
	}
	skip := -1
	for index := 1; index < len(parts)-1; index++ {
		if parts[index] == "" {
			if skip >= 0 {
				return false
			}
			skip = index
		}
	}
	var high, low int
	if skip >= 0 {
		high = skip
		low = len(parts) - skip - 1
		if parts[0] == "" {
			high--
			if high != 0 {
				return false
			}
		}
		if parts[len(parts)-1] == "" {
			low--
			if low != 0 {
				return false
			}
		}
		if 8-(high+low) < 1 {
			return false
		}
	} else {
		if len(parts) != 8 || parts[0] == "" || parts[len(parts)-1] == "" {
			return false
		}
		high = len(parts)
		low = 0
	}
	hextets := append([]string{}, parts[:high]...)
	if low > 0 {
		hextets = append(hextets, parts[len(parts)-low:]...)
	}
	for _, part := range hextets {
		if !hextet.MatchString(part) {
			return false
		}
	}
	return true
}
