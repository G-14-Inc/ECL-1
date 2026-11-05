package bindings

import "encoding/base64"

// EncodeContent returns bound content as a record holds it (MG1-012): the content read from its
// RFC 8785 canonical form, as the reference reads I-JSON, held as itself when it lies within the
// restricted canonical profile (IE1-001), and otherwise {"rfc8785": <canonical base64 of its RFC
// 8785 bytes>}. The decision is made on the content as DecodeContent reads it back: a double with
// an integral value, such as 1.0, is an integer in RFC 8785 form. The error
// is that of a value with no RFC 8785 form.
func EncodeContent(value any) (any, error) {
	data, err := JCS(value)
	if err != nil {
		return nil, err
	}
	held, err := ParseJWSJSON(data)
	if err != nil {
		return nil, err
	}
	if digestOf(held) != nil {
		return held, nil
	}
	return map[string]any{encodedMember: base64.StdEncoding.EncodeToString(data)}, nil
}
