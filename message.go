package qpack

import (
	"fmt"
	"strconv"
	"strings"
)

// MessageType identifies the role of a sequence of header fields
// within an HTTP/3 message exchange.
type MessageType int

const (
	// MessageTypeRequest is a request header block.
	MessageTypeRequest MessageType = iota
	// MessageTypeResponse is a response header block (informational or final).
	MessageTypeResponse
	// MessageTypeTrailer is a trailer section.
	MessageTypeTrailer
)

func (t MessageType) String() string {
	switch t {
	case MessageTypeRequest:
		return "request"
	case MessageTypeResponse:
		return "response"
	case MessageTypeTrailer:
		return "trailer"
	}
	return fmt.Sprintf("unknown message type %d", int(t))
}

// A MessageValidationError describes a violation of the HTTP/3 message
// rules (RFC 9114, Section 4) found in a sequence of header fields.
type MessageValidationError struct {
	// Index is the index of the offending header field in the validated
	// sequence. It is -1 if the error is not tied to a specific field,
	// e.g. when a required pseudo-header field is missing.
	Index int
	// Field is the name of the offending header field, if applicable.
	Field string
	// Rule describes the violated rule.
	Rule string
}

func (e *MessageValidationError) Error() string {
	if e.Index >= 0 {
		return fmt.Sprintf("qpack: invalid field %d (%q): %s", e.Index, e.Field, e.Rule)
	}
	return fmt.Sprintf("qpack: invalid message: %s", e.Rule)
}

// A MessageValidator validates a decoded sequence of header fields against
// the HTTP/3 message rules (RFC 9114, Section 4). Validation is optional:
// the Decoder does not apply it, callers opt in explicitly.
//
// The sequence is validated as-is, preserving order and duplicates;
// fields are never merged into a map or joined with commas.
type MessageValidator struct {
	// ExtendedConnect enables support for the extended CONNECT protocol
	// (RFC 9220), i.e. requests carrying a :protocol pseudo-header field.
	// When false, any :protocol pseudo-header field is rejected.
	ExtendedConnect bool
}

// connection-specific header fields are forbidden in HTTP/3
// (RFC 9114, Section 4.2).
var connectionSpecificFields = []string{
	"connection",
	"keep-alive",
	"proxy-connection",
	"transfer-encoding",
	"upgrade",
}

// Validate checks that fields form a valid header block for the given
// message type. It returns the first violation found, as a
// *MessageValidationError, or nil if the sequence is valid.
func (v MessageValidator) Validate(fields []HeaderField, typ MessageType) error {
	var (
		seenRegular         bool
		pseudos             = make(map[string]int)
		hasHost             bool
		contentLengthIdx    []int
		contentLengthValues []string
	)
	for i, hf := range fields {
		if hf.Name == "" {
			return &MessageValidationError{Index: i, Rule: "empty field name"}
		}
		if hf.IsPseudo() {
			if seenRegular {
				return &MessageValidationError{Index: i, Field: hf.Name, Rule: "pseudo-header field after regular header field"}
			}
			if !isValidFieldName(hf.Name[1:]) {
				return &MessageValidationError{Index: i, Field: hf.Name, Rule: "invalid pseudo-header field name"}
			}
			if first, ok := pseudos[hf.Name]; ok {
				return &MessageValidationError{Index: i, Field: hf.Name, Rule: fmt.Sprintf("duplicate pseudo-header field (first occurrence at index %d)", first)}
			}
			pseudos[hf.Name] = i
			if !isAllowedPseudoHeader(typ, hf.Name) {
				return &MessageValidationError{Index: i, Field: hf.Name, Rule: fmt.Sprintf("pseudo-header field not allowed in %s", typ)}
			}
		} else {
			seenRegular = true
			if !isValidFieldName(hf.Name) {
				return &MessageValidationError{Index: i, Field: hf.Name, Rule: "invalid field name (must be lowercase)"}
			}
			for _, f := range connectionSpecificFields {
				if hf.Name == f {
					return &MessageValidationError{Index: i, Field: hf.Name, Rule: "connection-specific header field not allowed in HTTP/3"}
				}
			}
			switch hf.Name {
			case "te":
				// RFC 9113, Section 8.2.2: the only valid value is "trailers".
				if hf.Value != "trailers" {
					return &MessageValidationError{Index: i, Field: hf.Name, Rule: `te field value must be "trailers"`}
				}
			case "content-length":
				contentLengthIdx = append(contentLengthIdx, i)
				contentLengthValues = append(contentLengthValues, hf.Value)
			case "host":
				hasHost = true
			}
		}
		if err := validateFieldValue(hf.Value); err != "" {
			return &MessageValidationError{Index: i, Field: hf.Name, Rule: err}
		}
	}

	if err := validateContentLength(contentLengthIdx, contentLengthValues); err != nil {
		return err
	}

	switch typ {
	case MessageTypeRequest:
		return v.validateRequest(fields, pseudos, hasHost)
	case MessageTypeResponse:
		return validateResponse(fields, pseudos)
	case MessageTypeTrailer:
		// Pseudo-header fields are not allowed in trailers; this was
		// already rejected by isAllowedPseudoHeader.
		return nil
	}
	return &MessageValidationError{Index: -1, Rule: fmt.Sprintf("unknown message type %d", int(typ))}
}

func isAllowedPseudoHeader(typ MessageType, name string) bool {
	switch typ {
	case MessageTypeRequest:
		switch name {
		case ":method", ":scheme", ":authority", ":path", ":protocol":
			return true
		}
	case MessageTypeResponse:
		return name == ":status"
	case MessageTypeTrailer:
		return false
	}
	return false
}

func (v MessageValidator) validateRequest(fields []HeaderField, pseudos map[string]int, hasHost bool) error {
	methodIdx, ok := pseudos[":method"]
	if !ok {
		return &MessageValidationError{Index: -1, Field: ":method", Rule: "request missing :method pseudo-header field"}
	}
	method := fields[methodIdx].Value
	protocolIdx, hasProtocol := pseudos[":protocol"]
	_, hasScheme := pseudos[":scheme"]
	_, hasPath := pseudos[":path"]
	_, hasAuthority := pseudos[":authority"]

	if method == "CONNECT" {
		if hasProtocol {
			// Extended CONNECT (RFC 9220, Section 3).
			if !v.ExtendedConnect {
				return &MessageValidationError{Index: protocolIdx, Field: ":protocol", Rule: "extended CONNECT not enabled"}
			}
			if !hasScheme {
				return &MessageValidationError{Index: -1, Field: ":scheme", Rule: "extended CONNECT request missing :scheme pseudo-header field"}
			}
			if !hasPath {
				return &MessageValidationError{Index: -1, Field: ":path", Rule: "extended CONNECT request missing :path pseudo-header field"}
			}
			if !hasAuthority {
				return &MessageValidationError{Index: -1, Field: ":authority", Rule: "extended CONNECT request missing :authority pseudo-header field"}
			}
		} else {
			// Regular CONNECT (RFC 9114, Section 4.4): :scheme and :path
			// MUST be omitted, :authority MUST be present.
			if schemeIdx, ok := pseudos[":scheme"]; ok {
				return &MessageValidationError{Index: schemeIdx, Field: ":scheme", Rule: ":scheme not allowed on CONNECT requests"}
			}
			if pathIdx, ok := pseudos[":path"]; ok {
				return &MessageValidationError{Index: pathIdx, Field: ":path", Rule: ":path not allowed on CONNECT requests"}
			}
			if !hasAuthority {
				return &MessageValidationError{Index: -1, Field: ":authority", Rule: "CONNECT request missing :authority pseudo-header field"}
			}
		}
	} else {
		if hasProtocol {
			return &MessageValidationError{Index: protocolIdx, Field: ":protocol", Rule: ":protocol only allowed on CONNECT requests"}
		}
		if !hasScheme {
			return &MessageValidationError{Index: -1, Field: ":scheme", Rule: "request missing :scheme pseudo-header field"}
		}
		if !hasPath {
			return &MessageValidationError{Index: -1, Field: ":path", Rule: "request missing :path pseudo-header field"}
		}
	}
	// Every request MUST include either :authority or Host
	// (RFC 9114, Section 4.3.1).
	if !hasAuthority && !hasHost {
		return &MessageValidationError{Index: -1, Field: ":authority", Rule: "request missing :authority pseudo-header field and host header field"}
	}
	return nil
}

func validateResponse(fields []HeaderField, pseudos map[string]int) error {
	statusIdx, ok := pseudos[":status"]
	if !ok {
		return &MessageValidationError{Index: -1, Field: ":status", Rule: "response missing :status pseudo-header field"}
	}
	status := fields[statusIdx].Value
	if len(status) != 3 {
		return &MessageValidationError{Index: statusIdx, Field: ":status", Rule: "invalid :status value (must be 3 digits)"}
	}
	for i := 0; i < 3; i++ {
		if status[i] < '0' || status[i] > '9' {
			return &MessageValidationError{Index: statusIdx, Field: ":status", Rule: "invalid :status value (must be 3 digits)"}
		}
	}
	return nil
}

// isValidFieldName reports whether name is a valid HTTP/3 field name:
// a non-empty token (RFC 9110, Section 5.1) containing no uppercase
// characters (RFC 9113, Section 8.2.1).
func isValidFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
			c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
			c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

// validateFieldValue checks a field value for characters that make a
// message malformed (RFC 9113, Section 8.2.1): NUL, CR, LF, other
// disallowed control characters, and leading or trailing whitespace.
func validateFieldValue(value string) string {
	if len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t') {
		return "field value has leading or trailing whitespace"
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == 0x0 {
			return "field value contains NUL"
		}
		if c == '\r' || c == '\n' {
			return "field value contains CR or LF"
		}
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return "field value contains invalid control character"
		}
	}
	return ""
}

// validateContentLength checks that all content-length values are valid
// and consistent (RFC 9110, Section 8.6). A field value may itself be a
// comma-separated list; all elements across all fields must be equal.
func validateContentLength(indices []int, values []string) error {
	var (
		expected uint64
		seen     bool
	)
	for i, v := range values {
		for _, elem := range strings.Split(v, ",") {
			elem = strings.TrimSpace(elem)
			if !isDigits(elem) {
				return &MessageValidationError{Index: indices[i], Field: "content-length", Rule: "invalid content-length value"}
			}
			n, err := strconv.ParseUint(elem, 10, 64)
			if err != nil {
				return &MessageValidationError{Index: indices[i], Field: "content-length", Rule: "invalid content-length value"}
			}
			if !seen {
				expected, seen = n, true
				continue
			}
			if n != expected {
				return &MessageValidationError{Index: indices[i], Field: "content-length", Rule: fmt.Sprintf("inconsistent content-length values (%d != %d)", n, expected)}
			}
		}
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
