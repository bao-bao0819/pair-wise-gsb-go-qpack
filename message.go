package qpack

import (
	"fmt"
	"strconv"
	"strings"
)

// MessageKind describes the role a header block plays in an HTTP/3 message.
type MessageKind int

const (
	// KindRequest is a request header block.
	KindRequest MessageKind = iota
	// KindResponse is a response header block.
	KindResponse
	// KindTrailer is a trailer section, for requests and responses alike.
	KindTrailer
)

func (k MessageKind) String() string {
	switch k {
	case KindRequest:
		return "request"
	case KindResponse:
		return "response"
	case KindTrailer:
		return "trailer"
	default:
		return fmt.Sprintf("unknown message kind %d", int(k))
	}
}

// Rule identifiers used in ValidationError.
const (
	RuleInvalidFieldName     = "invalid field name"
	RuleUppercaseFieldName   = "field name must be lowercase"
	RuleInvalidFieldValue    = "invalid character in field value"
	RulePseudoAfterRegular   = "pseudo-header field after regular header field"
	RuleDuplicatePseudo      = "duplicate pseudo-header field"
	RuleUnknownPseudo        = "pseudo-header field not allowed for this message kind"
	RuleMissingPseudo        = "required pseudo-header field missing"
	RuleForbiddenPseudo      = "pseudo-header field must not be present"
	RuleInvalidStatus        = "invalid :status value"
	RuleConnectionSpecific   = "connection-specific header field not allowed in HTTP/3"
	RuleInvalidTE            = "te header field may only carry the value \"trailers\""
	RuleInvalidContentLength = "invalid content-length value"
	RuleContentLengthClash   = "conflicting content-length values"
	RuleTrailerForbidden     = "header field not allowed in trailers"
)

// A ValidationError describes a single violation of the HTTP/3 message rules
// (RFC 9114, Section 4) found while validating a list of header fields.
type ValidationError struct {
	// Index is the position of the offending field in the validated slice.
	Index int
	// Field is the offending header field. For RuleMissingPseudo it is zero.
	Field HeaderField
	// Rule identifies the violated rule; it is one of the Rule* constants.
	Rule string
	// Detail holds additional human-readable context.
	Detail string
}

func (e *ValidationError) Error() string {
	if e.Field.Name == "" {
		return fmt.Sprintf("qpack: field %d: %s: %s", e.Index, e.Rule, e.Detail)
	}
	return fmt.Sprintf("qpack: field %d (%q): %s: %s", e.Index, e.Field.Name, e.Rule, e.Detail)
}

// A Validator checks whether an ordered list of header fields constitutes a
// valid HTTP/3 message header block or trailer section, as defined by
// RFC 9114, Section 4.3. Validation is optional: the Decoder performs no
// message validation on its own.
type Validator struct {
	extendedConnect bool
}

// A ValidatorOption configures a Validator.
type ValidatorOption func(*Validator)

// WithExtendedConnect enables validation of extended CONNECT requests
// (RFC 9220), i.e. requests carrying a :protocol pseudo-header field.
func WithExtendedConnect() ValidatorOption {
	return func(v *Validator) { v.extendedConnect = true }
}

// NewValidator returns a new Validator.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks fields according to the rules for the given message kind.
// The slice is inspected in order; duplicates are significant and are never
// collapsed. It returns the first violation found, or nil if the fields are
// valid.
func (v *Validator) Validate(kind MessageKind, fields []HeaderField) error {
	s := &messageState{kind: kind, extendedConnect: v.extendedConnect}
	for i, hf := range fields {
		if err := s.checkField(i, hf); err != nil {
			return err
		}
	}
	return s.finish()
}

type messageState struct {
	kind            MessageKind
	extendedConnect bool

	seenRegular bool
	pseudoSeen  map[string]int

	method       string
	hasScheme    bool
	hasPath      bool
	hasAuthority bool
	hasProtocol  bool

	contentLength    string
	hasContentLength bool
}

func (s *messageState) err(index int, hf HeaderField, rule, detail string) *ValidationError {
	return &ValidationError{Index: index, Field: hf, Rule: rule, Detail: detail}
}

func (s *messageState) checkField(index int, hf HeaderField) error {
	if err := checkFieldName(hf.Name); err != nil {
		return s.err(index, hf, err.Rule, err.Detail)
	}
	if detail := checkFieldValue(hf.Value); detail != "" {
		return s.err(index, hf, RuleInvalidFieldValue, detail)
	}

	if hf.IsPseudo() {
		return s.checkPseudo(index, hf)
	}
	s.seenRegular = true
	return s.checkRegular(index, hf)
}

func (s *messageState) checkPseudo(index int, hf HeaderField) error {
	if s.seenRegular {
		return s.err(index, hf, RulePseudoAfterRegular, "pseudo-header fields must precede regular header fields")
	}
	if s.pseudoSeen == nil {
		s.pseudoSeen = make(map[string]int)
	}
	if first, ok := s.pseudoSeen[hf.Name]; ok {
		return s.err(index, hf, RuleDuplicatePseudo, fmt.Sprintf("first occurrence at field %d", first))
	}
	s.pseudoSeen[hf.Name] = index

	allowed := pseudoHeadersFor(s.kind)
	if !allowed[hf.Name] {
		return s.err(index, hf, RuleUnknownPseudo, fmt.Sprintf("%s not allowed in %s", hf.Name, s.kind))
	}

	switch hf.Name {
	case ":method":
		s.method = hf.Value
	case ":scheme":
		s.hasScheme = true
	case ":path":
		s.hasPath = true
	case ":authority":
		s.hasAuthority = true
	case ":protocol":
		s.hasProtocol = true
	case ":status":
		if !isValidStatus(hf.Value) {
			return s.err(index, hf, RuleInvalidStatus, fmt.Sprintf("%q is not a three-digit status code", hf.Value))
		}
	}
	return nil
}

func (s *messageState) checkRegular(index int, hf HeaderField) error {
	switch hf.Name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return s.err(index, hf, RuleConnectionSpecific, fmt.Sprintf("%s is not allowed in HTTP/3", hf.Name))
	case "te":
		if hf.Value != "trailers" {
			return s.err(index, hf, RuleInvalidTE, fmt.Sprintf("unexpected value %q", hf.Value))
		}
	case "content-length":
		if s.kind == KindTrailer {
			return s.err(index, hf, RuleTrailerForbidden, "content-length is a message framing field")
		}
		value, detail := parseContentLength(hf.Value)
		if detail != "" {
			return s.err(index, hf, RuleInvalidContentLength, detail)
		}
		if s.hasContentLength && value != s.contentLength {
			return s.err(index, hf, RuleContentLengthClash,
				fmt.Sprintf("value %q conflicts with earlier value %q", value, s.contentLength))
		}
		s.hasContentLength = true
		s.contentLength = value
	}
	return nil
}

func (s *messageState) finish() error {
	if s.kind != KindRequest {
		if s.kind == KindResponse && !s.hasPseudo(":status") {
			return &ValidationError{Index: -1, Rule: RuleMissingPseudo, Detail: "response is missing :status"}
		}
		return nil
	}

	if s.method == "" {
		return &ValidationError{Index: -1, Rule: RuleMissingPseudo, Detail: "request is missing :method"}
	}

	if s.method == "CONNECT" {
		if s.hasProtocol {
			// Extended CONNECT (RFC 9220).
			if !s.extendedConnect {
				return &ValidationError{Index: s.pseudoSeen[":protocol"], Rule: RuleForbiddenPseudo,
					Detail: ":protocol requires extended CONNECT to be enabled"}
			}
			for _, req := range []struct {
				name string
				ok   bool
			}{
				{":scheme", s.hasScheme},
				{":path", s.hasPath},
				{":authority", s.hasAuthority},
			} {
				if !req.ok {
					return &ValidationError{Index: -1, Rule: RuleMissingPseudo,
						Detail: fmt.Sprintf("extended CONNECT request is missing %s", req.name)}
				}
			}
			return nil
		}
		// Regular CONNECT (RFC 9114, Section 4.4): :scheme and :path are omitted.
		if s.hasScheme {
			return &ValidationError{Index: s.pseudoSeen[":scheme"], Rule: RuleForbiddenPseudo,
				Detail: ":scheme must be omitted from CONNECT requests"}
		}
		if s.hasPath {
			return &ValidationError{Index: s.pseudoSeen[":path"], Rule: RuleForbiddenPseudo,
				Detail: ":path must be omitted from CONNECT requests"}
		}
		if !s.hasAuthority {
			return &ValidationError{Index: -1, Rule: RuleMissingPseudo,
				Detail: "CONNECT request is missing :authority"}
		}
		return nil
	}

	if s.hasProtocol {
		return &ValidationError{Index: s.pseudoSeen[":protocol"], Rule: RuleForbiddenPseudo,
			Detail: ":protocol is only allowed on extended CONNECT requests"}
	}
	for _, req := range []struct {
		name string
		ok   bool
	}{
		{":scheme", s.hasScheme},
		{":path", s.hasPath},
	} {
		if !req.ok {
			return &ValidationError{Index: -1, Rule: RuleMissingPseudo,
				Detail: fmt.Sprintf("request is missing %s", req.name)}
		}
	}
	return nil
}

func (s *messageState) hasPseudo(name string) bool {
	_, ok := s.pseudoSeen[name]
	return ok
}

func pseudoHeadersFor(kind MessageKind) map[string]bool {
	switch kind {
	case KindRequest:
		return map[string]bool{
			":method": true, ":scheme": true, ":authority": true,
			":path": true, ":protocol": true,
		}
	case KindResponse:
		return map[string]bool{":status": true}
	default:
		return map[string]bool{}
	}
}

var tcharTable = [256]bool{}

func init() {
	for _, c := range []byte("!#$%&'*+-.^_`|~") {
		tcharTable[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		tcharTable[c] = true
	}
	for c := byte('a'); c <= 'z'; c++ {
		tcharTable[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		tcharTable[c] = true
	}
}

func checkFieldName(name string) *ValidationError {
	if name == "" {
		return &ValidationError{Rule: RuleInvalidFieldName, Detail: "empty field name"}
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == ':' && i == 0 {
			continue // pseudo-header fields start with a colon
		}
		if c >= 'A' && c <= 'Z' {
			return &ValidationError{Rule: RuleUppercaseFieldName,
				Detail: fmt.Sprintf("uppercase character %q at position %d", string(c), i)}
		}
		if !tcharTable[c] {
			return &ValidationError{Rule: RuleInvalidFieldName,
				Detail: fmt.Sprintf("invalid character 0x%02x at position %d", c, i)}
		}
	}
	return nil
}

func checkFieldValue(value string) string {
	for i := 0; i < len(value); i++ {
		c := value[i]
		// RFC 9110, Section 5.5: field values consist of VCHAR, SP, HTAB and obs-text.
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return fmt.Sprintf("invalid control character 0x%02x at position %d", c, i)
		}
	}
	return ""
}

func isValidStatus(value string) bool {
	if len(value) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// parseContentLength validates a content-length field value. A single field
// may carry a comma-separated list (RFC 9110, Section 8.6), in which case all
// list members must be identical. It returns the canonical value.
func parseContentLength(value string) (string, string) {
	var canonical string
	for i, part := range strings.Split(value, ",") {
		part = strings.Trim(part, " \t")
		if part == "" {
			return "", fmt.Sprintf("empty list element in %q", value)
		}
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return "", fmt.Sprintf("%q is not a non-negative integer", part)
		}
		if i == 0 {
			canonical = part
		} else if part != canonical {
			return "", fmt.Sprintf("conflicting values in %q", value)
		}
	}
	return canonical, ""
}
