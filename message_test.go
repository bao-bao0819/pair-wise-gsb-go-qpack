package qpack

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func hf(name, value string) HeaderField { return HeaderField{Name: name, Value: value} }

func validRequest() []HeaderField {
	return []HeaderField{
		hf(":method", "GET"),
		hf(":scheme", "https"),
		hf(":authority", "example.com"),
		hf(":path", "/index.html"),
		hf("accept", "text/html"),
	}
}

func validConnect() []HeaderField {
	return []HeaderField{
		hf(":method", "CONNECT"),
		hf(":authority", "example.com:443"),
	}
}

func validExtendedConnect() []HeaderField {
	return []HeaderField{
		hf(":method", "CONNECT"),
		hf(":protocol", "websocket"),
		hf(":scheme", "https"),
		hf(":authority", "example.com"),
		hf(":path", "/chat"),
	}
}

func validResponse() []HeaderField {
	return []HeaderField{
		hf(":status", "200"),
		hf("content-type", "text/html"),
	}
}

func TestValidatorValidMessages(t *testing.T) {
	v := NewValidator()
	ve := NewValidator(WithExtendedConnect())

	tests := []struct {
		name      string
		validator *Validator
		kind      MessageKind
		fields    []HeaderField
	}{
		{"request", v, KindRequest, validRequest()},
		{"request with te trailers", v, KindRequest, append(validRequest(), hf("te", "trailers"))},
		{"request with consistent content-length", v, KindRequest,
			append(validRequest(), hf("content-length", "5"), hf("content-length", "5"))},
		{"request with comma-separated content-length", v, KindRequest,
			append(validRequest(), hf("content-length", "5, 5"))},
		{"connect", v, KindRequest, validConnect()},
		{"extended connect", ve, KindRequest, validExtendedConnect()},
		{"response", v, KindResponse, validResponse()},
		{"informational response", v, KindResponse, []HeaderField{hf(":status", "103"), hf("link", "</style.css>; rel=preload")}},
		{"trailer", v, KindTrailer, []HeaderField{hf("x-checksum", "abc"), hf("expires", "tomorrow")}},
		{"empty trailer", v, KindTrailer, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.validator.Validate(tc.kind, tc.fields))
		})
	}
}

func TestValidatorInvalidMessages(t *testing.T) {
	v := NewValidator()
	ve := NewValidator(WithExtendedConnect())

	tests := []struct {
		name      string
		validator *Validator
		kind      MessageKind
		fields    []HeaderField
		rule      string
		index     int // index of the offending field, -1 for missing pseudo-headers
	}{
		// field names and values
		{"empty field name", v, KindTrailer, []HeaderField{hf("", "x")}, RuleInvalidFieldName, 0},
		{"uppercase field name", v, KindResponse,
			append(validResponse(), hf("X-Bad", "1")), RuleUppercaseFieldName, 2},
		{"uppercase pseudo-header", v, KindResponse, []HeaderField{hf(":Status", "200")}, RuleUppercaseFieldName, 0},
		{"invalid character in field name", v, KindTrailer,
			[]HeaderField{hf("bad name", "1")}, RuleInvalidFieldName, 0},
		{"colon inside field name", v, KindTrailer,
			[]HeaderField{hf("bad:name", "1")}, RuleInvalidFieldName, 0},
		{"NUL in field value", v, KindResponse,
			append(validResponse(), hf("x-bad", "a\x00b")), RuleInvalidFieldValue, 2},
		{"CRLF in field value", v, KindResponse,
			append(validResponse(), hf("x-bad", "a\r\nb")), RuleInvalidFieldValue, 2},
		{"DEL in field value", v, KindResponse,
			append(validResponse(), hf("x-bad", "a\x7fb")), RuleInvalidFieldValue, 2},
		{"tab in field value is fine", v, KindResponse,
			append(validResponse(), hf("x-ok", "a\tb")), "", -1},

		// pseudo-header ordering and duplicates
		{"pseudo-header after regular field", v, KindRequest,
			[]HeaderField{hf(":method", "GET"), hf("accept", "*/*"), hf(":path", "/")},
			RulePseudoAfterRegular, 2},
		{"duplicate pseudo-header", v, KindRequest,
			[]HeaderField{hf(":method", "GET"), hf(":method", "POST")},
			RuleDuplicatePseudo, 1},
		{"duplicate content-length is not a pseudo duplicate", v, KindRequest,
			append(validRequest(), hf("content-length", "5"), hf("content-length", "5")), "", -1},

		// pseudo-header sets per role
		{"status pseudo-header in request", v, KindRequest,
			[]HeaderField{hf(":status", "200"), hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/")},
			RuleUnknownPseudo, 0},
		{"method pseudo-header in response", v, KindResponse,
			[]HeaderField{hf(":method", "GET"), hf(":status", "200")},
			RuleUnknownPseudo, 0},
		{"unknown pseudo-header in request", v, KindRequest,
			append(validRequest()[:1], hf(":made-up", "x")), RuleUnknownPseudo, 1},
		{"pseudo-header in trailer", v, KindTrailer,
			[]HeaderField{hf(":status", "200")}, RuleUnknownPseudo, 0},
		{"missing method", v, KindRequest,
			[]HeaderField{hf(":scheme", "https"), hf(":path", "/")}, RuleMissingPseudo, -1},
		{"missing scheme", v, KindRequest,
			[]HeaderField{hf(":method", "GET"), hf(":path", "/")}, RuleMissingPseudo, -1},
		{"missing path", v, KindRequest,
			[]HeaderField{hf(":method", "GET"), hf(":scheme", "https")}, RuleMissingPseudo, -1},
		{"missing status", v, KindResponse,
			[]HeaderField{hf("content-type", "text/html")}, RuleMissingPseudo, -1},

		// :status value
		{"status too short", v, KindResponse, []HeaderField{hf(":status", "20")}, RuleInvalidStatus, 0},
		{"status too long", v, KindResponse, []HeaderField{hf(":status", "2000")}, RuleInvalidStatus, 0},
		{"status not numeric", v, KindResponse, []HeaderField{hf(":status", "OK!")}, RuleInvalidStatus, 0},

		// connection-specific fields
		{"connection header", v, KindResponse,
			append(validResponse(), hf("connection", "close")), RuleConnectionSpecific, 2},
		{"keep-alive header", v, KindRequest,
			append(validRequest(), hf("keep-alive", "timeout=5")), RuleConnectionSpecific, 5},
		{"transfer-encoding header", v, KindResponse,
			append(validResponse(), hf("transfer-encoding", "chunked")), RuleConnectionSpecific, 2},
		{"upgrade header", v, KindRequest,
			append(validRequest(), hf("upgrade", "websocket")), RuleConnectionSpecific, 5},
		{"te with non-trailers value", v, KindRequest,
			append(validRequest(), hf("te", "gzip")), RuleInvalidTE, 5},
		{"connection header in trailer", v, KindTrailer,
			[]HeaderField{hf("connection", "close")}, RuleConnectionSpecific, 0},

		// content-length
		{"content-length not a number", v, KindRequest,
			append(validRequest(), hf("content-length", "five")), RuleInvalidContentLength, 5},
		{"content-length empty list element", v, KindRequest,
			append(validRequest(), hf("content-length", "5,")), RuleInvalidContentLength, 5},
		{"conflicting values within one content-length", v, KindRequest,
			append(validRequest(), hf("content-length", "5, 6")), RuleInvalidContentLength, 5},
		{"conflicting content-length fields", v, KindRequest,
			append(validRequest(), hf("content-length", "5"), hf("content-length", "6")),
			RuleContentLengthClash, 6},
		{"content-length in trailer", v, KindTrailer,
			[]HeaderField{hf("content-length", "5")}, RuleTrailerForbidden, 0},

		// CONNECT
		{"connect with scheme", v, KindRequest,
			append(validConnect(), hf(":scheme", "https")), RuleForbiddenPseudo, 2},
		{"connect with path", v, KindRequest,
			append(validConnect(), hf(":path", "/")), RuleForbiddenPseudo, 2},
		{"connect without authority", v, KindRequest,
			[]HeaderField{hf(":method", "CONNECT")}, RuleMissingPseudo, -1},

		// extended CONNECT
		{"extended connect without option", v, KindRequest,
			validExtendedConnect(), RuleForbiddenPseudo, 1},
		{"extended connect missing path", ve, KindRequest,
			[]HeaderField{hf(":method", "CONNECT"), hf(":protocol", "websocket"), hf(":scheme", "https"), hf(":authority", "example.com")},
			RuleMissingPseudo, -1},
		{"protocol pseudo-header on regular request", ve, KindRequest,
			[]HeaderField{hf(":method", "GET"), hf(":protocol", "websocket"), hf(":scheme", "https"), hf(":path", "/")},
			RuleForbiddenPseudo, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.validator.Validate(tc.kind, tc.fields)
			if tc.rule == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var verr *ValidationError
			require.True(t, errors.As(err, &verr))
			require.Equal(t, tc.rule, verr.Rule)
			require.Equal(t, tc.index, verr.Index)
		})
	}
}

// The same field list must yield different results depending on the
// message kind it is validated as.
func TestValidatorSameFieldsDifferentKinds(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name     string
		fields   []HeaderField
		request  string // expected rule, "" means valid
		response string
		trailer  string
	}{
		{
			name:     "response fields",
			fields:   validResponse(),
			request:  RuleUnknownPseudo,
			response: "",
			trailer:  RuleUnknownPseudo,
		},
		{
			name:     "request fields",
			fields:   validRequest(),
			request:  "",
			response: RuleUnknownPseudo,
			trailer:  RuleUnknownPseudo,
		},
		{
			name:     "regular fields only",
			fields:   []HeaderField{hf("x-checksum", "abc")},
			request:  RuleMissingPseudo,
			response: RuleMissingPseudo,
			trailer:  "",
		},
		{
			name:     "content-length",
			fields:   []HeaderField{hf("content-length", "5")},
			request:  RuleMissingPseudo,
			response: RuleMissingPseudo,
			trailer:  RuleTrailerForbidden,
		},
		{
			name:     "connect fields",
			fields:   validConnect(),
			request:  "",
			response: RuleUnknownPseudo,
			trailer:  RuleUnknownPseudo,
		},
		{
			name:     "extended connect fields",
			fields:   validExtendedConnect(),
			request:  RuleForbiddenPseudo, // no extended CONNECT support enabled
			response: RuleUnknownPseudo,
			trailer:  RuleUnknownPseudo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for kind, expected := range map[MessageKind]string{
				KindRequest:  tc.request,
				KindResponse: tc.response,
				KindTrailer:  tc.trailer,
			} {
				err := v.Validate(kind, tc.fields)
				if expected == "" {
					require.NoError(t, err, "kind %s", kind)
					continue
				}
				require.Error(t, err, "kind %s", kind)
				var verr *ValidationError
				require.True(t, errors.As(err, &verr), "kind %s", kind)
				require.Equal(t, expected, verr.Rule, "kind %s", kind)
			}
		})
	}
}

func TestValidationErrorMessage(t *testing.T) {
	v := NewValidator()
	err := v.Validate(KindResponse, append(validResponse(), hf("X-Bad", "1")))
	require.EqualError(t, err, `qpack: field 2 ("X-Bad"): field name must be lowercase: uppercase character "X" at position 0`)
}
