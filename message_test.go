package qpack

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMessageValidator(t *testing.T) {
	validRequest := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
		{Name: "user-agent", Value: "test"},
	}
	validResponse := []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/html"},
	}
	validTrailer := []HeaderField{
		{Name: "x-checksum", Value: "abc"},
	}
	validConnect := []HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: "example.com:443"},
	}
	validExtendedConnect := []HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/chat"},
	}

	tests := []struct {
		name            string
		typ             MessageType
		extendedConnect bool
		fields          []HeaderField
		wantErr         string // empty means valid
		wantIndex       int    // only checked when wantErr is set; -1 matches any
	}{
		// requests
		{name: "valid request", typ: MessageTypeRequest, fields: validRequest},
		{name: "valid request with host instead of authority", typ: MessageTypeRequest, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/"},
			{Name: "host", Value: "example.com"},
		}},
		{name: "request missing :method", typ: MessageTypeRequest, wantErr: "missing :method", wantIndex: -1, fields: []HeaderField{
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/"},
		}},
		{name: "request missing :scheme", typ: MessageTypeRequest, wantErr: "missing :scheme", wantIndex: -1, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/"},
		}},
		{name: "request missing :path", typ: MessageTypeRequest, wantErr: "missing :path", wantIndex: -1, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
		}},
		{name: "request missing :authority and host", typ: MessageTypeRequest, wantErr: "missing :authority", wantIndex: -1, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/"},
		}},
		{name: "request with :status", typ: MessageTypeRequest, wantErr: "not allowed in request", wantIndex: 1, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":status", Value: "200"},
		}},
		// responses
		{name: "valid response", typ: MessageTypeResponse, fields: validResponse},
		{name: "valid informational response", typ: MessageTypeResponse, fields: []HeaderField{
			{Name: ":status", Value: "103"},
			{Name: "link", Value: "</style.css>; rel=preload"},
		}},
		{name: "response missing :status", typ: MessageTypeResponse, wantErr: "missing :status", wantIndex: -1, fields: []HeaderField{
			{Name: "content-type", Value: "text/html"},
		}},
		{name: "response with invalid :status", typ: MessageTypeResponse, wantErr: "invalid :status", wantIndex: 0, fields: []HeaderField{
			{Name: ":status", Value: "20"},
		}},
		{name: "response with non-numeric :status", typ: MessageTypeResponse, wantErr: "invalid :status", wantIndex: 0, fields: []HeaderField{
			{Name: ":status", Value: "2x0"},
		}},
		{name: "response with :method", typ: MessageTypeResponse, wantErr: "not allowed in response", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: ":method", Value: "GET"},
		}},
		// trailers
		{name: "valid trailer", typ: MessageTypeTrailer, fields: validTrailer},
		{name: "empty trailer", typ: MessageTypeTrailer, fields: nil},
		{name: "trailer with pseudo-header", typ: MessageTypeTrailer, wantErr: "not allowed in trailer", wantIndex: 0, fields: []HeaderField{
			{Name: ":status", Value: "200"},
		}},
		// pseudo-header ordering and duplication
		{name: "pseudo-header after regular field", typ: MessageTypeRequest, wantErr: "after regular header field", wantIndex: 2, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: "user-agent", Value: "test"},
			{Name: ":path", Value: "/"},
		}},
		{name: "duplicate pseudo-header", typ: MessageTypeRequest, wantErr: "duplicate pseudo-header", wantIndex: 3, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/"},
			{Name: ":path", Value: "/other"},
		}},
		{name: "unknown pseudo-header", typ: MessageTypeRequest, wantErr: "not allowed in request", wantIndex: 0, fields: []HeaderField{
			{Name: ":foobar", Value: "x"},
		}},
		// field names and values
		{name: "uppercase field name", typ: MessageTypeResponse, wantErr: "must be lowercase", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "Content-Type", Value: "text/html"},
		}},
		{name: "invalid character in field name", typ: MessageTypeResponse, wantErr: "invalid field name", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "cont ent", Value: "x"},
		}},
		{name: "empty field name", typ: MessageTypeResponse, wantErr: "empty field name", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "", Value: "x"},
		}},
		{name: "value with NUL", typ: MessageTypeResponse, wantErr: "contains NUL", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "x-a", Value: "a\x00b"},
		}},
		{name: "value with CR LF", typ: MessageTypeResponse, wantErr: "contains CR or LF", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "x-a", Value: "a\r\nb"},
		}},
		{name: "value with control character", typ: MessageTypeResponse, wantErr: "invalid control character", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "x-a", Value: "a\x07b"},
		}},
		{name: "value with trailing whitespace", typ: MessageTypeResponse, wantErr: "whitespace", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "x-a", Value: "abc "},
		}},
		// connection-specific fields and te
		{name: "connection field", typ: MessageTypeResponse, wantErr: "connection-specific", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "connection", Value: "close"},
		}},
		{name: "transfer-encoding field", typ: MessageTypeResponse, wantErr: "connection-specific", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "transfer-encoding", Value: "chunked"},
		}},
		{name: "te trailers", typ: MessageTypeRequest, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/"},
			{Name: "te", Value: "trailers"},
		}},
		{name: "te with other value", typ: MessageTypeRequest, wantErr: `must be "trailers"`, wantIndex: 4, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/"},
			{Name: "te", Value: "gzip"},
		}},
		// content-length
		{name: "matching duplicate content-length", typ: MessageTypeResponse, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: "42"},
			{Name: "content-length", Value: "42"},
		}},
		{name: "content-length list", typ: MessageTypeResponse, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: "42, 42"},
		}},
		{name: "mismatching content-length", typ: MessageTypeResponse, wantErr: "inconsistent content-length", wantIndex: 2, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: "42"},
			{Name: "content-length", Value: "43"},
		}},
		{name: "invalid content-length", typ: MessageTypeResponse, wantErr: "invalid content-length", wantIndex: 1, fields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: "fourty-two"},
		}},
		// CONNECT
		{name: "valid CONNECT", typ: MessageTypeRequest, fields: validConnect},
		{name: "CONNECT with :scheme", typ: MessageTypeRequest, wantErr: ":scheme not allowed on CONNECT", wantIndex: 1, fields: []HeaderField{
			{Name: ":method", Value: "CONNECT"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com:443"},
		}},
		{name: "CONNECT with :path", typ: MessageTypeRequest, wantErr: ":path not allowed on CONNECT", wantIndex: 1, fields: []HeaderField{
			{Name: ":method", Value: "CONNECT"},
			{Name: ":path", Value: "/"},
			{Name: ":authority", Value: "example.com:443"},
		}},
		{name: "CONNECT missing :authority", typ: MessageTypeRequest, wantErr: "CONNECT request missing :authority", wantIndex: -1, fields: []HeaderField{
			{Name: ":method", Value: "CONNECT"},
		}},
		// extended CONNECT
		{name: "valid extended CONNECT", typ: MessageTypeRequest, extendedConnect: true, fields: validExtendedConnect},
		{name: "extended CONNECT not enabled", typ: MessageTypeRequest, wantErr: "extended CONNECT not enabled", wantIndex: 1, fields: validExtendedConnect},
		{name: "extended CONNECT missing :path", typ: MessageTypeRequest, extendedConnect: true, wantErr: "missing :path", wantIndex: -1, fields: []HeaderField{
			{Name: ":method", Value: "CONNECT"},
			{Name: ":protocol", Value: "websocket"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
		}},
		{name: ":protocol on non-CONNECT", typ: MessageTypeRequest, extendedConnect: true, wantErr: "only allowed on CONNECT", wantIndex: 1, fields: []HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":protocol", Value: "websocket"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/"},
		}},
		// the same fields under different message types
		{name: "request fields as response", typ: MessageTypeResponse, wantErr: "not allowed in response", wantIndex: 0, fields: validRequest},
		{name: "request fields as trailer", typ: MessageTypeTrailer, wantErr: "not allowed in trailer", wantIndex: 0, fields: validRequest},
		{name: "response fields as request", typ: MessageTypeRequest, wantErr: "not allowed in request", wantIndex: 0, fields: validResponse},
		{name: "response fields as trailer", typ: MessageTypeTrailer, wantErr: "not allowed in trailer", wantIndex: 0, fields: validResponse},
		{name: "CONNECT fields as response", typ: MessageTypeResponse, wantErr: "not allowed in response", wantIndex: 0, fields: validConnect},
		{name: "extended CONNECT fields as response", typ: MessageTypeResponse, extendedConnect: true, wantErr: "not allowed in response", wantIndex: 0, fields: validExtendedConnect},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := MessageValidator{ExtendedConnect: tc.extendedConnect}
			err := v.Validate(tc.fields, tc.typ)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
			var mve *MessageValidationError
			require.True(t, errors.As(err, &mve))
			if tc.wantIndex >= 0 {
				require.Equal(t, tc.wantIndex, mve.Index)
			}
		})
	}
}

func TestMessageValidatorErrorFormatting(t *testing.T) {
	err := (&MessageValidationError{Index: 3, Field: "te", Rule: `te field value must be "trailers"`}).Error()
	require.Contains(t, err, "3")
	require.Contains(t, err, "te")
	require.Contains(t, err, "trailers")

	err = (&MessageValidationError{Index: -1, Field: ":method", Rule: "request missing :method pseudo-header field"}).Error()
	require.Contains(t, err, "missing :method")
}
