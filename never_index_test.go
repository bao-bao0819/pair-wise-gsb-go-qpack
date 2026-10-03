package qpack

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/stretchr/testify/require"
)

// errReject is returned by test policies that reject a field.
var errReject = errors.New("rejected by policy")

// parseLiteralWithNameReference reads a literal header field with name
// reference (01NTxxxx) from data and returns the decoded field, the N bit and
// the remaining bytes.
func parseLiteralWithNameReference(t *testing.T, data []byte, hf HeaderField, wantN bool) []byte {
	t.Helper()
	require.Equal(t, uint8(0x1), data[0]>>6)    // 01NTxxxx
	require.Equal(t, wantN, data[0]&0x20 > 0)   // N bit
	require.Equal(t, uint8(1), data[0]&0x10>>4) // T bit
	index, rest, err := readVarInt(4, data)
	require.NoError(t, err)
	require.Equal(t, hf.Name, staticTableEntries[index].Name)

	usesHuffman := rest[0]&0x80 > 0
	valueLen, rest, err := readVarInt(7, rest)
	require.NoError(t, err)
	var value string
	if usesHuffman {
		value, err = hpack.HuffmanDecodeToString(rest[:valueLen])
		require.NoError(t, err)
	} else {
		value = string(rest[:valueLen])
	}
	require.Equal(t, hf.Value, value)
	return rest[valueLen:]
}

// parseLiteralWithoutNameReference reads a literal header field without name
// reference (001Nxxxx) from data and returns the remaining bytes.
func parseLiteralWithoutNameReference(t *testing.T, data []byte, hf HeaderField, wantN bool) []byte {
	t.Helper()
	require.Equal(t, uint8(0x1), data[0]>>5)  // 001Nxxxx
	require.Equal(t, wantN, data[0]&0x10 > 0) // N bit

	usesHuffmanForName := data[0]&0x8 > 0
	nameLen, afterNameLen, err := readVarInt(3, data)
	require.NoError(t, err)
	var name string
	if usesHuffmanForName {
		name, err = hpack.HuffmanDecodeToString(afterNameLen[:nameLen])
		require.NoError(t, err)
	} else {
		name = string(afterNameLen[:nameLen])
	}
	require.Equal(t, hf.Name, name)

	valueStart := afterNameLen[nameLen:]
	usesHuffmanForValue := valueStart[0]&0x80 > 0
	valueLen, rest, err := readVarInt(7, valueStart)
	require.NoError(t, err)
	var value string
	if usesHuffmanForValue {
		value, err = hpack.HuffmanDecodeToString(rest[:valueLen])
		require.NoError(t, err)
	} else {
		value = string(rest[:valueLen])
	}
	require.Equal(t, hf.Value, value)
	return rest[valueLen:]
}

// appendRawLiteralWithoutNameReference builds a literal header field without
// name reference, using non-Huffman name and value. n sets the N bit.
func appendRawLiteralWithoutNameReference(dst []byte, name, value string, n bool) []byte {
	offset := len(dst)
	dst = appendVarInt(dst, 3, uint64(len(name)))
	dst[offset] |= 0x20 // 001Nxxxx, H=0
	if n {
		dst[offset] |= 0x10
	}
	dst = append(dst, name...)
	dst = appendVarInt(dst, 7, uint64(len(value))) // H=0
	dst = append(dst, value...)
	return dst
}

// appendRawLiteralWithNameReference builds a literal header field with a
// static-table name reference, using a non-Huffman value. n sets the N bit.
func appendRawLiteralWithNameReference(dst []byte, id uint64, value string, n bool) []byte {
	start := len(dst)
	dst = appendVarInt(dst, 4, id)
	b := byte(0x40 | 0x10) // 0101xxxx: T=1
	if n {
		b |= 0x20
	}
	dst[start] |= b
	valueLenBytes := appendVarInt(nil, 7, uint64(len(value))) // H=0
	dst = append(dst, valueLenBytes...)
	dst = append(dst, value...)
	return dst
}

// TestHandcraftedLiteralNeverIndexBit verifies the N bit of both literal
// representations using manually constructed (non-Huffman) bytes, instead of
// relying on the encoder to produce them.
func TestHandcraftedLiteralNeverIndexBit(t *testing.T) {
	hfWithNameRef := HeaderField{Name: "content-type", Value: "secret/value"}
	hfWithoutNameRef := HeaderField{Name: "x-secret", Value: "topsecret"}

	t.Run("literal with name reference", func(t *testing.T) {
		for _, n := range []bool{false, true} {
			data := insertPrefix(appendRawLiteralWithNameReference(nil, 44, hfWithNameRef.Value, n))
			hfs := decodeAll(t, NewDecoder().Decode(data))
			require.Equal(t, []HeaderField{{Name: hfWithNameRef.Name, Value: hfWithNameRef.Value, NeverIndex: n}}, hfs)
		}
	})

	t.Run("literal without name reference", func(t *testing.T) {
		for _, n := range []bool{false, true} {
			data := insertPrefix(appendRawLiteralWithoutNameReference(nil, hfWithoutNameRef.Name, hfWithoutNameRef.Value, n))
			hfs := decodeAll(t, NewDecoder().Decode(data))
			require.Equal(t, []HeaderField{{Name: hfWithoutNameRef.Name, Value: hfWithoutNameRef.Value, NeverIndex: n}}, hfs)
		}
	})
}

// TestSensitiveFieldFullStaticTableHit asserts the raw bytes of a field that
// fully matches a static table entry: the sensitive version must be encoded
// as a literal with N=1, not as an indexed field, and the name reference may
// still be used.
func TestSensitiveFieldFullStaticTableHit(t *testing.T) {
	hf := HeaderField{Name: ":method", Value: "GET"}

	t.Run("non-sensitive: indexed", func(t *testing.T) {
		buf := &bytes.Buffer{}
		enc := NewEncoder(buf)
		require.NoError(t, enc.WriteField(hf))
		data, ric, base := readPrefix(t, buf.Bytes())
		require.Zero(t, ric)
		require.Zero(t, base)
		require.Equal(t, uint8(1), data[0]>>7) // 1Txxxxxx indexed
		index, rest, err := readVarInt(6, data)
		require.NoError(t, err)
		require.Equal(t, uint64(17), index)
		require.Empty(t, rest)
	})

	t.Run("sensitive: literal with name reference and N bit", func(t *testing.T) {
		buf := &bytes.Buffer{}
		enc := NewEncoder(buf)
		require.NoError(t, enc.WriteField(HeaderField{Name: hf.Name, Value: hf.Value, NeverIndex: true}))
		data, _, _ := readPrefix(t, buf.Bytes())
		data = parseLiteralWithNameReference(t, data, hf, true)
		require.Empty(t, data)
	})
}

// TestSensitiveFieldWithoutNameReference covers the N bit for a sensitive
// field whose name is not in the static table.
func TestSensitiveFieldWithoutNameReference(t *testing.T) {
	hf := HeaderField{Name: "x-secret", Value: "topsecret", NeverIndex: true}
	buf := &bytes.Buffer{}
	enc := NewEncoder(buf)
	require.NoError(t, enc.WriteField(hf))

	data, _, _ := readPrefix(t, buf.Bytes())
	data = parseLiteralWithoutNameReference(t, data, hf, true)
	require.Empty(t, data)
}

// TestPolicyPromotionRoundTrip runs the full chain: decode handcrafted
// bytes (one of two N-bit literals), apply a local policy that promotes a
// normal field, re-encode (upstream mark and local policy take the stricter
// result), and decode again.
func TestPolicyPromotionRoundTrip(t *testing.T) {
	// cookie value "a": N=1 (upstream sensitive); authorization: N=0 literal.
	raw := appendRawLiteralWithNameReference(nil, 5, "a", true)
	raw = appendRawLiteralWithNameReference(raw, 84, "bearer token", false)
	incoming := insertPrefix(raw)

	decoded := decodeAll(t, NewDecoder().Decode(incoming))
	require.Equal(t, []HeaderField{
		{Name: "cookie", Value: "a", NeverIndex: true},
		{Name: "authorization", Value: "bearer token"},
	}, decoded)

	// Policy: promote authorization to sensitive; leave other fields alone
	// (the callback returns false, which must not downgrade the upstream N).
	policy := FieldPolicyFunc(func(hf HeaderField, index int) (bool, error) {
		return hf.Name == "authorization", nil
	})

	buf := &bytes.Buffer{}
	enc := NewEncoder(buf)
	enc.SetFieldPolicy(policy)
	require.NoError(t, enc.WriteFields(decoded))

	encoded, _, _ := readPrefix(t, buf.Bytes())
	// cookie stays a name-referenced literal carrying N=1 ...
	encoded = parseLiteralWithNameReference(t, encoded, HeaderField{Name: "cookie", Value: "a"}, true)
	// ... and the locally promoted authorization becomes N=1 too.
	encoded = parseLiteralWithNameReference(t, encoded, HeaderField{Name: "authorization", Value: "bearer token"}, true)
	require.Empty(t, encoded)

	redecoded := decodeAll(t, NewDecoder().Decode(buf.Bytes()))
	require.Equal(t, []HeaderField{
		{Name: "cookie", Value: "a", NeverIndex: true},
		{Name: "authorization", Value: "bearer token", NeverIndex: true},
	}, redecoded)
}

// TestPolicyReceivesOccurrenceIndexAndKeepsDuplicates verifies that repeated
// fields sharing a name get 1-based occurrence numbers and survive encoding
// without being merged.
func TestPolicyReceivesOccurrenceIndexAndKeepsDuplicates(t *testing.T) {
	type call struct {
		name  string
		index int
	}
	var calls []call
	policy := FieldPolicyFunc(func(hf HeaderField, index int) (bool, error) {
		calls = append(calls, call{hf.Name, index})
		return false, nil
	})

	fields := []HeaderField{
		{Name: "cookie", Value: "a=1"},
		{Name: "x-custom", Value: "one"},
		{Name: "cookie", Value: "b=2"},
		{Name: "x-custom", Value: "two"},
	}

	buf := &bytes.Buffer{}
	enc := NewEncoder(buf)
	enc.SetFieldPolicy(policy)
	require.NoError(t, enc.WriteFields(fields))

	require.Equal(t, []call{
		{"cookie", 1},
		{"x-custom", 1},
		{"cookie", 2},
		{"x-custom", 2},
	}, calls)

	// All four fields, including the duplicate names, survive the round trip.
	require.Equal(t, fields, decodeAll(t, NewDecoder().Decode(buf.Bytes())))

	// Occurrence counting starts over for a new header block.
	buf.Reset()
	require.NoError(t, enc.Close())
	calls = nil
	require.NoError(t, enc.WriteFields(fields[:1]))
	require.Equal(t, []call{{"cookie", 1}}, calls)
}

// TestPolicyRejectionDropsEntireBlock ensures that a rejected field prevents
// any byte of the precoded header block from reaching the downstream writer.
func TestPolicyRejectionDropsEntireBlock(t *testing.T) {
	policy := FieldPolicyFunc(func(hf HeaderField, index int) (bool, error) {
		if hf.Name == "forbidden" {
			return false, errReject
		}
		return false, nil
	})

	t.Run("rejected field at the end", func(t *testing.T) {
		buf := &bytes.Buffer{}
		enc := NewEncoder(buf)
		enc.SetFieldPolicy(policy)
		err := enc.WriteFields([]HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: "forbidden", Value: "nope"},
		})
		require.ErrorIs(t, err, errReject)
		require.Empty(t, buf.Bytes())

		// The encoder remains usable for the next header block.
		require.NoError(t, enc.Close())
		require.NoError(t, enc.WriteFields([]HeaderField{{Name: ":method", Value: "GET"}}))
		require.NotEmpty(t, buf.Bytes())
		require.Equal(t,
			[]HeaderField{staticTableEntries[17]},
			decodeAll(t, NewDecoder().Decode(buf.Bytes())),
		)
	})

	t.Run("rejected field in the middle", func(t *testing.T) {
		buf := &bytes.Buffer{}
		enc := NewEncoder(buf)
		enc.SetFieldPolicy(policy)
		err := enc.WriteFields([]HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: "forbidden", Value: "nope"},
			{Name: ":scheme", Value: "https"},
		})
		require.ErrorIs(t, err, errReject)
		require.Empty(t, buf.Bytes())
	})
}

// TestDefaultEncodingUnchanged verifies that without a policy and without
// NeverIndex set, output stays compatible: a full static-table hit remains an
// indexed field.
func TestDefaultEncodingUnchanged(t *testing.T) {
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: "x-secret", Value: "plain"},
	}
	buf := &bytes.Buffer{}
	enc := NewEncoder(buf)
	require.NoError(t, enc.WriteFields(fields))

	data, _, _ := readPrefix(t, buf.Bytes())
	require.Equal(t, uint8(1), data[0]>>7) // still indexed, no N bit
}
