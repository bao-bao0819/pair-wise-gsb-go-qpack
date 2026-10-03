package qpack

import (
	"errors"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/stretchr/testify/require"
)

// literalWithNameReference builds a Literal Field Line With Name Reference
// (01NTxxxx) referencing the static table, with a plain (non-Huffman) value.
func literalWithNameReference(index uint64, neverIndexed bool, value string) []byte {
	data := appendVarInt(nil, 4, index)
	data[0] |= 0x40 | 0x10 // T=1: static table reference
	if neverIndexed {
		data[0] |= 0x20 // N bit
	}
	data = appendVarInt(data, 7, uint64(len(value)))
	return append(data, value...)
}

// literalWithoutNameReference builds a Literal Field Line Without Name
// Reference (001NHxxx), with plain (non-Huffman) name and value.
func literalWithoutNameReference(name, value string, neverIndexed bool) []byte {
	data := appendVarInt(nil, 3, uint64(len(name)))
	data[0] |= 0x20
	if neverIndexed {
		data[0] |= 0x10 // N bit
	}
	data = append(data, name...)
	data = appendVarInt(data, 7, uint64(len(value)))
	return append(data, value...)
}

func TestDecoderNeverIndexedBit(t *testing.T) {
	t.Run("literal field with name reference", func(t *testing.T) {
		data := insertPrefix(literalWithNameReference(49, true, "text/html"))
		hfs := decodeAll(t, NewDecoder().Decode(data))
		require.Equal(t, []HeaderField{
			{Name: "content-type", Value: "text/html", Sensitive: true},
		}, hfs)
	})

	t.Run("literal field without name reference", func(t *testing.T) {
		data := insertPrefix(literalWithoutNameReference("x-custom", "value", true))
		hfs := decodeAll(t, NewDecoder().Decode(data))
		require.Equal(t, []HeaderField{
			{Name: "x-custom", Value: "value", Sensitive: true},
		}, hfs)
	})

	t.Run("N bit not set", func(t *testing.T) {
		data := insertPrefix(append(
			literalWithNameReference(49, false, "text/html"),
			literalWithoutNameReference("x-custom", "value", false)...,
		))
		hfs := decodeAll(t, NewDecoder().Decode(data))
		require.Equal(t, []HeaderField{
			{Name: "content-type", Value: "text/html"},
			{Name: "x-custom", Value: "value"},
		}, hfs)
	})
}

// A sensitive field that fully matches a static table entry (name and value)
// must not use the indexed representation, since it can't carry the N bit.
func TestEncoderSensitiveFieldMatchingStaticTableEntry(t *testing.T) {
	hf := HeaderField{Name: ":status", Value: "200", Sensitive: true}

	expected := insertPrefix(nil)
	lit := appendVarInt(nil, 4, 24) // name reference to :status
	lit[0] |= 0x40 | 0x10 | 0x20    // 01NTxxxx: T=1 (static), N=1 (never indexed)
	vlen := appendVarInt(nil, 7, hpack.HuffmanEncodeLength("200"))
	vlen[0] |= 0x80
	lit = append(lit, vlen...)
	lit = hpack.AppendHuffmanString(lit, "200")
	expected = append(expected, lit...)

	encoder, output := getEncoder()
	require.NoError(t, encoder.WriteField(hf))
	require.Equal(t, expected, output.Bytes())
	// the indexed representation (1Txxxxxx) would not be able to carry the N bit
	require.Zero(t, output.Bytes()[2]&0x80)

	// the same field without the sensitive flag uses the indexed representation
	encoder, output = getEncoder()
	require.NoError(t, encoder.WriteField(HeaderField{Name: ":status", Value: "200"}))
	indexed := appendVarInt(nil, 6, 25) // :status: 200
	indexed[0] |= 0x80 | 0x40
	require.Equal(t, insertPrefix(indexed), output.Bytes())
}

func TestEncoderSensitiveFieldWithoutNameReference(t *testing.T) {
	hf := HeaderField{Name: "x-secret", Value: "value", Sensitive: true}

	expected := insertPrefix(nil)
	lit := appendVarInt(nil, 3, hpack.HuffmanEncodeLength("x-secret"))
	lit[0] |= 0x20 | 0x10 | 0x8 // 001NHxxx: N=1 (never indexed), H=1 (Huffman)
	lit = hpack.AppendHuffmanString(lit, "x-secret")
	vlen := appendVarInt(nil, 7, hpack.HuffmanEncodeLength("value"))
	vlen[0] |= 0x80
	lit = append(lit, vlen...)
	lit = hpack.AppendHuffmanString(lit, "value")
	expected = append(expected, lit...)

	encoder, output := getEncoder()
	require.NoError(t, encoder.WriteField(hf))
	require.Equal(t, expected, output.Bytes())
}

// The full gateway chain: decode a header block, re-encode it while a local
// policy promotes a field to sensitive, then decode the result again.
func TestDecodeEncodeWithPolicyDecode(t *testing.T) {
	// hand-crafted header block coming from the upstream peer:
	// content-type is already marked never-indexed, x-custom is not
	upstream := insertPrefix(append(
		literalWithNameReference(49, true, "text/html"),
		literalWithoutNameReference("x-custom", "value", false)...,
	))
	hfs := decodeAll(t, NewDecoder().Decode(upstream))
	require.Equal(t, []HeaderField{
		{Name: "content-type", Value: "text/html", Sensitive: true},
		{Name: "x-custom", Value: "value"},
	}, hfs)

	// the local policy promotes x-custom to sensitive;
	// it must not be able to downgrade the upstream N bit on content-type
	policy := func(f HeaderField, occurrence int) (bool, error) {
		require.Zero(t, occurrence)
		return f.Name == "x-custom", nil
	}
	encoder, output := getEncoder()
	require.NoError(t, encoder.WriteFieldSection(hfs, policy))

	// byte-level assertion of the re-encoded field section
	expected := insertPrefix(nil)
	lit1 := appendVarInt(nil, 4, 44) // name reference to content-type
	lit1[0] |= 0x40 | 0x10 | 0x20    // 01NTxxxx: T=1 (static), N=1 (upstream N bit preserved)
	vlen := appendVarInt(nil, 7, hpack.HuffmanEncodeLength("text/html"))
	vlen[0] |= 0x80
	lit1 = append(lit1, vlen...)
	lit1 = hpack.AppendHuffmanString(lit1, "text/html")
	lit2 := appendVarInt(nil, 3, hpack.HuffmanEncodeLength("x-custom"))
	lit2[0] |= 0x20 | 0x10 | 0x8 // 001NHxxx: N=1 (promoted by the policy), H=1
	lit2 = hpack.AppendHuffmanString(lit2, "x-custom")
	vlen = appendVarInt(nil, 7, hpack.HuffmanEncodeLength("value"))
	vlen[0] |= 0x80
	lit2 = append(lit2, vlen...)
	lit2 = hpack.AppendHuffmanString(lit2, "value")
	expected = append(append(expected, lit1...), lit2...)
	require.Equal(t, expected, output.Bytes())

	// decoding the re-encoded block recovers both N bits
	require.Equal(t, []HeaderField{
		{Name: "content-type", Value: "text/html", Sensitive: true},
		{Name: "x-custom", Value: "value", Sensitive: true},
	}, decodeAll(t, NewDecoder().Decode(output.Bytes())))
}

// The policy is told the occurrence index of every field among the fields
// with the same name, so repeated fields are not merged into a map entry.
func TestWriteFieldSectionPolicyOccurrences(t *testing.T) {
	hfs := []HeaderField{
		{Name: "cookie", Value: "a=1"},
		{Name: "cookie", Value: "b=2"},
		{Name: "x-dup", Value: "p"},
		{Name: "cookie", Value: "c=3"},
		{Name: "x-dup", Value: "q"},
	}

	type seenOccurrence struct {
		name       string
		occurrence int
	}
	var seen []seenOccurrence
	policy := func(f HeaderField, occurrence int) (bool, error) {
		seen = append(seen, seenOccurrence{f.Name, occurrence})
		// promote only the second cookie
		return f.Name == "cookie" && occurrence == 1, nil
	}
	encoder, output := getEncoder()
	require.NoError(t, encoder.WriteFieldSection(hfs, policy))

	require.Equal(t, []seenOccurrence{
		{"cookie", 0},
		{"cookie", 1},
		{"x-dup", 0},
		{"cookie", 2},
		{"x-dup", 1},
	}, seen)

	require.Equal(t, []HeaderField{
		{Name: "cookie", Value: "a=1"},
		{Name: "cookie", Value: "b=2", Sensitive: true},
		{Name: "x-dup", Value: "p"},
		{Name: "cookie", Value: "c=3"},
		{Name: "x-dup", Value: "q"},
	}, decodeAll(t, NewDecoder().Decode(output.Bytes())))
}

// When the policy rejects a field, the entire pre-encoded field section
// must be discarded: nothing may be written to the underlying writer.
func TestWriteFieldSectionPolicyRejectsField(t *testing.T) {
	errPolicy := errors.New("field rejected by policy")
	hfs := []HeaderField{
		{Name: "foo", Value: "bar"},
		{Name: "x-evil", Value: "lorem ipsum"},
		{Name: "raboof", Value: "dolor sit amet"},
	}
	policy := func(f HeaderField, _ int) (bool, error) {
		if f.Name == "x-evil" {
			return false, errPolicy
		}
		return false, nil
	}

	output := &errWriter{}
	encoder := NewEncoder(output)
	err := encoder.WriteFieldSection(hfs, policy)
	require.ErrorIs(t, err, errPolicy)
	require.Empty(t, output.Bytes())

	// the encoder is still usable, and the next section starts with the prefix
	require.NoError(t, encoder.WriteField(HeaderField{Name: "foo", Value: "bar"}))
	data, requiredInsertCount, deltaBase := readPrefix(t, output.Bytes())
	require.Zero(t, requiredInsertCount)
	require.Zero(t, deltaBase)
	require.Empty(t, checkHeaderField(t, data, HeaderField{Name: "foo", Value: "bar"}))
}

// A field section encoded without a policy (or with a policy that doesn't
// promote anything) produces the same bytes as the old WriteField API.
func TestWriteFieldSectionDefaultOutputCompatibility(t *testing.T) {
	hfs := []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/html"},
		{Name: "x-custom", Value: "value"},
	}

	expected := &errWriter{}
	encoder := NewEncoder(expected)
	for _, hf := range hfs {
		require.NoError(t, encoder.WriteField(hf))
	}

	output := &errWriter{}
	encoder = NewEncoder(output)
	require.NoError(t, encoder.WriteFieldSection(hfs, nil))
	require.Equal(t, expected.Bytes(), output.Bytes())

	output.Reset()
	encoder = NewEncoder(output)
	require.NoError(t, encoder.WriteFieldSection(hfs, func(HeaderField, int) (bool, error) {
		return false, nil
	}))
	require.Equal(t, expected.Bytes(), output.Bytes())
}

// The N bit survives a decode / re-encode round trip through the old
// WriteField API, without any policy involved.
func TestWriteFieldPreservesNeverIndexedBit(t *testing.T) {
	upstream := insertPrefix(literalWithoutNameReference("x-secret", "value", true))
	hfs := decodeAll(t, NewDecoder().Decode(upstream))
	require.Len(t, hfs, 1)
	require.True(t, hfs[0].Sensitive)

	encoder, output := getEncoder()
	for _, hf := range hfs {
		require.NoError(t, encoder.WriteField(hf))
	}
	require.Equal(t, []HeaderField{
		{Name: "x-secret", Value: "value", Sensitive: true},
	}, decodeAll(t, NewDecoder().Decode(output.Bytes())))
}
