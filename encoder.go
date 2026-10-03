package qpack

import (
	"io"

	"golang.org/x/net/http2/hpack"
)

// An Encoder performs QPACK encoding.
type Encoder struct {
	wrotePrefix bool

	w   io.Writer
	buf []byte
}

// A FieldPolicy decides how a single header field of a field section is
// encoded. The occurrence argument is the 0-based index of the field among
// all fields with the same name in the section, allowing the policy to
// distinguish repeated fields (e.g. multiple cookie fields).
// Returning sensitive = true promotes the field to a sensitive field,
// causing it to be encoded with the Never Indexed (N) bit set.
// It can only make a field more sensitive: a field that already carries
// the N bit (e.g. one that was decoded from an upstream header block)
// is never downgraded.
// Returning a non-nil error rejects the field. In that case, the entire
// field section is discarded and nothing is written to the connection.
type FieldPolicy func(f HeaderField, occurrence int) (sensitive bool, err error)

// NewEncoder returns a new Encoder which performs QPACK encoding. An
// encoded data is written to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// WriteField encodes f into a single Write to e's underlying Writer.
// This function may also produce bytes for the Header Block Prefix
// if necessary. If produced, it is done before encoding f.
func (e *Encoder) WriteField(f HeaderField) error {
	// write the Header Block Prefix
	if !e.wrotePrefix {
		e.buf = appendVarInt(e.buf, 8, 0)
		e.buf = appendVarInt(e.buf, 7, 0)
		e.wrotePrefix = true
	}

	e.buf = appendField(e.buf, f, f.Sensitive)

	_, err := e.w.Write(e.buf)
	e.buf = e.buf[:0]
	return err
}

// WriteFieldSection encodes an entire field section into a single Write to
// e's underlying Writer, consulting policy for every field.
// A field is encoded with the Never Indexed (N) bit set if it is already
// marked sensitive or if the policy promotes it; the stricter of the two
// wins, so the policy can never downgrade an upstream N bit.
// If the policy rejects any field, the entire section is discarded and
// nothing is written to the underlying Writer.
// A nil policy encodes every field with its default sensitivity.
func (e *Encoder) WriteFieldSection(fields []HeaderField, policy FieldPolicy) error {
	buf := e.buf[:0]
	wrotePrefix := e.wrotePrefix
	if !wrotePrefix {
		buf = appendVarInt(buf, 8, 0)
		buf = appendVarInt(buf, 7, 0)
		wrotePrefix = true
	}

	occurrences := make(map[string]int)
	for _, f := range fields {
		sensitive := f.Sensitive
		if policy != nil {
			occurrence := occurrences[f.Name]
			occurrences[f.Name]++
			s, err := policy(f, occurrence)
			if err != nil {
				e.buf = e.buf[:0]
				return err
			}
			sensitive = sensitive || s
		}
		buf = appendField(buf, f, sensitive)
	}

	if _, err := e.w.Write(buf); err != nil {
		e.buf = e.buf[:0]
		return err
	}
	e.buf = buf[:0]
	e.wrotePrefix = wrotePrefix
	return nil
}

// Close declares that the encoding is complete and resets the Encoder
// to be reused again for a new header block.
func (e *Encoder) Close() error {
	e.wrotePrefix = false
	return nil
}

func appendField(buf []byte, f HeaderField, sensitive bool) []byte {
	idxAndVals, nameFound := encoderMap[f.Name]
	if sensitive {
		// Sensitive fields must carry the N bit, which neither of the two
		// indexed representations can do. Use a literal representation,
		// referencing the name from the static table if possible.
		if nameFound {
			return appendLiteralFieldWithNameReference(buf, &f, idxAndVals.idx, true)
		}
		return appendLiteralFieldWithoutNameReference(buf, f, true)
	}
	if nameFound {
		if idxAndVals.values == nil {
			if len(f.Value) == 0 {
				return appendIndexedField(buf, idxAndVals.idx)
			}
			return appendLiteralFieldWithNameReference(buf, &f, idxAndVals.idx, false)
		}
		if valIdx, valueFound := idxAndVals.values[f.Value]; valueFound {
			return appendIndexedField(buf, valIdx)
		}
		return appendLiteralFieldWithNameReference(buf, &f, idxAndVals.idx, false)
	}
	return appendLiteralFieldWithoutNameReference(buf, f, false)
}

func appendLiteralFieldWithoutNameReference(buf []byte, f HeaderField, sensitive bool) []byte {
	offset := len(buf)
	buf = appendVarInt(buf, 3, hpack.HuffmanEncodeLength(f.Name))
	// Set the 001NHxxx pattern, forcing the H bit (Huffman encoding) to 1.
	buf[offset] ^= 0x20 ^ 0x8
	if sensitive {
		buf[offset] |= 0x10
	}
	buf = hpack.AppendHuffmanString(buf, f.Name)
	offset = len(buf)
	buf = appendVarInt(buf, 7, hpack.HuffmanEncodeLength(f.Value))
	buf[offset] ^= 0x80
	return hpack.AppendHuffmanString(buf, f.Value)
}

// Encodes a header field whose name is present in one of the tables.
func appendLiteralFieldWithNameReference(buf []byte, f *HeaderField, id uint8, sensitive bool) []byte {
	offset := len(buf)
	buf = appendVarInt(buf, 4, uint64(id))
	// Set the 01NTxxxx pattern, forcing T to 1.
	buf[offset] ^= 0x50
	if sensitive {
		buf[offset] |= 0x20
	}
	offset = len(buf)
	buf = appendVarInt(buf, 7, hpack.HuffmanEncodeLength(f.Value))
	buf[offset] ^= 0x80
	return hpack.AppendHuffmanString(buf, f.Value)
}

// Encodes an indexed field, meaning it's entirely defined in one of the tables.
func appendIndexedField(buf []byte, id uint8) []byte {
	offset := len(buf)
	buf = appendVarInt(buf, 6, uint64(id))
	// Set the 1Txxxxxx pattern, forcing T to 1
	buf[offset] ^= 0xc0
	return buf
}
