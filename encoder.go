package qpack

import (
	"io"

	"golang.org/x/net/http2/hpack"
)

// An Encoder performs QPACK encoding.
type Encoder struct {
	wrotePrefix bool

	policy FieldPolicy
	// counts tracks the 1-based occurrence number of every field name,
	// so the policy can distinguish repeated fields sharing a name
	// (e.g. multiple cookie or set-cookie fields).
	counts map[string]int

	w   io.Writer
	buf []byte
}

// NewEncoder returns a new Encoder which performs QPACK encoding. Encoded
// data is written to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// FieldPolicy allows the caller to influence encoding of header fields.
// Field is called for every header field, in encoding order.
// index is the 1-based occurrence number of this field among fields sharing
// the same name within the current header block (the first cookie gets 1,
// the second cookie gets 2, etc.).
// Returning neverIndex true promotes the field to a sensitive field: it is
// encoded using a literal representation with the Never-Index (N) bit set,
// even if name and value fully match a static table entry; the name may
// still be encoded using a static table reference.
// Returning an error rejects the field. WriteFields then drops the entire
// header block without writing anything to the underlying writer.
type FieldPolicy interface {
	Field(hf HeaderField, index int) (neverIndex bool, err error)
}

// FieldPolicyFunc is an adapter to allow the use of ordinary functions as
// FieldPolicies.
type FieldPolicyFunc func(hf HeaderField, index int) (neverIndex bool, err error)

// Field calls p(hf, index).
func (p FieldPolicyFunc) Field(hf HeaderField, index int) (bool, error) {
	return p(hf, index)
}

// SetFieldPolicy installs the policy consulted while encoding fields.
// Passing nil removes the policy.
func (e *Encoder) SetFieldPolicy(p FieldPolicy) {
	e.policy = p
}

// WriteField encodes f into a single Write to e's underlying Writer.
// This function may also produce bytes for the Header Block Prefix
// if necessary. If produced, it is done before encoding f.
// If f.NeverIndex is set, or the installed field policy marks the field
// sensitive, f is encoded using a literal representation with the N bit set.
func (e *Encoder) WriteField(f HeaderField) error {
	policyNeverIndex, err := e.policyNeverIndex(f)
	if err != nil {
		return err
	}

	e.ensurePrefix()

	e.buf = e.appendField(e.buf, f, policyNeverIndex)

	_, err = e.w.Write(e.buf)
	e.buf = e.buf[:0]
	return err
}

// WriteFields encodes all fields as a single header block.
// The Header Block Prefix and every field are assembled in an internal
// buffer first. If the installed field policy rejects any field, nothing is
// written to the underlying writer and the policy's error is returned.
// Duplicate field names are preserved; they are never merged.
func (e *Encoder) WriteFields(fields []HeaderField) error {
	decisions := make([]bool, len(fields))
	for i, f := range fields {
		neverIndex, err := e.policyNeverIndex(f)
		if err != nil {
			// Rejecting a single field drops the entire header block.
			e.counts = nil
			return err
		}
		decisions[i] = neverIndex
	}

	e.ensurePrefix()

	buf := e.buf
	for i, f := range fields {
		buf = e.appendField(buf, f, decisions[i])
	}
	e.buf = buf

	_, err := e.w.Write(e.buf)
	e.buf = e.buf[:0]
	return err
}

// Close declares that the encoding is complete and resets the Encoder
// to be reused again for a new header block.
func (e *Encoder) Close() error {
	e.wrotePrefix = false
	e.counts = nil
	return nil
}

func (e *Encoder) ensurePrefix() {
	if e.wrotePrefix {
		return
	}
	// write the Header Block Prefix
	e.buf = appendVarInt(e.buf, 8, 0)
	e.buf = appendVarInt(e.buf, 7, 0)
	e.wrotePrefix = true
}

// policyNeverIndex consults the field policy (if installed), passing it the
// occurrence number of the field. Occurrence counting starts over after
// Close.
func (e *Encoder) policyNeverIndex(f HeaderField) (bool, error) {
	if e.policy == nil {
		return false, nil
	}
	if e.counts == nil {
		e.counts = make(map[string]int)
	}
	e.counts[f.Name]++
	return e.policy.Field(f, e.counts[f.Name])
}

// appendField appends the encoding of f to dst. The field is encoded as a
// literal with the Never-Index (N) bit set if f.NeverIndex is set or the
// local policy marked it sensitive; the stricter value wins, so the local
// policy can never downgrade an upstream N bit. Sensitive fields never use
// the indexed representation, even on a full static table hit; the name may
// still be encoded using a static table reference.
func (e *Encoder) appendField(dst []byte, f HeaderField, policyNeverIndex bool) []byte {
	f.NeverIndex = f.NeverIndex || policyNeverIndex

	idxAndVals, nameFound := encoderMap[f.Name]
	if f.NeverIndex {
		if nameFound {
			return e.appendLiteralFieldWithNameReference(dst, &f, idxAndVals.idx)
		}
		return e.appendLiteralFieldWithoutNameReference(dst, f)
	}

	if nameFound {
		if idxAndVals.values == nil {
			if len(f.Value) == 0 {
				return e.appendIndexedField(dst, idxAndVals.idx)
			}
			return e.appendLiteralFieldWithNameReference(dst, &f, idxAndVals.idx)
		}
		valIdx, valueFound := idxAndVals.values[f.Value]
		if valueFound {
			return e.appendIndexedField(dst, valIdx)
		}
		return e.appendLiteralFieldWithNameReference(dst, &f, idxAndVals.idx)
	}
	return e.appendLiteralFieldWithoutNameReference(dst, f)
}

func (e *Encoder) appendLiteralFieldWithoutNameReference(dst []byte, f HeaderField) []byte {
	offset := len(dst)
	dst = appendVarInt(dst, 3, hpack.HuffmanEncodeLength(f.Name))
	// Set the 001Hxxxx pattern (Huffman), and the N bit (00010000) if
	// the field is sensitive.
	dst[offset] ^= 0x20 | 0x8
	if f.NeverIndex {
		dst[offset] |= 0x10
	}
	dst = hpack.AppendHuffmanString(dst, f.Name)
	offset = len(dst)
	dst = appendVarInt(dst, 7, hpack.HuffmanEncodeLength(f.Value))
	dst[offset] ^= 0x80
	dst = hpack.AppendHuffmanString(dst, f.Value)
	return dst
}

// appendLiteralFieldWithNameReference encodes a header field whose name is
// present in one of the tables.
func (e *Encoder) appendLiteralFieldWithNameReference(dst []byte, f *HeaderField, id uint8) []byte {
	offset := len(dst)
	dst = appendVarInt(dst, 4, uint64(id))
	// Set the 01NTxxxx pattern, forcing T to 1. N is set for sensitive fields.
	dst[offset] ^= 0x50
	if f.NeverIndex {
		dst[offset] |= 0x20
	}
	offset = len(dst)
	dst = appendVarInt(dst, 7, hpack.HuffmanEncodeLength(f.Value))
	dst[offset] ^= 0x80
	dst = hpack.AppendHuffmanString(dst, f.Value)
	return dst
}

// appendIndexedField encodes an indexed field, entirely defined in one of
// the tables.
func (e *Encoder) appendIndexedField(dst []byte, id uint8) []byte {
	offset := len(dst)
	dst = appendVarInt(dst, 6, uint64(id))
	// Set the 1Txxxxxx pattern, forcing T to 1
	dst[offset] ^= 0xc0
	return dst
}
