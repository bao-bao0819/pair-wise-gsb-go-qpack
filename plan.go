package qpack

import (
	"io"
	"strconv"

	"golang.org/x/net/http2/hpack"
)

// representation identifies the QPACK field line representation selected by
// the byte-cost planner.
type representation uint8

const (
	// repIndexed is an Indexed Field Line (4.3.2 in RFC 9204): the complete
	// field is an entry in the static table.
	repIndexed representation = iota
	// repNameReference is a Literal Field Line With Name Reference (4.3.3):
	// the name is taken from a static table entry, the value is literal.
	repNameReference
	// repLiteral is a Literal Field Line Without Name Reference: both the
	// name and the value are literal.
	repLiteral
)

// stringPlan describes how a single string (a name or a value) is emitted.
type stringPlan struct {
	huffman bool
	rawLen  int // number of payload bytes (len(s) raw, or the Huffman length)
}

// fieldPlan is the cheapest representation found for a single header field.
type fieldPlan struct {
	hf   HeaderField
	rep  representation
	idx  uint64 // static table index (repIndexed and repNameReference only)
	name stringPlan
	val  stringPlan
}

// FieldSectionPlan is the byte-optimal encoding plan for a complete header
// block (a QPACK field section). It is computed once and can be used for both
// length estimation and the actual encoding, guaranteeing that the estimate
// matches the bytes that Encode produces.
type FieldSectionPlan struct {
	fields []fieldPlan
	length int
}

// PlanFieldSection computes the cheapest encoding for fields and returns a
// FieldSectionPlan. Field order and duplicates are preserved.
//
// For every field the planner compares all legal candidates:
//   - an Indexed Field Line for every static table entry equal to the field,
//   - a Literal Field Line With Name Reference for every static table entry
//     whose name matches the field name,
//   - a Literal Field Line Without Name Reference.
//
// For the literal name and the literal value it compares the raw bytes with
// the Huffman encoding independently. Costs include the variable-length
// integer prefix expansion (e.g. a static index of 63 no longer fits the
// 6-bit prefix and costs an extra byte), not just the string payload length.
//
// Planning is deterministic: identical input always yields the same plan.
// When two representations have exactly the same total byte cost, the
// following rule decides, in order:
//  1. prefer the Indexed Field Line, then Name Reference, then Literal,
//  2. for table references, prefer the smaller static table index,
//  3. for the raw/Huffman choice of a string, prefer raw bytes.
func PlanFieldSection(fields []HeaderField) *FieldSectionPlan {
	p := &FieldSectionPlan{
		fields: make([]fieldPlan, 0, len(fields)),
		length: 2, // Header Block Prefix: Required Insert Count and Delta Base
	}
	for i := range fields {
		fp := planField(fields[i])
		p.fields = append(p.fields, fp)
		p.length += fieldPlanLen(fp)
	}
	return p
}

// Len returns the total number of bytes the field section occupies, including
// the Header Block Prefix. It does not allocate the encoded bytes.
func (p *FieldSectionPlan) Len() int {
	return p.length
}

// Encode writes the complete field section (Header Block Prefix followed by
// the encoded field lines) to w in a single Write, according to the plan.
// The plan is not modified and may be Encodeed repeatedly.
func (p *FieldSectionPlan) Encode(w io.Writer) (int, error) {
	buf := make([]byte, 0, p.length)
	buf = appendVarInt(buf, 8, 0)
	buf = appendVarInt(buf, 7, 0)
	for _, fp := range p.fields {
		buf = appendPlannedField(buf, fp)
	}
	n, err := w.Write(buf)
	return n, err
}

// EncodeFieldSection is a convenience wrapper that plans fields and encodes
// them only when they fit within budget bytes (the budget covers the whole
// field section, including the Header Block Prefix).
//
// When the section exceeds the budget nothing is written to w and the
// returned error is *FieldSectionTooLongError; callers can use errors.As to
// recover the required length.
func EncodeFieldSection(w io.Writer, fields []HeaderField, budget int) (int, error) {
	plan := PlanFieldSection(fields)
	if plan.Len() > budget {
		return 0, &FieldSectionTooLongError{Required: plan.Len(), Budget: budget}
	}
	return plan.Encode(w)
}

// FieldSectionTooLongError reports that a planned field section exceeds the
// budget passed to EncodeFieldSection. No bytes were written.
type FieldSectionTooLongError struct {
	// Required is the total number of bytes needed to encode the field
	// section, including the Header Block Prefix.
	Required int
	// Budget is the maximum number of bytes the caller allowed.
	Budget int
}

func (e *FieldSectionTooLongError) Error() string {
	return "qpack: field section requires " + strconv.Itoa(e.Required) +
		" bytes, exceeding the field section budget of " + strconv.Itoa(e.Budget) + " bytes"
}

// planString compares the raw and Huffman encodings of s, including the
// length-prefix expansion, and returns the cheaper stringPlan. On a tie the
// raw encoding is preferred.
func planString(s string) stringPlan {
	raw := stringPlan{huffman: false, rawLen: len(s)}
	hufLen := int(hpack.HuffmanEncodeLength(s))
	huf := stringPlan{huffman: true, rawLen: hufLen}
	if huf.rawLen < raw.rawLen {
		return huf
	}
	return raw
}

// planField selects the cheapest legal representation for hf.
func planField(hf HeaderField) fieldPlan {
	val := planString(hf.Value)
	lit := fieldPlan{
		hf:   hf,
		rep:  repLiteral,
		name: planString(hf.Name),
		val:  val,
	}
	best := lit

	for idx := 0; idx < len(staticTableEntries); idx++ {
		e := staticTableEntries[idx]
		if e.Name != hf.Name {
			continue
		}
		// Every name match yields a Literal Field Line With Name Reference.
		cand := fieldPlan{
			hf:  hf,
			rep: repNameReference,
			idx: uint64(idx),
			val: val,
		}
		if cheaperField(cand, best) {
			best = cand
		}
		// An entry also equal in value yields an Indexed Field Line.
		if e.Value == hf.Value {
			idxCand := fieldPlan{
				hf:  hf,
				rep: repIndexed,
				idx: uint64(idx),
			}
			if cheaperField(idxCand, best) {
				best = idxCand
			}
		}
	}
	return best
}

// cheaperField reports whether a is preferred over b. The static table is
// iterated in increasing index order, so equal-cost candidates are rejected.
func cheaperField(a, b fieldPlan) bool {
	ca, cb := fieldPlanLen(a), fieldPlanLen(b)
	if ca != cb {
		return ca < cb
	}
	if a.rep != b.rep {
		return a.rep < b.rep // indexed < name reference < literal
	}
	if a.rep != repLiteral {
		return a.idx < b.idx
	}
	return false // the literal candidate is the first one seen for this field
}

// fieldPlanLen computes the number of bytes a planned field line occupies.
func fieldPlanLen(fp fieldPlan) int {
	switch fp.rep {
	case repIndexed:
		// 1Txxxxxx, 6-bit prefix, T=1 (static table).
		return varIntLen(6, fp.idx)
	case repNameReference:
		// 01NTxxxx with N=0, T=1 (4-bit prefix), followed by the value.
		return varIntLen(4, fp.idx) + stringLen(7, fp.val.rawLen)
	default:
		// 001Hxxxx with a 3-bit name length prefix, then the 7-bit value.
		return stringLen(3, fp.name.rawLen) + stringLen(7, fp.val.rawLen)
	}
}

// stringLen is the size of a length-prefixed string with payload length l:
// the length integer (n-bit prefix) plus the payload.
func stringLen(n byte, l int) int {
	return varIntLen(n, uint64(l)) + l
}

// varIntLen returns the number of bytes used by an integer with an n-bit
// prefix (RFC 7541 section 5.1).
func varIntLen(n byte, i uint64) int {
	k := uint64(1)<<n - 1
	if i < k {
		return 1
	}
	l := 2 // one byte for the all-ones prefix, at least one continuation byte
	for i -= k; i >= 128; i >>= 7 {
		l++
	}
	return l
}

// appendPlannedField appends the bytes of one planned field line.
func appendPlannedField(dst []byte, fp fieldPlan) []byte {
	switch fp.rep {
	case repIndexed:
		offset := len(dst)
		dst = appendVarInt(dst, 6, fp.idx)
		// Force the 1Txxxxxx pattern with T=1.
		dst[offset] |= 0xc0
	case repNameReference:
		offset := len(dst)
		dst = appendVarInt(dst, 4, fp.idx)
		// Force the 01NTxxxx pattern with N=0 and T=1.
		dst[offset] |= 0x50
		dst = appendPlannedString(dst, 7, 0x00, 0x80, fp.hf.Value, fp.val)
	default:
		dst = appendPlannedString(dst, 3, 0x20, 0x8, fp.hf.Name, fp.name)
		dst = appendPlannedString(dst, 7, 0x00, 0x80, fp.hf.Value, fp.val)
	}
	return dst
}

// appendPlannedString appends a length-prefixed literal string. typeBits are
// ORed into the first prefix byte and carry the representation type; hFlag is
// the H bit position (0x80 for a 7-bit prefix, 0x8 for a 3-bit prefix) and is
// set when the string uses Huffman encoding.
func appendPlannedString(dst []byte, n byte, typeBits byte, hFlag byte, s string, sp stringPlan) []byte {
	offset := len(dst)
	dst = appendVarInt(dst, n, uint64(sp.rawLen))
	dst[offset] |= typeBits
	if sp.huffman {
		dst[offset] |= hFlag
		dst = hpack.AppendHuffmanString(dst, s)
	} else {
		dst = append(dst, s...)
	}
	return dst
}
