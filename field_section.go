package qpack

import (
	"errors"

	"golang.org/x/net/http2/hpack"
)

const headerBlockPrefixSize = 2

// ErrFieldSectionTooLarge is returned when an EncodingPlan does not fit in
// the field section budget. The returned length is the required total size.
var ErrFieldSectionTooLarge = errors.New("qpack: field section exceeds budget")

type fieldRepresentation uint8

const (
	indexedRepresentation fieldRepresentation = iota
	literalNameReferenceRepresentation
	literalNameRepresentation
)

type plannedString struct {
	huffman bool
	length  int
}

type plannedField struct {
	field          HeaderField
	representation fieldRepresentation
	staticIndex    uint8
	name           plannedString
	value          plannedString
	length         int
}

// EncodingPlan is the deterministic representation selected for a complete
// field section. It includes the two-byte header block prefix.
type EncodingPlan struct {
	fields []plannedField
	length int
}

// PlanFields selects the smallest representation for every field without
// writing anything.
//
// For every field, indexed static-table entries, literal fields with every
// matching static-table name reference, and literal fields without a name
// reference are compared. Name and value strings independently use raw or
// Huffman encoding based on the complete encoded size, including integer
// prefix expansion.
//
// If two representations have the same size, PlanFields uses an indexed field,
// then a name reference with the lowest static-table index, then a literal name.
// If raw and Huffman strings have the same size, the raw string is selected.
func PlanFields(fields []HeaderField) EncodingPlan {
	plan := EncodingPlan{
		fields: make([]plannedField, len(fields)),
		length: headerBlockPrefixSize,
	}
	for i, field := range fields {
		planned := planField(field)
		plan.fields[i] = planned
		plan.length += planned.length
	}
	return plan
}

// Len returns the complete field section size, including the header block
// prefix.
func (p EncodingPlan) Len() int {
	return p.length
}

// WriteFields plans and writes a complete field section if it fits budget.
// On success it returns the number of bytes written. If the section does not
// fit, it returns the required size and ErrFieldSectionTooLarge without
// writing to the underlying Writer.
func (e *Encoder) WriteFields(fields []HeaderField, budget int) (int, error) {
	return e.WritePlan(PlanFields(fields), budget)
}

// WritePlan writes a previously planned complete field section if it fits
// budget. See WriteFields for the return values and budget behavior.
func (e *Encoder) WritePlan(plan EncodingPlan, budget int) (int, error) {
	if plan.length > budget {
		return plan.length, ErrFieldSectionTooLarge
	}

	e.wrotePrefix = false
	e.buf = e.buf[:0]
	e.buf = appendVarInt(e.buf, 8, 0)
	e.buf = appendVarInt(e.buf, 7, 0)
	e.buf = appendPlannedFields(e.buf, plan)

	n, err := e.w.Write(e.buf)
	e.buf = e.buf[:0]
	e.wrotePrefix = true
	return n, err
}

func planField(field HeaderField) plannedField {
	name := planString(field.Name, 3)
	value := planString(field.Value, 7)
	best := plannedField{
		field:          field,
		representation: literalNameRepresentation,
		name:           name,
		value:          value,
		length:         name.length + value.length,
	}

	for _, index := range staticTableNameIndices[field.Name] {
		if staticTableEntries[index].Value == field.Value {
			candidate := plannedField{
				field:          field,
				representation: indexedRepresentation,
				staticIndex:    index,
				length:         varIntLength(6, uint64(index)),
			}
			best = betterPlannedField(candidate, best)
		}

		candidate := plannedField{
			field:          field,
			representation: literalNameReferenceRepresentation,
			staticIndex:    index,
			value:          value,
			length:         varIntLength(4, uint64(index)) + value.length,
		}
		best = betterPlannedField(candidate, best)
	}

	return best
}

func betterPlannedField(candidate, best plannedField) plannedField {
	if candidate.length < best.length {
		return candidate
	}
	if candidate.length > best.length {
		return best
	}
	if candidate.representation != best.representation {
		if representationRank(candidate.representation) < representationRank(best.representation) {
			return candidate
		}
		return best
	}
	if candidate.staticIndex != best.staticIndex {
		if candidate.staticIndex < best.staticIndex {
			return candidate
		}
		return best
	}
	if candidate.name.huffman != best.name.huffman {
		if !candidate.name.huffman {
			return candidate
		}
		return best
	}
	if candidate.value.huffman != best.value.huffman && !candidate.value.huffman {
		return candidate
	}
	return best
}

func representationRank(representation fieldRepresentation) int {
	switch representation {
	case indexedRepresentation:
		return 0
	case literalNameReferenceRepresentation:
		return 1
	default:
		return 2
	}
}

func planString(value string, prefixBits uint8) plannedString {
	rawLength := len(value) + varIntLength(prefixBits, uint64(len(value)))
	huffmanLength := hpack.HuffmanEncodeLength(value)
	huffmanTotal := int(huffmanLength) + varIntLength(prefixBits, huffmanLength)
	if huffmanTotal < rawLength {
		return plannedString{huffman: true, length: huffmanTotal}
	}
	return plannedString{length: rawLength}
}

func appendPlannedFields(dst []byte, plan EncodingPlan) []byte {
	for _, field := range plan.fields {
		switch field.representation {
		case indexedRepresentation:
			offset := len(dst)
			dst = appendVarInt(dst, 6, uint64(field.staticIndex))
			dst[offset] |= 0xc0
		case literalNameReferenceRepresentation:
			offset := len(dst)
			dst = appendVarInt(dst, 4, uint64(field.staticIndex))
			dst[offset] |= 0x50
			dst = appendPlannedString(dst, 7, field.field.Value, field.value, 0x80)
		default:
			offset := len(dst)
			dst = appendPlannedString(dst, 3, field.field.Name, field.name, 0x08)
			dst[offset] |= 0x20
			dst = appendPlannedString(dst, 7, field.field.Value, field.value, 0x80)
		}
	}
	return dst
}

func appendPlannedString(dst []byte, prefixBits uint8, value string, planned plannedString, huffmanBit byte) []byte {
	offset := len(dst)
	if planned.huffman {
		length := hpack.HuffmanEncodeLength(value)
		dst = appendVarInt(dst, prefixBits, length)
		dst[offset] |= huffmanBit
		return hpack.AppendHuffmanString(dst, value)
	}
	dst = appendVarInt(dst, prefixBits, uint64(len(value)))
	return append(dst, value...)
}

func varIntLength(prefixBits uint8, value uint64) int {
	maxPrefixValue := uint64(1)<<prefixBits - 1
	if value < maxPrefixValue {
		return 1
	}
	value -= maxPrefixValue
	length := 2
	for value >= 128 {
		value >>= 7
		length++
	}
	return length
}
