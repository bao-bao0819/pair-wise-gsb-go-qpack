package qpack

import (
	"errors"
	"fmt"
	"io"
)

type parsedSection struct {
	fields []preparedField
}

// parseFieldSection parses an encoded field section (RFC 9204, Section 4.5).
//
// It resolves every field line against the static table and the dynamic table
// at its current state. The Required Insert Count is unwrapped with the RFC
// pseudo-code. The returned result distinguishes three dynamic table cases:
//   - all referenced entries are present (nil error): the section is ready;
//   - a referenced entry has not been inserted yet (errSectionBlocked): the
//     caller may wait for the inserts and re-parse;
//   - a referenced entry has already been evicted (InvalidIndexError): the
//     connection has to be closed.
func (d *ConnectionDecoder) parseFieldSection(p []byte) (parsedSection, error) {
	ricEncoded, rest, err := readVarInt(8, p)
	if err != nil {
		return parsedSection{}, decompressionError(err)
	}
	if len(rest) == 0 {
		return parsedSection{}, truncatedSectionError()
	}
	signBit := rest[0]&0x80 > 0
	deltaBase, rest, err := readVarInt(7, rest)
	if err != nil {
		return parsedSection{}, decompressionError(err)
	}

	requiredInsertCount, err := decodeRIC(ricEncoded, d.table.knownReceivedCount, d.table.maxEntries())
	if err != nil {
		return parsedSection{}, err
	}

	var base int64
	if signBit {
		base = int64(requiredInsertCount) - int64(deltaBase) - 1
	} else {
		base = int64(requiredInsertCount) + int64(deltaBase)
	}

	sec := parsedSection{}
	blocked := false
	for len(rest) > 0 {
		b := rest[0]
		var f preparedField
		switch {
		case b&0x80 > 0: // 1Txxxxxx: Indexed Field Line
			f, rest, err = d.parseIndexedFieldLine(rest, base)
		case b&0xc0 == 0x40: // 01NTxxxx: Literal Field Line With Name Reference
			f, rest, err = d.parseLiteralWithNameReference(rest, base)
		case b&0xf0 == 0x10: // 0001xxxx: Literal Field Line With Post-Base Name
			f, rest, err = d.parseLiteralWithPostBaseName(rest, base)
		case b&0xf0 == 0x00: // 0000xxxx: Indexed Field Line With Post-Base Index
			f, rest, err = d.parsePostBaseIndexed(rest, base)
		case b&0xe0 == 0x20: // 001Hxxx: Literal Field Line Without Name Reference
			f, rest, err = d.parseLiteralWithoutName(rest)
		default:
			return parsedSection{}, fmt.Errorf("%w: invalid field line type byte %#x", ErrDecompressionFailed, b)
		}
		if err != nil {
			return parsedSection{}, err
		}
		if f.kind == fieldDynamic || f.kind == fieldDynamicName {
			switch {
			case f.index >= d.table.knownReceivedCount:
				blocked = true
			case f.index < d.table.smallestAbsoluteIndex:
				return sec, InvalidIndexError{Index: f.index, Dynamic: true}
			}
		}
		sec.fields = append(sec.fields, f)
	}
	if blocked {
		return sec, errSectionBlocked
	}
	return sec, nil
}

// requiredInspects returns the insert count at which the section becomes
// decodable (one past the largest dynamic table absolute index referenced)
// and the smallest referenced absolute index.
func (s parsedSection) requiredInserts() (needCount, minIndex uint64) {
	minIndex = ^uint64(0)
	for _, f := range s.fields {
		if f.kind != fieldDynamic && f.kind != fieldDynamicName {
			continue
		}
		if f.index+1 > needCount {
			needCount = f.index + 1
		}
		if f.index < minIndex {
			minIndex = f.index
		}
	}
	if needCount == 0 {
		minIndex = 0
	}
	return needCount, minIndex
}

func (d *ConnectionDecoder) parseIndexedFieldLine(buf []byte, base int64) (preparedField, []byte, error) {
	dynamic := buf[0]&0x40 == 0
	index, rest, err := readVarInt(6, buf)
	if err != nil {
		return preparedField{}, buf, decompressionError(err)
	}
	if dynamic {
		return preparedField{kind: fieldDynamic, index: uint64(base - 1 - int64(index))}, rest, nil
	}
	if index >= uint64(len(staticTableEntries)) {
		return preparedField{}, buf, InvalidIndexError{Index: index}
	}
	return preparedField{kind: fieldStaticIndex, index: index}, rest, nil
}

func (d *ConnectionDecoder) parseLiteralWithNameReference(buf []byte, base int64) (preparedField, []byte, error) {
	dynamic := buf[0]&0x10 == 0
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return preparedField{}, buf, decompressionError(err)
	}
	value, rest, err := readQString(rest, 7)
	if err != nil {
		return preparedField{}, rest, decompressionError(err)
	}
	if dynamic {
		return preparedField{kind: fieldDynamicName, index: uint64(base - 1 - int64(index)), value: value}, rest, nil
	}
	if index >= uint64(len(staticTableEntries)) {
		return preparedField{}, buf, InvalidIndexError{Index: index}
	}
	return preparedField{kind: fieldStaticName, index: index, value: value}, rest, nil
}

func (d *ConnectionDecoder) parsePostBaseIndexed(buf []byte, base int64) (preparedField, []byte, error) {
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return preparedField{}, buf, decompressionError(err)
	}
	return preparedField{kind: fieldDynamic, index: uint64(base + 1 + int64(index))}, rest, nil
}

func (d *ConnectionDecoder) parseLiteralWithPostBaseName(buf []byte, base int64) (preparedField, []byte, error) {
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return preparedField{}, buf, decompressionError(err)
	}
	value, rest, err := readQString(rest, 7)
	if err != nil {
		return preparedField{}, rest, decompressionError(err)
	}
	return preparedField{kind: fieldDynamicName, index: uint64(base + 1 + int64(index)), value: value}, rest, nil
}

func (d *ConnectionDecoder) parseLiteralWithoutName(buf []byte) (preparedField, []byte, error) {
	name, rest, err := readQString(buf, 3)
	if err != nil {
		return preparedField{}, rest, decompressionError(err)
	}
	value, rest, err := readQString(rest, 7)
	if err != nil {
		return preparedField{}, rest, decompressionError(err)
	}
	return preparedField{kind: fieldLiteral, name: name, value: value}, rest, nil
}

// decodeRIC unwraps the Required Insert Count using the algorithm from
// RFC 9204, Section 4.5.1.1.
func decodeRIC(encoded, knownReceivedCount, maxEntries uint64) (uint64, error) {
	if encoded == 0 {
		return 0, nil
	}
	fullRange := 2 * maxEntries
	if fullRange == 0 {
		return 0, fmt.Errorf("%w: Required Insert Count %d with empty dynamic table", ErrDecompressionFailed, encoded)
	}
	if encoded > fullRange {
		return 0, fmt.Errorf("%w: Required Insert Count %d larger than maximum value %d", ErrDecompressionFailed, encoded, fullRange)
	}

	// Reverse the wrapping from RFC 9204, Section 4.5.1.1: align to the
	// window containing Known Received Count. The result is the largest
	// value no larger than the current window end that is congruent to the
	// encoded value modulo FullRange; it may exceed Known Received Count, in
	// which case the field section is blocked on the missing inserts.
	if knownReceivedCount == 0 {
		return encoded, nil
	}
	return encoded + ((knownReceivedCount-1)/fullRange)*fullRange, nil
}

func truncatedSectionError() error {
	return fmt.Errorf("%w: truncated field section", ErrDecompressionFailed)
}

func decompressionError(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errVarintOverflow) {
		return truncatedSectionError()
	}
	return fmt.Errorf("%w: %v", ErrDecompressionFailed, err)
}
