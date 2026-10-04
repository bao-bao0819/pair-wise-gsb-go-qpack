package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

// processEncoderInstruction parses and executes exactly one encoder stream
// instruction (RFC 9204, Section 4.3) at the beginning of p.
// It returns the number of bytes consumed.
func (d *ConnectionDecoder) processEncoderInstruction(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	b := p[0]
	switch {
	case b&0x80 > 0: // 1Txxxxxx: Insert With Name Reference
		return d.insertWithNameReference(p)
	case b&0xc0 == 0x40: // 01Hxxxxx: Insert With Literal Name
		return d.insertWithLiteralName(p)
	case b&0xf0 == 0x20: // 0010xxxx: Set Dynamic Table Capacity
		return d.setTableCapacity(p)
	case b&0xf0 == 0x00: // 0000xxxx: Duplicate
		return d.insertDuplicate(p)
	default:
		return 0, fmt.Errorf("%w: invalid encoder stream instruction type byte %#x", ErrEncoderStreamError, b)
	}
}

func (d *ConnectionDecoder) setTableCapacity(raw []byte) (int, error) {
	c, rest, err := readVarInt(4, raw)
	if err != nil {
		return 0, err
	}
	if c > d.maxTableCapacity {
		return 0, InvalidCapacityError{Requested: c, Maximum: d.maxTableCapacity}
	}

	if sec := d.sectionEvicted(d.smallestAfterCapacityChange(c)); sec != nil {
		return 0, fmt.Errorf("stream %d: %w", sec.streamID, InvalidIndexError{Index: sec.minIndex, Dynamic: true, OnEncoderStream: true})
	}

	d.table.setCapacity(c)
	return len(raw) - len(rest), nil
}

// smallestAfterCapacityChange returns the absolute index of the oldest entry
// that would remain after shrinking the table capacity to c.
func (d *ConnectionDecoder) smallestAfterCapacityChange(c uint64) uint64 {
	tableSize := d.table.tableSize
	newSmallest := d.table.smallestAbsoluteIndex
	for i := 0; i < d.table.size; i++ {
		if tableSize <= c {
			break
		}
		tableSize -= d.table.entries[(d.table.head+i)%len(d.table.entries)].size
		newSmallest++
	}
	return newSmallest
}

// sectionEvicted returns a blocked field section referencing an entry older
// than newSmallest (RFC 9204, Section 4.1.1).
func (d *ConnectionDecoder) sectionEvicted(newSmallest uint64) *blockedSection {
	for _, sec := range d.pending {
		if sec.minIndex < newSmallest {
			return sec
		}
	}
	return nil
}

func (d *ConnectionDecoder) insertWithNameReference(raw []byte) (int, error) {
	dynamic := raw[0]&0x40 == 0
	index, rest, err := readVarInt(6, raw)
	if err != nil {
		return 0, err
	}

	var name string
	if dynamic {
		if index >= uint64(d.table.size) {
			return 0, InvalidIndexError{Index: index, Dynamic: true, OnEncoderStream: true}
		}
		e := d.table.entries[(d.table.head+d.table.size-1-int(index))%len(d.table.entries)]
		name = e.Name
	} else {
		if index >= uint64(len(staticTableEntries)) {
			return 0, InvalidIndexError{Index: index, OnEncoderStream: true}
		}
		name = staticTableEntries[index].Name
	}

	value, rest, err := readQString(rest, 7)
	if err != nil {
		return 0, wrapEncoderStream(err)
	}

	consumed := len(raw) - len(rest)
	if err := d.prepareInsert(name, value); err != nil {
		return 0, err
	}
	d.table.add(name, value)
	return consumed, nil
}

func (d *ConnectionDecoder) insertWithLiteralName(raw []byte) (int, error) {
	name, rest, err := readQString(raw, 5)
	if err != nil {
		return 0, wrapEncoderStream(err)
	}
	value, rest, err := readQString(rest, 7)
	if err != nil {
		return 0, wrapEncoderStream(err)
	}

	consumed := len(raw) - len(rest)
	if err := d.prepareInsert(name, value); err != nil {
		return 0, err
	}
	d.table.add(name, value)
	return consumed, nil
}

func (d *ConnectionDecoder) insertDuplicate(raw []byte) (int, error) {
	index, rest, err := readVarInt(5, raw)
	if err != nil {
		return 0, err
	}
	if index >= uint64(d.table.size) {
		return 0, InvalidIndexError{Index: index, Dynamic: true, OnEncoderStream: true}
	}
	e := d.table.entries[(d.table.head+d.table.size-1-int(index))%len(d.table.entries)]

	if err := d.prepareInsert(e.Name, e.Value); err != nil {
		return 0, err
	}
	d.table.add(e.Name, e.Value)
	return len(raw) - len(rest), nil
}

// prepareInsert validates the "Entry Too Large" rule (RFC 9204, Section
// 3.2.2) and makes sure the evictions caused by the new entry would not remove
// an entry referenced by a blocked field section.
func (d *ConnectionDecoder) prepareInsert(name, value string) error {
	newSize := dynamicEntrySize(name, value)
	if newSize > d.table.capacity && (d.table.capacity == 0 || d.table.size != 0) {
		return fmt.Errorf("entry (%q, %q) larger than dynamic table capacity %d: %w", name, value, d.table.capacity, ErrEncoderStreamError)
	}
	newSmallest := d.table.smallestAbsoluteIndex
	tableSize := d.table.tableSize + newSize
	for i := 0; i < d.table.size; i++ {
		if tableSize <= d.table.capacity {
			break
		}
		tableSize -= d.table.entries[(d.table.head+i)%len(d.table.entries)].size
		newSmallest++
	}
	if sec := d.sectionEvicted(newSmallest); sec != nil {
		return fmt.Errorf("stream %d: %w", sec.streamID, InvalidIndexError{Index: sec.minIndex, Dynamic: true, OnEncoderStream: true})
	}
	return nil
}

func wrapEncoderStream(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrEncoderStreamError, err)
}

// readQString reads an RFC 7541 string literal. The most significant bit of
// the n-bit prefix is the H (Huffman-encoded) bit.
func readQString(buf []byte, n uint8) (string, []byte, error) {
	if len(buf) == 0 {
		return "", nil, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&(1<<n) != 0
	l, rest, err := readVarInt(n, buf)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(rest)) < l {
		return "", nil, io.ErrUnexpectedEOF
	}
	if usesHuffman {
		s, err := hpack.HuffmanDecodeToString(rest[:l])
		if err != nil {
			return "", nil, err
		}
		return s, rest[l:], nil
	}
	return string(rest[:l]), rest[l:], nil
}
