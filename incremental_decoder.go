package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

// A DecodeError describes an error that occurred while decoding a field section.
// Offset is the byte offset within the encoded field section at which the
// error was detected.
type DecodeError struct {
	Offset uint64
	Err    error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("decoding error at offset %d: %s", e.Offset, e.Err)
}

func (e *DecodeError) Unwrap() error { return e.Err }

var (
	errEncodedSectionTooLarge = errors.New("encoded field section too large")
	errDecodedSectionTooLarge = errors.New("decoded field section too large")
	errFieldTooLarge          = errors.New("header field too large")
	errPushAfterFinish        = errors.New("qpack: Push called after the field section completed")
)

// decoder states
const (
	stateReadRequiredInsertCount uint8 = iota
	stateReadDeltaBase
	stateReadField
)

// An IncrementalDecoderOption configures an IncrementalDecoder.
type IncrementalDecoderOption func(*IncrementalDecoder)

// WithMaxEncodedBytes limits the total size of the encoded field section,
// in bytes. A zero value (the default) means no limit.
func WithMaxEncodedBytes(max uint64) IncrementalDecoderOption {
	return func(d *IncrementalDecoder) { d.maxEncodedBytes = max }
}

// WithMaxSectionSize limits the decoded size of the field section, defined as
// the sum of len(Name) + len(Value) over all header fields.
// A zero value (the default) means no limit.
func WithMaxSectionSize(max uint64) IncrementalDecoderOption {
	return func(d *IncrementalDecoder) { d.maxSectionSize = max }
}

// WithMaxFieldSize limits the size of a single header field, defined as
// len(Name) + len(Value). A zero value (the default) means no limit.
func WithMaxFieldSize(max uint64) IncrementalDecoderOption {
	return func(d *IncrementalDecoder) { d.maxFieldSize = max }
}

// An IncrementalDecoder incrementally decodes a QPACK field section.
// It only supports field sections that don't reference the dynamic table.
//
// Input is provided in arbitrarily sized chunks via Push. Chunks don't need
// to be aligned to header field boundaries: integer prefixes, string lengths
// and (Huffman-encoded) strings may span chunk boundaries. A header field is
// only delivered once it has been received in full and validated, and it is
// never delivered more than once.
type IncrementalDecoder struct {
	maxEncodedBytes uint64
	maxSectionSize  uint64
	maxFieldSize    uint64

	state       uint8
	offset      uint64 // number of bytes of the field section consumed so far
	sectionSize uint64 // sum of len(Name) + len(Value) of the fields delivered so far
	pending     bool   // whether the previous Push ended in the middle of a token
	finished    bool
	err         error
}

// NewIncrementalDecoder returns a new IncrementalDecoder.
func NewIncrementalDecoder(opts ...IncrementalDecoderOption) *IncrementalDecoder {
	d := &IncrementalDecoder{}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Push feeds a chunk of the encoded field section to the decoder.
// end must be set to true once the end of the field section is reached.
//
// It consumes as many bytes from the beginning of data as possible, and
// returns the number of bytes consumed, the header fields that were
// completed by this chunk, and whether more input is needed to finish the
// field section. The decoder doesn't retain any references to data: the
// caller may reuse the consumed prefix as soon as Push returns, but needs to
// pass the unconsumed remainder (data[consumed:]) again as part of the next
// Push.
//
// If end is set and the remaining input doesn't complete the field section,
// an error wrapping io.ErrUnexpectedEOF is returned.
// Any other error is terminal: subsequent Push calls return the same error.
// Errors are reported as *DecodeError, carrying the offset within the field
// section at which the error was detected.
func (d *IncrementalDecoder) Push(data []byte, end bool) (consumed int, fields []HeaderField, needMore bool, err error) {
	if d.err != nil {
		return 0, nil, false, d.err
	}
	if d.finished {
		return 0, nil, false, errPushAfterFinish
	}

	n := 0
	for n < len(data) {
		tokenOffset := d.offset
		c, hf, ok, err := d.step(data[n:])
		if err != nil {
			d.err = &DecodeError{Offset: tokenOffset, Err: err}
			break
		}
		if !ok { // need more input to complete the current token
			break
		}
		n += c
		d.offset += uint64(c)
		if d.maxEncodedBytes > 0 && d.offset > d.maxEncodedBytes {
			d.err = &DecodeError{Offset: d.maxEncodedBytes, Err: errEncodedSectionTooLarge}
			break
		}
		if hf != nil {
			if err := d.accountField(*hf, tokenOffset); err != nil {
				d.err = err
				break
			}
			fields = append(fields, *hf)
		}
	}
	consumed = n
	if len(data) > 0 {
		d.pending = n < len(data)
	}
	if d.err != nil {
		return consumed, fields, false, d.err
	}
	if end {
		if d.pending || d.state != stateReadField {
			d.err = &DecodeError{Offset: d.offset, Err: io.ErrUnexpectedEOF}
			return consumed, fields, false, d.err
		}
		d.finished = true
		return consumed, fields, false, nil
	}
	return consumed, fields, true, nil
}

// Finish signals that no more input will be provided.
// It returns nil if the field section (which may be empty) was received in
// full, and an error wrapping io.ErrUnexpectedEOF if it was truncated.
// Finish only needs to be called if the final Push didn't set the end flag.
func (d *IncrementalDecoder) Finish() error {
	if d.err != nil {
		return d.err
	}
	if d.finished {
		return nil
	}
	if d.state == stateReadField && !d.pending {
		d.finished = true
		return nil
	}
	d.err = &DecodeError{Offset: d.offset, Err: io.ErrUnexpectedEOF}
	return d.err
}

// step parses a single token (the field section prefix or one header field)
// from the beginning of b. It returns the number of bytes consumed and, if a
// header field was completed, that field. ok is false if more input is needed
// to complete the token.
func (d *IncrementalDecoder) step(b []byte) (consumed int, hf *HeaderField, ok bool, err error) {
	switch d.state {
	case stateReadRequiredInsertCount:
		requiredInsertCount, rest, err := readVarInt(8, b)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, nil, false, nil
			}
			return 0, nil, false, err
		}
		if requiredInsertCount != 0 {
			return 0, nil, false, errors.New("expected Required Insert Count to be zero")
		}
		d.state = stateReadDeltaBase
		return len(b) - len(rest), nil, true, nil
	case stateReadDeltaBase:
		base, rest, err := readVarInt(7, b)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, nil, false, nil
			}
			return 0, nil, false, err
		}
		if base != 0 {
			return 0, nil, false, errors.New("expected Base to be zero")
		}
		d.state = stateReadField
		return len(b) - len(rest), nil, true, nil
	default: // stateReadField
		field, rest, err := d.parseField(b)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, nil, false, nil
			}
			return 0, nil, false, err
		}
		return len(b) - len(rest), &field, true, nil
	}
}

func (d *IncrementalDecoder) accountField(hf HeaderField, offset uint64) error {
	size := uint64(len(hf.Name) + len(hf.Value))
	if d.maxFieldSize > 0 && size > d.maxFieldSize {
		return &DecodeError{Offset: offset, Err: errFieldTooLarge}
	}
	d.sectionSize += size
	if d.maxSectionSize > 0 && d.sectionSize > d.maxSectionSize {
		return &DecodeError{Offset: offset, Err: errDecodedSectionTooLarge}
	}
	return nil
}

func (d *IncrementalDecoder) parseField(buf []byte) (_ HeaderField, rest []byte, _ error) {
	b := buf[0]
	switch {
	case (b & 0x80) > 0: // 1xxxxxxx
		return d.parseIndexedHeaderField(buf)
	case (b & 0xc0) == 0x40: // 01xxxxxx
		return d.parseLiteralHeaderField(buf)
	case (b & 0xe0) == 0x20: // 001xxxxx
		return d.parseLiteralHeaderFieldWithoutNameReference(buf)
	default:
		return HeaderField{}, buf, fmt.Errorf("unexpected type byte: %#x", b)
	}
}

func (d *IncrementalDecoder) parseIndexedHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
	if buf[0]&0x40 == 0 {
		return HeaderField{}, buf, errNoDynamicTable
	}
	index, rest, err := readVarInt(6, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.at(index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	return hf, rest, nil
}

func (d *IncrementalDecoder) parseLiteralHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
	if buf[0]&0x10 == 0 {
		return HeaderField{}, buf, errNoDynamicTable
	}
	// We don't need to check the value of the N-bit here.
	// It's only relevant when re-encoding header fields,
	// and determines whether the header field can be added to the dynamic table.
	// Since we don't support the dynamic table, we can ignore it.
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.at(index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, buf, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&0x80 > 0
	val, rest, err := d.readString(rest, 7, usesHuffman)
	if err != nil {
		return HeaderField{}, rest, err
	}
	hf.Value = val
	return hf, rest, nil
}

func (d *IncrementalDecoder) parseLiteralHeaderFieldWithoutNameReference(buf []byte) (_ HeaderField, rest []byte, _ error) {
	usesHuffmanForName := buf[0]&0x8 > 0
	name, rest, err := d.readString(buf, 3, usesHuffmanForName)
	if err != nil {
		return HeaderField{}, rest, err
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, rest, io.ErrUnexpectedEOF
	}
	usesHuffmanForVal := buf[0]&0x80 > 0
	val, rest, err := d.readString(buf, 7, usesHuffmanForVal)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: val}, rest, nil
}

func (d *IncrementalDecoder) readString(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	l, buf, err := readVarInt(n, buf)
	if err != nil {
		return "", nil, err
	}
	// Reject strings that exceed the field size limit right away,
	// instead of buffering them first.
	if d.maxFieldSize > 0 && l > d.maxFieldSize {
		return "", nil, errFieldTooLarge
	}
	if uint64(len(buf)) < l {
		return "", nil, io.ErrUnexpectedEOF
	}
	var val string
	if usesHuffman {
		val, err = hpack.HuffmanDecodeToString(buf[:l])
		if err != nil {
			return "", nil, err
		}
	} else {
		val = string(buf[:l])
	}
	buf = buf[l:]
	return val, buf, nil
}

func (d *IncrementalDecoder) at(i uint64) (hf HeaderField, ok bool) {
	if i >= uint64(len(staticTableEntries)) {
		return
	}
	return staticTableEntries[i], true
}
