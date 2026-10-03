package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

// Limits configures the resource limits of a StreamDecoder.
// The zero value disables all limits.
// All counters are kept across Push calls, i.e. they apply to the field
// section as a whole, not to individual chunks.
type Limits struct {
	// MaxEncodedBytes limits the size of the encoded field section, in bytes.
	MaxEncodedBytes uint64
	// MaxFieldSectionSize limits the decoded size of the field section.
	// Following the HTTP/2 convention (RFC 9113, Section 6.5.2), the size of
	// a field is the length of its name plus the length of its value in
	// bytes, plus an overhead of 32 bytes.
	MaxFieldSectionSize uint64
	// MaxFieldLength limits the combined length of a single field's
	// name and value, in bytes.
	MaxFieldLength uint64
}

// A ParseError describes a failure to decode a field section.
// Offset is the byte offset within the encoded field section at which the
// error was detected.
type ParseError struct {
	Offset uint64
	Err    error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("qpack: parse error at offset %d: %s", e.Offset, e.Err)
}

// Unwrap returns the underlying error,
// e.g. io.ErrUnexpectedEOF for a truncated field section.
func (e *ParseError) Unwrap() error { return e.Err }

var (
	errEncodedSectionTooLarge = errors.New("qpack: encoded field section exceeds limit")
	errFieldSectionTooLarge   = errors.New("qpack: decoded field section exceeds limit")
	errFieldTooLarge          = errors.New("qpack: header field exceeds limit")
	errSectionComplete        = errors.New("qpack: field section already complete")
)

type streamState uint8

const (
	streamStateRequiredInsertCount streamState = iota
	streamStateBase
	streamStateFields
)

// A StreamDecoder incrementally decodes a QPACK field section.
// Unlike Decoder, which requires the entire field section to be buffered
// before decoding starts, a StreamDecoder accepts the field section in
// arbitrarily small chunks via Push. Integer prefixes, string lengths and
// Huffman-encoded strings may all span chunk boundaries.
//
// A StreamDecoder decodes a single field section and must not be reused.
// Like Decoder, it only supports the static table: field sections that
// depend on the dynamic table are rejected.
type StreamDecoder struct {
	limits Limits

	state       streamState
	buf         []byte // unparsed bytes retained across Push calls
	offset      uint64 // number of bytes consumed so far
	sectionSize uint64 // decoded size of the field section so far
	done        bool
	err         error
}

// NewStreamDecoder returns a new StreamDecoder enforcing the given limits.
func NewStreamDecoder(limits Limits) *StreamDecoder {
	return &StreamDecoder{limits: limits}
}

// Push feeds a chunk of the encoded field section to the decoder.
// end must be set to true when pushing the final chunk of the field section.
//
// It returns the number of bytes consumed from p (the caller may reuse these
// bytes as soon as Push returns), the header fields completed by this call,
// and whether more input is required to finish the field section.
// A header field is only returned once it is complete and valid, and no
// field is returned more than once, even if a Push is retried.
//
// A non-nil error is a *ParseError carrying the offset of the failure within
// the field section. If the field section is truncated (end set to true
// before the section is complete), the error wraps io.ErrUnexpectedEOF.
// After an error, the decoder must not be used again.
func (d *StreamDecoder) Push(p []byte, end bool) (consumed int, hfs []HeaderField, needMore bool, err error) {
	if d.err != nil {
		return 0, nil, false, d.err
	}
	if d.done {
		return 0, nil, false, errSectionComplete
	}
	start := d.offset // offset of data[0] within the field section
	buffered := len(d.buf)
	data := p
	if buffered > 0 {
		d.buf = append(d.buf, p...)
		data = d.buf
	}
	if d.limits.MaxEncodedBytes > 0 && start+uint64(len(data)) > d.limits.MaxEncodedBytes {
		d.err = &ParseError{Offset: d.limits.MaxEncodedBytes, Err: errEncodedSectionTooLarge}
		return 0, nil, false, d.err
	}
	// consumedFromP converts a parse position within data to the number of
	// bytes consumed from p (as opposed to previously buffered bytes).
	consumedFromP := func(parsed int) int {
		n := parsed - buffered
		if n < 0 {
			return 0
		}
		if n > len(p) {
			return len(p)
		}
		return n
	}
	parsed := 0
	for parsed < len(data) {
		hf, ok, rest, err := d.parseNext(data[parsed:])
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) && !end {
				break // wait for more input
			}
			d.err = &ParseError{Offset: start + uint64(parsed), Err: err}
			return consumedFromP(parsed), hfs, false, d.err
		}
		parsed += len(data) - parsed - len(rest)
		if !ok {
			continue
		}
		fieldLen := uint64(len(hf.Name)) + uint64(len(hf.Value))
		if d.limits.MaxFieldLength > 0 && fieldLen > d.limits.MaxFieldLength {
			d.err = &ParseError{Offset: start + uint64(parsed), Err: errFieldTooLarge}
			return consumedFromP(parsed), hfs, false, d.err
		}
		d.sectionSize += fieldLen + 32
		if d.limits.MaxFieldSectionSize > 0 && d.sectionSize > d.limits.MaxFieldSectionSize {
			d.err = &ParseError{Offset: start + uint64(parsed), Err: errFieldSectionTooLarge}
			return consumedFromP(parsed), hfs, false, d.err
		}
		hfs = append(hfs, hf)
	}
	d.offset = start + uint64(parsed)
	// Retain the unparsed remainder for the next Push.
	// The caller is free to reuse p as soon as Push returns.
	if parsed < len(data) {
		d.buf = append(d.buf[:0], data[parsed:]...)
	} else {
		d.buf = d.buf[:0]
	}
	if end {
		if d.state != streamStateFields {
			// the prefix is incomplete: the field section is truncated
			d.err = &ParseError{Offset: d.offset, Err: io.ErrUnexpectedEOF}
			return len(p), hfs, false, d.err
		}
		d.done = true
		return len(p), hfs, false, nil
	}
	return len(p), hfs, true, nil
}

// Finish declares the end of the field section without providing more data.
// It is equivalent to calling Push with an empty chunk and end set to true:
// it returns nil if the field section (which may be empty) is complete, and
// an error wrapping io.ErrUnexpectedEOF if the field section is truncated.
func (d *StreamDecoder) Finish() error {
	_, _, _, err := d.Push(nil, true)
	return err
}

// parseNext parses the next item (a prefix integer or a header field) from data.
// ok reports whether a header field was completed.
// io.ErrUnexpectedEOF is returned if data doesn't contain a complete item.
func (d *StreamDecoder) parseNext(data []byte) (hf HeaderField, ok bool, rest []byte, err error) {
	switch d.state {
	case streamStateRequiredInsertCount:
		requiredInsertCount, rest, err := readVarInt(8, data)
		if err != nil {
			return HeaderField{}, false, data, err
		}
		if requiredInsertCount != 0 {
			return HeaderField{}, false, data, errors.New("expected Required Insert Count to be zero")
		}
		d.state = streamStateBase
		return HeaderField{}, false, rest, nil
	case streamStateBase:
		base, rest, err := readVarInt(7, data)
		if err != nil {
			return HeaderField{}, false, data, err
		}
		if base != 0 {
			return HeaderField{}, false, data, errors.New("expected Base to be zero")
		}
		d.state = streamStateFields
		return HeaderField{}, false, rest, nil
	default:
		return d.parseField(data)
	}
}

func (d *StreamDecoder) parseField(data []byte) (HeaderField, bool, []byte, error) {
	switch b := data[0]; {
	case b&0x80 > 0: // 1xxxxxxx
		hf, rest, err := d.parseIndexedHeaderField(data)
		return hf, err == nil, rest, err
	case b&0xc0 == 0x40: // 01xxxxxx
		hf, rest, err := d.parseLiteralHeaderField(data)
		return hf, err == nil, rest, err
	case b&0xe0 == 0x20: // 001xxxxx
		hf, rest, err := d.parseLiteralHeaderFieldWithoutNameReference(data)
		return hf, err == nil, rest, err
	default:
		return HeaderField{}, false, data, fmt.Errorf("unexpected type byte: %#x", b)
	}
}

func (d *StreamDecoder) parseIndexedHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
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

func (d *StreamDecoder) parseLiteralHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
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

func (d *StreamDecoder) parseLiteralHeaderFieldWithoutNameReference(buf []byte) (_ HeaderField, rest []byte, _ error) {
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

func (d *StreamDecoder) readString(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	l, buf, err := readVarInt(n, buf)
	if err != nil {
		return "", nil, err
	}
	// A single string longer than the field length limit can never be part
	// of a valid field. Rejecting it here avoids buffering it in full.
	if d.limits.MaxFieldLength > 0 && l > d.limits.MaxFieldLength {
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

func (d *StreamDecoder) at(i uint64) (hf HeaderField, ok bool) {
	if i >= uint64(len(staticTableEntries)) {
		return
	}
	return staticTableEntries[i], true
}
