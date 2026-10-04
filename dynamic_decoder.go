package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

var (
	// ErrDecompressionFailed is the parent error for all QPACK protocol errors
	// that make the QPACK decoder unusable. The HTTP/3 layer SHOULD map such an
	// error to the QPACK_DECOMPRESSION_FAILED (0x0200) connection error.
	ErrDecompressionFailed = errors.New("QPACK decompression failed")
	// ErrInvalidIndex is returned when an instruction or field section
	// references an entry that does not exist.
	ErrInvalidIndex = fmt.Errorf("%w: invalid index", ErrDecompressionFailed)
	// ErrInvalidTableCapacity is returned when an encoder stream Set Dynamic
	// Table Capacity instruction requests a capacity larger than the value
	// negotiated via SETTINGS_QPACK_MAX_TABLE_CAPACITY.
	ErrInvalidTableCapacity = fmt.Errorf("%w: invalid table capacity", ErrDecompressionFailed)
	// ErrTooManyBlockedStreams is returned when a field section requires
	// blocking while the number of already blocked streams has reached the
	// limit negotiated via SETTINGS_QPACK_BLOCKED_STREAMS.
	ErrTooManyBlockedStreams = fmt.Errorf("%w: too many blocked streams", ErrDecompressionFailed)
	// ErrInvalidBase is returned when the header block prefix specifies a Base
	// that is negative or larger than the Required Insert Count.
	ErrInvalidBase = fmt.Errorf("%w: invalid base", ErrDecompressionFailed)
	// ErrInvalidRequiredInsertCount is returned when the encoded Required
	// Insert Count cannot be decoded.
	ErrInvalidRequiredInsertCount = fmt.Errorf("%w: invalid required insert count", ErrDecompressionFailed)
)

// DecodedSection is a field section that was released by the connection-level
// decoder. StreamID is the QUIC stream on which the section arrived.
type DecodedSection struct {
	StreamID     uint64
	HeaderFields []HeaderField
}

type dynamicEntry struct {
	name  string
	value string
	size  int
}

// DynamicDecoder is a connection-level QPACK decoder with dynamic table
// support, as described in RFC 9204. It is independent of any QUIC transport:
// the caller feeds it bytes received on the encoder stream and complete field
// sections received on request streams, and it produces bytes that have to be
// sent on the decoder stream.
//
// A field section referencing dynamic table entries that have not been
// inserted yet is put into bounded waiting and is released as soon as the
// referenced entries arrive on the encoder stream.
//
// DynamicDecoder is safe for single-goroutine use only, as is typical when
// fed from an HTTP/3 receive loop.
type DynamicDecoder struct {
	maxTableCapacity int
	maxBlocked       int

	// knownCount is the number of inserts that the decoder has processed.
	knownCount int
	// Dynamic table storage, organized as a ring buffer.
	entries  []dynamicEntry
	head     int // slot holding the entry with the smallest absolute index
	resident int // number of entries currently resident
	// totalSize is the sum of sizes of resident entries.
	totalSize int
	// capacity is the dynamic table capacity set by the most recent Set
	// Dynamic Table Capacity instruction.
	capacity int

	blocked []blockedSection

	// pending holds the remainder of the last FeedEncoderStream call that did
	// not contain a complete instruction.
	pending []byte
}

type blockedSection struct {
	streamID uint64
	ric      int
	data     []byte
}

// NewDynamicDecoder returns a connection-level decoder supporting the dynamic
// table. maxTableCapacity is the value advertised via
// SETTINGS_QPACK_MAX_TABLE_CAPACITY, and maxBlockedStreams the value
// advertised via SETTINGS_QPACK_BLOCKED_STREAMS.
func NewDynamicDecoder(maxTableCapacity int, maxBlockedStreams int) *DynamicDecoder {
	ringLen := maxTableCapacity/32 + 2
	if ringLen < 2 {
		ringLen = 2
	}
	return &DynamicDecoder{
		maxTableCapacity: maxTableCapacity,
		maxBlocked:       maxBlockedStreams,
		entries:          make([]dynamicEntry, ringLen),
	}
}

// KnownInsertCount returns the number of dynamic table inserts processed so
// far.
func (d *DynamicDecoder) KnownInsertCount() int { return d.knownCount }

// BlockedStreams returns the number of streams currently waiting for inserts.
func (d *DynamicDecoder) BlockedStreams() int { return len(d.blocked) }

// FeedEncoderStream processes bytes received on the encoder stream. Encoder
// stream instructions can be delivered across arbitrarily sized chunks;
// incomplete instructions are buffered internally.
//
// It returns the feedback to be written to the decoder stream (insert count
// increment and acknowledgments of sections that were unblocked), as well as
// the sections that became decodable. An error indicates a QPACK protocol
// error; the decoder must not be used afterwards.
func (d *DynamicDecoder) FeedEncoderStream(p []byte) (feedback []byte, sections []DecodedSection, err error) {
	if len(d.pending) > 0 {
		d.pending = append(d.pending, p...)
		p = d.pending
		d.pending = nil
	}
	oldCount := d.knownCount
	buf := p
	var acks []uint64
	for len(buf) > 0 {
		rest, ierr := d.processInstruction(buf)
		if ierr != nil {
			if !errors.Is(ierr, io.ErrUnexpectedEOF) {
				return d.buildFeedback(feedback, oldCount, acks), sections, ierr
			}
			d.pending = append(d.pending, buf...)
			return d.buildFeedback(feedback, oldCount, acks), sections, nil
		}
		buf = rest
		var rerr error
		acks, sections, rerr = d.releaseBlocked(acks, sections)
		if rerr != nil {
			return d.buildFeedback(feedback, oldCount, acks), sections, rerr
		}
	}
	return d.buildFeedback(feedback, oldCount, acks), sections, nil
}

// FeedFieldSection processes a complete field section (the QPACK header block,
// including the prefix) received on stream streamID.
//
// If the section references dynamic table entries that have not been inserted
// yet, it is put into bounded waiting (subject to the blocked streams limit)
// and nil fields are returned; it will later be returned by FeedEncoderStream.
// Every section is delivered at most once.
func (d *DynamicDecoder) FeedFieldSection(streamID uint64, data []byte) (fields []HeaderField, feedback []byte, err error) {
	ric, base, body, err := d.parsePrefix(data)
	if err != nil {
		return nil, nil, err
	}
	if ric > d.knownCount {
		if d.blockedIndex(streamID) >= 0 {
			return nil, nil, fmt.Errorf("%w: section for stream %d already blocked", ErrDecompressionFailed, streamID)
		}
		if len(d.blocked) >= d.maxBlocked {
			return nil, nil, ErrTooManyBlockedStreams
		}
		blockedData := make([]byte, len(data))
		copy(blockedData, data)
		d.blocked = append(d.blocked, blockedSection{
			streamID: streamID,
			ric:      ric,
			data:     blockedData,
		})
		return nil, nil, nil
	}
	fields, err = d.decodeSection(body, base)
	if err != nil {
		return nil, nil, err
	}
	feedback = appendSectionAcknowledgment(nil, streamID)
	return fields, feedback, nil
}

// CancelStream notifies the decoder that streamID was canceled by the
// application, so no more field sections will be delivered on it. If a
// section for that stream is currently blocked, it returns a Stream Cancellation
// instruction to send on the decoder stream. This is an application-level
// action and never results in a protocol error.
func (d *DynamicDecoder) CancelStream(streamID uint64) []byte {
	idx := d.blockedIndex(streamID)
	if idx < 0 {
		return nil
	}
	d.blocked = append(d.blocked[:idx], d.blocked[idx+1:]...)
	return appendStreamCancellation(nil, streamID)
}

func (d *DynamicDecoder) blockedIndex(streamID uint64) int {
	for i, s := range d.blocked {
		if s.streamID == streamID {
			return i
		}
	}
	return -1
}

func (d *DynamicDecoder) buildFeedback(feedback []byte, oldCount int, acks []uint64) []byte {
	if d.knownCount > oldCount {
		feedback = appendInsertCountIncrement(feedback, d.knownCount-oldCount)
	}
	for _, streamID := range acks {
		feedback = appendSectionAcknowledgment(feedback, streamID)
	}
	return feedback
}

func (d *DynamicDecoder) releaseBlocked(acks []uint64, sections []DecodedSection) ([]uint64, []DecodedSection, error) {
	kept := d.blocked[:0]
	for _, s := range d.blocked {
		if s.ric > d.knownCount {
			kept = append(kept, s)
			continue
		}
		_, base, body, perr := d.parsePrefix(s.data)
		if perr != nil {
			d.blocked = kept
			return acks, sections, perr
		}
		fields, derr := d.decodeSection(body, base)
		if derr != nil {
			d.blocked = kept
			return acks, sections, derr
		}
		acks = append(acks, s.streamID)
		sections = append(sections, DecodedSection{
			StreamID:     s.streamID,
			HeaderFields: fields,
		})
	}
	d.blocked = kept
	return acks, sections, nil
}

// parsePrefix parses the header block prefix (RFC 9204, section 4.5.1) and
// returns the Required Insert Count, the Base and the remainder of the block.
func (d *DynamicDecoder) parsePrefix(p []byte) (ric int, base int, body []byte, err error) {
	encodedRIC, rest, err := readVarInt(8, p)
	if err != nil {
		return 0, 0, nil, err
	}
	if encodedRIC != 0 {
		ric, err = decodeRequiredInsertCount(int(encodedRIC), d.knownCount, d.maxTableCapacity)
		if err != nil {
			return 0, 0, nil, err
		}
	}
	if len(rest) == 0 {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	sign := rest[0]&0x80 > 0
	deltaBase, rest, err := readVarInt(7, rest)
	if err != nil {
		return 0, 0, nil, err
	}
	if sign {
		base = ric - int(deltaBase)
	} else {
		base = ric + int(deltaBase)
	}
	if base < 0 || base > ric {
		return 0, 0, nil, fmt.Errorf("%w: base %d for required insert count %d", ErrInvalidBase, base, ric)
	}
	return ric, base, rest, nil
}

// decodeRequiredInsertCount decodes the wire encoding of the Required Insert
// Count (RFC 9204, section 4.5.1.1). fullInsertCount is the current Known
// Insert Count on the decoder.
func decodeRequiredInsertCount(encoded, fullInsertCount, maxTableCapacity int) (int, error) {
	if encoded == 0 {
		return 0, nil
	}
	maxEntries := maxTableCapacity / 32
	if maxEntries == 0 {
		return 0, ErrInvalidRequiredInsertCount
	}
	maxValue := 2 * maxEntries
	if encoded > maxValue {
		return 0, ErrInvalidRequiredInsertCount
	}
	// RFC 9204, section 4.5.1.1.
	tempCAS := fullInsertCount + maxEntries
	maxWrapped := tempCAS / maxValue
	ric := encoded + maxWrapped*maxValue
	if ric > tempCAS {
		ric -= maxValue
	}
	if ric <= 0 || ric > tempCAS {
		return 0, ErrInvalidRequiredInsertCount
	}
	return ric, nil
}

func (d *DynamicDecoder) decodeSection(body []byte, base int) ([]HeaderField, error) {
	var fields []HeaderField
	for len(body) > 0 {
		b := body[0]
		var hf HeaderField
		var rest []byte
		var err error
		switch {
		case b&0x80 > 0: // 1xxxxxxx: Indexed Field Line
			hf, rest, err = d.parseIndexedFieldLine(body, base)
		case b&0xc0 == 0x40: // 01xxxxxx: Literal Field Line With Name Reference
			hf, rest, err = d.parseLiteralWithNameReference(body, base)
		case b&0xf0 == 0x10: // 0001xxxx: Indexed Field Line With Post-Base Index
			hf, rest, err = d.parsePostBaseIndexedFieldLine(body, base)
		case b&0xe0 == 0x20: // 001xxxxx: Literal Field Line Without Name Reference
			hf, rest, err = d.parseLiteralWithoutNameReference(body)
		default: // 0000xxxx: Literal Field Line With Post-Base Name Reference
			hf, rest, err = d.parsePostBaseLiteralWithNameReference(body, base)
		}
		if err != nil {
			return nil, err
		}
		fields = append(fields, hf)
		body = rest
	}
	return fields, nil
}

func (d *DynamicDecoder) parseIndexedFieldLine(p []byte, base int) (HeaderField, []byte, error) {
	usesStatic := p[0]&0x40 > 0
	index, rest, err := readVarInt(6, p)
	if err != nil {
		return HeaderField{}, p, err
	}
	hf, ok := d.lookupField(usesStatic, int(index), base, false)
	if !ok {
		return HeaderField{}, p, fmt.Errorf("%w: indexed field line index %d", ErrInvalidIndex, index)
	}
	return hf, rest, nil
}

func (d *DynamicDecoder) parseLiteralWithNameReference(p []byte, base int) (HeaderField, []byte, error) {
	usesStatic := p[0]&0x10 > 0
	index, rest, err := readVarInt(4, p)
	if err != nil {
		return HeaderField{}, p, err
	}
	name, ok := d.lookupName(usesStatic, int(index), base, false)
	if !ok {
		return HeaderField{}, p, fmt.Errorf("%w: literal name reference index %d", ErrInvalidIndex, index)
	}
	value, rest, err := readFieldString(rest)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: value}, rest, nil
}

func (d *DynamicDecoder) parsePostBaseIndexedFieldLine(p []byte, base int) (HeaderField, []byte, error) {
	index, rest, err := readVarInt(4, p)
	if err != nil {
		return HeaderField{}, p, err
	}
	hf, ok := d.lookupField(false, int(index), base, true)
	if !ok {
		return HeaderField{}, p, fmt.Errorf("%w: post-base indexed field line index %d", ErrInvalidIndex, index)
	}
	return hf, rest, nil
}

func (d *DynamicDecoder) parsePostBaseLiteralWithNameReference(p []byte, base int) (HeaderField, []byte, error) {
	index, rest, err := readVarInt(3, p)
	if err != nil {
		return HeaderField{}, p, err
	}
	name, ok := d.lookupName(false, int(index), base, true)
	if !ok {
		return HeaderField{}, p, fmt.Errorf("%w: post-base literal name reference index %d", ErrInvalidIndex, index)
	}
	value, rest, err := readFieldString(rest)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: value}, rest, nil
}

func (d *DynamicDecoder) parseLiteralWithoutNameReference(p []byte) (HeaderField, []byte, error) {
	usesHuffmanForName := p[0]&0x04 > 0
	name, rest, err := readPrefixedString(p, 4, usesHuffmanForName)
	if err != nil {
		return HeaderField{}, rest, err
	}
	value, rest, err := readFieldString(rest)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: value}, rest, nil
}

func readFieldString(p []byte) (string, []byte, error) {
	if len(p) == 0 {
		return "", p, io.ErrUnexpectedEOF
	}
	usesHuffman := p[0]&0x80 > 0
	return readPrefixedString(p, 7, usesHuffman)
}

func readPrefixedString(p []byte, n byte, usesHuffman bool) (string, []byte, error) {
	l, rest, err := readVarInt(n, p)
	if err != nil {
		return "", p, err
	}
	if uint64(len(rest)) < l {
		return "", rest, io.ErrUnexpectedEOF
	}
	if usesHuffman {
		s, err := hpack.HuffmanDecodeToString(rest[:l])
		if err != nil {
			return "", rest, err
		}
		return s, rest[l:], nil
	}
	return string(rest[:l]), rest[l:], nil
}

// lookupField resolves a field reference. postBase selects the post-base
// indexing; otherwise index is a static table index (usesStatic) or a relative
// index into the dynamic table.
func (d *DynamicDecoder) lookupField(usesStatic bool, index, base int, postBase bool) (HeaderField, bool) {
	switch {
	case usesStatic && !postBase:
		if index < 0 || index >= len(staticTableEntries) {
			return HeaderField{}, false
		}
		return staticTableEntries[index], true
	default:
		entry, ok := d.dynamicEntry(index, base, postBase)
		if !ok {
			return HeaderField{}, false
		}
		return HeaderField{Name: entry.name, Value: entry.value}, true
	}
}

func (d *DynamicDecoder) lookupName(usesStatic bool, index, base int, postBase bool) (string, bool) {
	switch {
	case usesStatic && !postBase:
		if index < 0 || index >= len(staticTableEntries) {
			return "", false
		}
		return staticTableEntries[index].Name, true
	default:
		entry, ok := d.dynamicEntry(index, base, postBase)
		if !ok {
			return "", false
		}
		return entry.name, true
	}
}

// dynamicEntry resolves a dynamic table reference to a resident entry.
// For relative references, the absolute index is Base - 1 - index; for
// post-base references it is Base + index (RFC 9204, sections 4.5.2-4.5.4).
func (d *DynamicDecoder) dynamicEntry(index, base int, postBase bool) (dynamicEntry, bool) {
	if index < 0 || d.resident == 0 {
		return dynamicEntry{}, false
	}
	absolute := base - 1 - index
	if postBase {
		absolute = base + index
	}
	if absolute < d.knownCount-d.resident || absolute >= d.knownCount {
		return dynamicEntry{}, false
	}
	slot := (d.head + (absolute - (d.knownCount - d.resident))) % len(d.entries)
	return d.entries[slot], true
}

// processInstruction parses a single encoder stream instruction
// (RFC 9204, section 4.4) and applies it to the dynamic table.
func (d *DynamicDecoder) processInstruction(p []byte) ([]byte, error) {
	if len(p) == 0 {
		return p, io.ErrUnexpectedEOF
	}
	b := p[0]
	switch {
	case b&0x80 > 0: // 1Txxxxxx: Insert With Name Reference
		return d.insertWithNameReference(p, b&0x40 > 0)
	case b&0xc0 == 0x40: // 01xxxxxx: Insert With Literal Name
		return d.insertWithLiteralName(p)
	case b&0xe0 == 0x20: // 001xxxxx: Set Dynamic Table Capacity
		return d.setCapacity(p)
	default: // 000xxxxx: Duplicate
		return d.duplicate(p)
	}
}

func (d *DynamicDecoder) insertWithNameReference(p []byte, usesStatic bool) ([]byte, error) {
	var name string
	index, rest, err := readVarInt(6, p)
	if err != nil {
		return p, err
	}
	if usesStatic {
		if index >= uint64(len(staticTableEntries)) {
			return p, fmt.Errorf("%w: insert referencing static table index %d", ErrInvalidIndex, index)
		}
		name = staticTableEntries[index].Name
	} else {
		entry, ok := d.dynamicEntry(int(index), d.knownCount, false)
		if !ok {
			return p, fmt.Errorf("%w: insert referencing dynamic relative index %d", ErrInvalidIndex, index)
		}
		name = entry.name
	}
	value, rest, err := readFieldString(rest)
	if err != nil {
		return rest, err
	}
	if err := d.insert(name, value); err != nil {
		return rest, err
	}
	return rest, nil
}

func (d *DynamicDecoder) insertWithLiteralName(p []byte) ([]byte, error) {
	usesHuffmanForName := p[0]&0x20 > 0
	name, rest, err := readPrefixedString(p, 5, usesHuffmanForName)
	if err != nil {
		return rest, err
	}
	value, rest, err := readFieldString(rest)
	if err != nil {
		return rest, err
	}
	if err := d.insert(name, value); err != nil {
		return rest, err
	}
	return rest, nil
}

func (d *DynamicDecoder) setCapacity(p []byte) ([]byte, error) {
	capacity, rest, err := readVarInt(5, p)
	if err != nil {
		return p, err
	}
	if capacity > uint64(d.maxTableCapacity) {
		return rest, fmt.Errorf("%w: requested %d, maximum %d", ErrInvalidTableCapacity, capacity, d.maxTableCapacity)
	}
	c := int(capacity)
	for d.totalSize > c && d.resident > 0 {
		d.evictOldest()
	}
	d.capacity = c
	return rest, nil
}

func (d *DynamicDecoder) duplicate(p []byte) ([]byte, error) {
	index, rest, err := readVarInt(5, p)
	if err != nil {
		return p, err
	}
	entry, ok := d.dynamicEntry(int(index), d.knownCount, false)
	if !ok {
		return p, fmt.Errorf("%w: duplicate relative index %d", ErrInvalidIndex, index)
	}
	return rest, d.insert(entry.name, entry.value)
}

// insert adds a new entry, evicting entries as permitted by the current
// dynamic table capacity.
func (d *DynamicDecoder) insert(name, value string) error {
	size := len(name) + len(value) + 32
	for d.resident > 0 && d.totalSize+size > d.capacity {
		d.evictOldest()
	}
	if size > d.capacity {
		return fmt.Errorf("%w: entry of size %d exceeds capacity %d", ErrDecompressionFailed, size, d.capacity)
	}
	if d.resident == len(d.entries) {
		// The ring is sized for the maximum number of simultaneously resident
		// entries; reaching its end means the negotiated capacity was exceeded.
		return fmt.Errorf("%w: dynamic table full", ErrDecompressionFailed)
	}
	slot := (d.head + d.resident) % len(d.entries)
	d.entries[slot] = dynamicEntry{name: name, value: value, size: size}
	d.resident++
	d.totalSize += size
	d.knownCount++
	return nil
}

func (d *DynamicDecoder) evictOldest() {
	oldest := d.entries[d.head]
	d.totalSize -= oldest.size
	d.entries[d.head] = dynamicEntry{}
	d.head = (d.head + 1) % len(d.entries)
	d.resident--
}

// appendSectionAcknowledgment appends a Section Acknowledgment instruction
// (0x1 type, 7-bit prefix stream ID) to dst.
func appendSectionAcknowledgment(dst []byte, streamID uint64) []byte {
	start := len(dst)
	dst = appendVarInt(dst, 7, streamID)
	dst[start] |= 0x80
	return dst
}

// appendStreamCancellation appends a Stream Cancellation instruction
// (0x1 type, 6-bit prefix stream ID) to dst.
func appendStreamCancellation(dst []byte, streamID uint64) []byte {
	start := len(dst)
	dst = appendVarInt(dst, 6, streamID)
	dst[start] |= 0x40
	return dst
}

// appendInsertCountIncrement appends an Insert Count Increment instruction
// (0x0 type, 6-bit prefix increment) to dst.
func appendInsertCountIncrement(dst []byte, increment int) []byte {
	return appendVarInt(dst, 6, uint64(increment))
}
