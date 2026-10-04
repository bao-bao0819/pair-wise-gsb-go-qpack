package qpack

import (
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/net/http2/hpack"
)

var (
	// ErrDecompressionFailed is the parent error for protocol errors that make
	// the QPACK decoder unusable.
	ErrDecompressionFailed = errors.New("qpack decompression failed")
	// ErrInvalidIndex is returned for a reference that cannot be resolved.
	ErrInvalidIndex = fmt.Errorf("%w: invalid index", ErrDecompressionFailed)
	// ErrInvalidTableCapacity is returned for an illegal capacity change.
	ErrInvalidTableCapacity = fmt.Errorf("%w: invalid dynamic table capacity", ErrDecompressionFailed)
	// ErrTooManyBlockedStreams is returned when the blocked-stream limit is exceeded.
	ErrTooManyBlockedStreams = fmt.Errorf("%w: too many blocked streams", ErrDecompressionFailed)
)

// DecodedSection is a field section released after its referenced inserts arrived.
type DecodedSection struct {
	StreamID     uint64
	HeaderFields []HeaderField
}

// DynamicDecoder is a transport-independent, connection-level QPACK decoder.
// It consumes encoder-stream instructions and complete field sections, and
// produces decoder-stream instructions for the HTTP/3 layer.
type DynamicDecoder struct {
	maxTableCapacity uint64
	maxBlocked       uint64

	knownInsertCount uint64
	capacity         uint64
	entries          []dynamicEntry
	totalSize        uint64

	blocked []blockedSection
	pending []byte
	err     error
}

type dynamicEntry struct {
	name  string
	value string
	size  uint64
}

type blockedSection struct {
	streamID     uint64
	required     uint64
	minimumIndex uint64
	fields       []fieldRep
}

type fieldRep struct {
	name          string
	value         string
	dynamicIndex  uint64
	postBase      bool
	useTableValue bool
	nameType      fieldNameType
}

type fieldNameType uint8

const (
	nameLiteral fieldNameType = iota
	nameStatic
	nameDynamic
)

// NewDynamicDecoder creates a decoder using the values advertised in
// SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS.
func NewDynamicDecoder(maxTableCapacity, maxBlockedStreams int) *DynamicDecoder {
	d := &DynamicDecoder{}
	if maxTableCapacity > 0 {
		d.maxTableCapacity = uint64(maxTableCapacity)
	}
	if maxBlockedStreams > 0 {
		d.maxBlocked = uint64(maxBlockedStreams)
	}
	return d
}

// KnownInsertCount returns the number of encoder-stream inserts processed.
func (d *DynamicDecoder) KnownInsertCount() int { return int(d.knownInsertCount) }

// BlockedStreams returns the number of field sections currently waiting.
func (d *DynamicDecoder) BlockedStreams() int { return len(d.blocked) }

// FeedEncoderStream consumes one chunk of encoder-stream bytes. Incomplete
// instructions are retained and completed by later calls.
func (d *DynamicDecoder) FeedEncoderStream(p []byte) (feedback []byte, sections []DecodedSection, err error) {
	if d.err != nil {
		return nil, nil, d.err
	}
	if len(d.pending) > 0 {
		d.pending = append(d.pending, p...)
		p = d.pending
		d.pending = nil
	}
	oldCount := d.knownInsertCount

	for len(p) > 0 {
		rest, perr := d.processInstruction(p)
		if perr != nil {
			if errors.Is(perr, io.ErrUnexpectedEOF) {
				d.pending = append(d.pending[:0], p...)
				return appendIncrement(nil, d.knownInsertCount, oldCount), sections, nil
			}
			return appendIncrement(nil, d.knownInsertCount, oldCount), sections, d.fail(perr)
		}
		p = rest
		d.pending = nil

		var released []DecodedSection
		released, perr = d.releaseBlocked()
		if perr != nil {
			sections = append(sections, released...)
			feedback = appendIncrement(nil, d.knownInsertCount, oldCount)
			feedback = appendAcknowledgments(feedback, released)
			return feedback, sections, d.fail(perr)
		}
		sections = append(sections, released...)
	}

	feedback = appendIncrement(nil, d.knownInsertCount, oldCount)
	feedback = appendAcknowledgments(feedback, sections)
	return feedback, sections, nil
}

// FeedFieldSection consumes a complete QPACK field section from one stream.
// If its inserts have not arrived yet, the section is held in bounded waiting.
func (d *DynamicDecoder) FeedFieldSection(streamID uint64, data []byte) (fields []HeaderField, feedback []byte, err error) {
	if d.err != nil {
		return nil, nil, d.err
	}
	required, base, body, perr := d.parsePrefix(data)
	if perr != nil {
		return nil, nil, d.fail(perr)
	}
	reps, minimumIndex, perr := d.parseFieldReps(body, required, base)
	if perr != nil {
		return nil, nil, d.fail(perr)
	}

	if required > d.knownInsertCount {
		if d.blockedIndex(streamID) >= 0 {
			return nil, nil, d.fail(fmt.Errorf("%w: duplicate field section for stream %d", ErrDecompressionFailed, streamID))
		}
		if uint64(len(d.blocked)) >= d.maxBlocked {
			return nil, nil, d.fail(ErrTooManyBlockedStreams)
		}
		d.blocked = append(d.blocked, blockedSection{
			streamID:     streamID,
			required:     required,
			minimumIndex: minimumIndex,
			fields:       reps,
		})
		return nil, nil, nil
	}

	fields, perr = d.resolveReps(reps)
	if perr != nil {
		return nil, nil, d.fail(perr)
	}
	return fields, appendSectionAcknowledgment(nil, streamID), nil
}

// CancelStream removes a blocked section canceled by the application and
// returns a Stream Cancellation instruction. This is never a connection error.
func (d *DynamicDecoder) CancelStream(streamID uint64) []byte {
	index := d.blockedIndex(streamID)
	if index < 0 {
		return nil
	}
	d.blocked = append(d.blocked[:index], d.blocked[index+1:]...)
	return appendStreamCancellation(nil, streamID)
}

func (d *DynamicDecoder) blockedIndex(streamID uint64) int {
	for i := range d.blocked {
		if d.blocked[i].streamID == streamID {
			return i
		}
	}
	return -1
}

func (d *DynamicDecoder) fail(err error) error {
	if d.err == nil {
		d.err = err
		d.blocked = nil
		d.pending = nil
		d.entries = nil
	}
	return d.err
}

func (d *DynamicDecoder) releaseBlocked() ([]DecodedSection, error) {
	kept := make([]blockedSection, 0, len(d.blocked))
	var sections []DecodedSection
	for _, section := range d.blocked {
		if section.required > d.knownInsertCount {
			kept = append(kept, section)
			continue
		}
		fields, err := d.resolveReps(section.fields)
		if err != nil {
			d.blocked = kept
			return sections, err
		}
		sections = append(sections, DecodedSection{
			StreamID:     section.streamID,
			HeaderFields: fields,
		})
	}
	d.blocked = kept
	return sections, nil
}

func appendIncrement(dst []byte, current, old uint64) []byte {
	if current <= old {
		return dst
	}
	return appendInsertCountIncrement(dst, current-old)
}

func appendAcknowledgments(dst []byte, sections []DecodedSection) []byte {
	for _, section := range sections {
		dst = appendSectionAcknowledgment(dst, section.StreamID)
	}
	return dst
}

func (d *DynamicDecoder) parsePrefix(p []byte) (required uint64, base int64, body []byte, err error) {
	encoded, rest, err := readVarInt(8, p)
	if err != nil {
		return 0, 0, nil, protocolError(err)
	}
	if encoded != 0 {
		required, err = decodeRequiredInsertCount(encoded, d.knownInsertCount, d.maxTableCapacity)
		if err != nil {
			return 0, 0, nil, err
		}
	}
	if len(rest) == 0 {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	hasSign := rest[0]&0x80 != 0
	delta, rest, err := readVarInt(7, rest)
	if err != nil {
		return 0, 0, nil, protocolError(err)
	}

	if hasSign {
		if required > math.MaxInt64 || delta > math.MaxInt64 {
			return 0, 0, nil, ErrInvalidIndex
		}
		base = int64(required) - int64(delta)
	} else {
		if required > math.MaxInt64 || delta > math.MaxInt64-required-1 {
			return 0, 0, nil, ErrInvalidIndex
		}
		base = int64(required) + int64(delta) + 1
	}
	return required, base, rest, nil
}

func decodeRequiredInsertCount(encoded, fullInsertCount, maxTableCapacity uint64) (uint64, error) {
	maxEntries := maxTableCapacity / 32
	if maxEntries == 0 {
		return 0, fmt.Errorf("%w: required insert count with empty dynamic table", ErrInvalidIndex)
	}
	fullRange := 2 * maxEntries
	if fullRange == 0 {
		return 0, ErrInvalidIndex
	}
	if encoded > fullRange {
		return 0, fmt.Errorf("%w: encoded required insert count %d", ErrInvalidIndex, encoded)
	}
	maxWrapped := (fullInsertCount + maxEntries) / fullRange
	if maxWrapped > (math.MaxUint64-encoded)/fullRange {
		return 0, ErrInvalidIndex
	}
	required := encoded + maxWrapped*fullRange
	if required > fullInsertCount+maxEntries {
		if required < fullRange {
			return 0, ErrInvalidIndex
		}
		required -= fullRange
	}
	if required == 0 || required > fullInsertCount+maxEntries {
		return 0, fmt.Errorf("%w: required insert count %d", ErrInvalidIndex, required)
	}
	return required, nil
}

func (d *DynamicDecoder) parseFieldReps(p []byte, required uint64, base int64) ([]fieldRep, uint64, error) {
	var reps []fieldRep
	minimumIndex := uint64(math.MaxUint64)
	hasDynamicReference := false
	for len(p) > 0 {
		rep, rest, err := d.parseFieldRep(p, base)
		if err != nil {
			return nil, 0, err
		}
		if rep.nameType == nameDynamic {
			absolute := rep.dynamicIndex
			if absolute >= required {
				return nil, 0, fmt.Errorf("%w: dynamic index %d for required insert count %d", ErrInvalidIndex, absolute, required)
			}
			if !rep.postBase {
				hasDynamicReference = true
			}
			if absolute < minimumIndex {
				minimumIndex = absolute
			}
		}
		reps = append(reps, rep)
		p = rest
	}
	if !hasDynamicReference {
		minimumIndex = required
	}
	return reps, minimumIndex, nil
}

func (d *DynamicDecoder) parseFieldRep(p []byte, base int64) (fieldRep, []byte, error) {
	b := p[0]
	switch {
	case b&0x80 != 0:
		index, rest, err := readVarInt(6, p)
		if err != nil {
			return fieldRep{}, nil, protocolError(err)
		}
		if b&0x40 != 0 {
			rep := staticRep(index, false)
			rep.useTableValue = true
			return rep, rest, checkStaticIndex(index)
		}
		rep, err := relativeDynamicRep(index, base)
		return rep, rest, err

	case b&0xc0 == 0x40:
		index, rest, err := readVarInt(4, p)
		if err != nil {
			return fieldRep{}, nil, protocolError(err)
		}
		if b&0x10 != 0 {
			if err := checkStaticIndex(index); err != nil {
				return fieldRep{}, nil, err
			}
			value, rest, err := readFieldValue(rest)
			if err != nil {
				return fieldRep{}, nil, err
			}
			rep := staticRep(index, true)
			rep.value = value
			return rep, rest, nil
		}
		rep, err := relativeDynamicRep(index, base)
		if err != nil {
			return fieldRep{}, nil, err
		}
		rep.useTableValue = false
		value, rest, err := readFieldValue(rest)
		if err != nil {
			return fieldRep{}, nil, err
		}
		rep.value = value
		return rep, rest, nil

	case b&0xf0 == 0x10:
		index, rest, err := readVarInt(4, p)
		if err != nil {
			return fieldRep{}, nil, protocolError(err)
		}
		rep, err := postBaseDynamicRep(index, base)
		if err == nil {
			rep.useTableValue = true
		}
		return rep, rest, err

	case b&0xe0 == 0x20:
		name, rest, err := readPrefixedString(p, 3, b&0x08 != 0)
		if err != nil {
			return fieldRep{}, nil, err
		}
		value, rest, err := readFieldValue(rest)
		if err != nil {
			return fieldRep{}, nil, err
		}
		return fieldRep{name: name, value: value, nameType: nameLiteral}, rest, nil

	default:
		if b&0xf0 != 0 {
			return fieldRep{}, nil, fmt.Errorf("%w: unknown field line type %#x", ErrDecompressionFailed, b)
		}
		index, rest, err := readVarInt(3, p)
		if err != nil {
			return fieldRep{}, nil, protocolError(err)
		}
		rep, err := postBaseDynamicRep(index, base)
		if err != nil {
			return fieldRep{}, nil, err
		}
		value, rest, err := readFieldValue(rest)
		if err != nil {
			return fieldRep{}, nil, err
		}
		rep.value = value
		return rep, rest, nil
	}
}

func staticRep(index uint64, hasValue bool) fieldRep {
	field := staticTableEntries[index]
	rep := fieldRep{
		name:         field.Name,
		nameType:     nameStatic,
		dynamicIndex: index,
	}
	if !hasValue {
		rep.value = field.Value
		rep.useTableValue = true
	}
	return rep
}

func checkStaticIndex(index uint64) error {
	if index >= uint64(len(staticTableEntries)) {
		return fmt.Errorf("%w: static index %d", ErrInvalidIndex, index)
	}
	return nil
}

func relativeDynamicRep(index uint64, base int64) (fieldRep, error) {
	if index > math.MaxInt64 || base <= 0 || int64(index) >= base {
		return fieldRep{}, ErrInvalidIndex
	}
	absolute := uint64(base - int64(index) - 1)
	return fieldRep{nameType: nameDynamic, dynamicIndex: absolute, useTableValue: true}, nil
}

func postBaseDynamicRep(index uint64, base int64) (fieldRep, error) {
	if index > math.MaxInt64 || base < 0 {
		return fieldRep{}, ErrInvalidIndex
	}
	absolute := uint64(base + int64(index))
	return fieldRep{nameType: nameDynamic, dynamicIndex: absolute, postBase: true}, nil
}

func readFieldValue(p []byte) (string, []byte, error) {
	if len(p) == 0 {
		return "", nil, io.ErrUnexpectedEOF
	}
	return readPrefixedString(p, 7, p[0]&0x80 != 0)
}

func readPrefixedString(p []byte, n byte, usesHuffman bool) (string, []byte, error) {
	length, rest, err := readVarInt(n, p)
	if err != nil {
		return "", nil, protocolError(err)
	}
	if length > uint64(len(rest)) {
		return "", nil, io.ErrUnexpectedEOF
	}
	raw := rest[:length]
	if usesHuffman {
		value, err := hpack.HuffmanDecodeToString(raw)
		if err != nil {
			return "", nil, protocolError(err)
		}
		return value, rest[length:], nil
	}
	return string(raw), rest[length:], nil
}

func (d *DynamicDecoder) resolveReps(reps []fieldRep) ([]HeaderField, error) {
	fields := make([]HeaderField, 0, len(reps))
	for _, rep := range reps {
		switch rep.nameType {
		case nameLiteral:
			fields = append(fields, HeaderField{Name: rep.name, Value: rep.value})
		case nameStatic:
			fields = append(fields, HeaderField{Name: rep.name, Value: rep.value})
		case nameDynamic:
			entry, ok := d.entry(rep.dynamicIndex)
			if !ok {
				return nil, fmt.Errorf("%w: dynamic index %d", ErrInvalidIndex, rep.dynamicIndex)
			}
			value := rep.value
			if rep.useTableValue {
				value = entry.value
			}
			fields = append(fields, HeaderField{Name: entry.name, Value: value})
		}
	}
	return fields, nil
}

func (d *DynamicDecoder) entry(absolute uint64) (dynamicEntry, bool) {
	oldest := d.knownInsertCount - uint64(len(d.entries))
	if absolute < oldest || absolute >= d.knownInsertCount {
		return dynamicEntry{}, false
	}
	return d.entries[absolute-oldest], true
}

func (d *DynamicDecoder) processInstruction(p []byte) ([]byte, error) {
	b := p[0]
	switch {
	case b&0x80 != 0:
		return d.insertWithNameReference(p, b&0x40 != 0)
	case b&0xc0 == 0x40:
		return d.insertWithLiteralName(p)
	case b&0xe0 == 0x20:
		return d.setCapacity(p)
	default:
		return d.duplicate(p)
	}
}

func (d *DynamicDecoder) insertWithNameReference(p []byte, usesStatic bool) ([]byte, error) {
	index, rest, err := readVarInt(6, p)
	if err != nil {
		return p, protocolError(err)
	}
	var name string
	if usesStatic {
		if index >= uint64(len(staticTableEntries)) {
			return p, fmt.Errorf("%w: insert name static index %d", ErrInvalidIndex, index)
		}
		name = staticTableEntries[index].Name
	} else {
		entry, ok := d.relativeEntry(index)
		if !ok {
			return p, fmt.Errorf("%w: insert name dynamic index %d", ErrInvalidIndex, index)
		}
		name = entry.name
	}
	value, rest, err := readFieldValue(rest)
	if err != nil {
		return rest, err
	}
	if err := d.addEntry(dynamicEntry{name: name, value: value, size: entrySize(name, value)}); err != nil {
		return rest, err
	}
	return rest, nil
}

func (d *DynamicDecoder) insertWithLiteralName(p []byte) ([]byte, error) {
	name, rest, err := readPrefixedString(p, 4, p[0]&0x10 != 0)
	if err != nil {
		return rest, err
	}
	value, rest, err := readFieldValue(rest)
	if err != nil {
		return rest, err
	}
	if err := d.addEntry(dynamicEntry{name: name, value: value, size: entrySize(name, value)}); err != nil {
		return rest, err
	}
	return rest, nil
}

func (d *DynamicDecoder) setCapacity(p []byte) ([]byte, error) {
	capacity, rest, err := readVarInt(5, p)
	if err != nil {
		return p, protocolError(err)
	}
	if capacity > d.maxTableCapacity {
		return rest, fmt.Errorf("%w: requested %d, maximum %d", ErrInvalidTableCapacity, capacity, d.maxTableCapacity)
	}
	if err := d.applyCapacity(capacity); err != nil {
		return rest, err
	}
	return rest, nil
}

func (d *DynamicDecoder) duplicate(p []byte) ([]byte, error) {
	index, rest, err := readVarInt(5, p)
	if err != nil {
		return p, protocolError(err)
	}
	entry, ok := d.relativeEntry(index)
	if !ok {
		return p, fmt.Errorf("%w: duplicate relative index %d", ErrInvalidIndex, index)
	}
	entry.size = entrySize(entry.name, entry.value)
	if err := d.addEntry(entry); err != nil {
		return rest, err
	}
	return rest, nil
}

func entrySize(name, value string) uint64 {
	return uint64(len(name)) + uint64(len(value)) + 32
}

func (d *DynamicDecoder) relativeEntry(relative uint64) (dynamicEntry, bool) {
	if relative >= d.knownInsertCount {
		return dynamicEntry{}, false
	}
	return d.entry(d.knownInsertCount - relative - 1)
}

func (d *DynamicDecoder) addEntry(entry dynamicEntry) error {
	if entry.size > d.capacity {
		return fmt.Errorf("%w: entry size %d exceeds capacity %d", ErrInvalidTableCapacity, entry.size, d.capacity)
	}
	for d.totalSize+entry.size > d.capacity {
		if !d.canEvictOldest() {
			return fmt.Errorf("%w: cannot evict entry referenced by a blocked section", ErrInvalidIndex)
		}
		d.evictOldest()
	}
	d.entries = append(d.entries, entry)
	d.totalSize += entry.size
	d.knownInsertCount++
	return nil
}

func (d *DynamicDecoder) applyCapacity(capacity uint64) error {
	for d.totalSize > capacity {
		if !d.canEvictOldest() {
			return fmt.Errorf("%w: capacity %d evicts an entry referenced by a blocked section", ErrInvalidTableCapacity, capacity)
		}
		d.evictOldest()
	}
	d.capacity = capacity
	return nil
}

func (d *DynamicDecoder) canEvictOldest() bool {
	if len(d.entries) == 0 {
		return false
	}
	oldest := d.knownInsertCount - uint64(len(d.entries))
	for _, section := range d.blocked {
		if section.minimumIndex < section.required && section.minimumIndex == oldest {
			return false
		}
	}
	return true
}

func (d *DynamicDecoder) evictOldest() {
	d.totalSize -= d.entries[0].size
	d.entries = append(d.entries[:0], d.entries[1:]...)
}

func protocolError(err error) error {
	if err == nil || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrDecompressionFailed, err)
}

func appendSectionAcknowledgment(dst []byte, streamID uint64) []byte {
	start := len(dst)
	dst = appendVarInt(dst, 7, streamID)
	dst[start] |= 0x80
	return dst
}

func appendStreamCancellation(dst []byte, streamID uint64) []byte {
	start := len(dst)
	dst = appendVarInt(dst, 6, streamID)
	dst[start] |= 0x40
	return dst
}

func appendInsertCountIncrement(dst []byte, increment uint64) []byte {
	return appendVarInt(dst, 6, increment)
}
