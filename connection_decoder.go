package qpack

import (
	"errors"
	"fmt"
	"io"
)

// DecodedFieldSection is a field section that has become decodable, together
// with the ID of the request stream it arrived on.
type DecodedFieldSection struct {
	// StreamID is the ID of the request stream the field section was received on.
	StreamID uint64
	// Fields are the decoded header fields, in order.
	Fields []HeaderField
}

// A ConnectionDecoder is a connection-scoped QPACK decoder (RFC 9204).
// It consumes bytes from the unidirectional encoder stream and encoded field
// sections from request streams, and produces bytes for the unidirectional
// decoder stream (Section Acknowledgment, Stream Cancellation and Insert
// Count Increment instructions) as well as decoded field sections.
//
// Field sections that reference dynamic table entries that have not yet been
// inserted are placed in a bounded waiting area, and are delivered once the
// referenced entries become available.
//
// A ConnectionDecoder is not safe for concurrent use.
// It does not perform any network I/O and has no dependencies on a QUIC
// transport implementation.
type ConnectionDecoder struct {
	maxTableCapacity  uint64
	maxBlockedStreams uint64

	table dynamicTable

	// pending holds blocked field sections in arrival order.
	pending []*blockedSection
	// pendingByStream tracks the at most one blocked section per stream.
	pendingByStream map[uint64]*blockedSection

	// ready holds sections that became deliverable, not yet returned.
	ready []DecodedFieldSection
	// feedback accumulates decoder stream bytes not yet returned.
	feedback []byte

	// encoderBuf holds the trailing bytes of an incomplete instruction.
	encoderBuf []byte

	// insertCountReported is the last insert count reported via Insert Count
	// Increment.
	insertCountReported uint64

	fatal error
}

// NewConnectionDecoder returns a new connection-scoped QPACK decoder.
// maxTableCapacity is the value advertised via
// SETTINGS_QPACK_MAX_TABLE_CAPACITY; maxBlockedStreams is the value advertised
// via SETTINGS_QPACK_BLOCKED_STREAMS.
func NewConnectionDecoder(maxTableCapacity, maxBlockedStreams uint64) *ConnectionDecoder {
	return &ConnectionDecoder{
		maxTableCapacity:  maxTableCapacity,
		maxBlockedStreams: maxBlockedStreams,
		pendingByStream:   make(map[uint64]*blockedSection),
	}
}

type fieldKind uint8

const (
	fieldLiteral fieldKind = iota
	fieldStaticIndex
	fieldStaticName
	fieldDynamic
	fieldDynamicName
)

type preparedField struct {
	kind  fieldKind
	index uint64
	name  string
	value string
}

type blockedSection struct {
	streamID uint64
	// raw is the complete, unparsed field section. It is re-parsed once the
	// required entries have arrived, at which point the correct RIC wrapping
	// is known.
	raw []byte
	// minIndex is the smallest dynamic table absolute index referenced.
	minIndex uint64
	// needCount is one past the largest dynamic table absolute index
	// referenced.
	needCount uint64
}

// FeedEncoderStream processes bytes received on the encoder stream.
// It executes all complete Set Dynamic Table Capacity, Insert With Name
// Reference, Insert With Literal Name and Duplicate instructions contained in
// p. Trailing bytes of an incomplete instruction are buffered until more data
// arrives.
//
// Insert Count Increment instructions, and Section Acknowledgments for field
// sections that became deliverable, are returned as decoder stream bytes.
// Field sections that became deliverable are returned as well.
func (d *ConnectionDecoder) FeedEncoderStream(p []byte) (decoderStream []byte, delivered []DecodedFieldSection, err error) {
	if d.fatal != nil {
		return nil, nil, d.fatal
	}

	d.encoderBuf = append(d.encoderBuf, p...)
	buf := d.encoderBuf
	consumed := 0
	for len(buf) > 0 {
		n, perr := d.processEncoderInstruction(buf)
		if perr != nil {
			if errors.Is(perr, io.ErrUnexpectedEOF) {
				break
			}
			d.fatal = perr
			return nil, nil, perr
		}
		buf = buf[n:]
		consumed += n
	}
	if consumed > 0 {
		d.encoderBuf = append(d.encoderBuf[:0], buf...)
	}

	d.emitInsertCountIncrement()
	d.flushPending()

	return d.takeFeedback(), d.takeReady(), d.fatal
}

// FeedFieldSection processes an encoded field section received on the request
// stream with the given stream ID.
//
// If all referenced dynamic table entries are already present, the decoded
// section is returned immediately (with its Section Acknowledgment).
// Otherwise the section is held in the bounded waiting area until the
// referenced entries arrive; it is then returned from FeedEncoderStream.
// Every field section is delivered at most once.
func (d *ConnectionDecoder) FeedFieldSection(streamID uint64, p []byte) (decoderStream []byte, delivered []DecodedFieldSection, err error) {
	if d.fatal != nil {
		return nil, nil, d.fatal
	}

	parsed, perr := d.parseFieldSection(p)
	if perr != nil && !errors.Is(perr, errSectionBlocked) {
		d.fatal = perr
		return nil, nil, perr
	}

	if perr == nil {
		d.deliverParsed(streamID, parsed)
		return d.takeFeedback(), d.takeReady(), nil
	}

	// The section references inserts that have not arrived yet. Determine the
	// required insert count and the referenced index range from the parsed
	// field lines.
	needCount, minIndex := parsed.requiredInserts()
	if needCount == 0 {
		// parseFieldSection reported blocked without dynamic references; this
		// cannot happen, but be defensive.
		d.fatal = errSectionBlocked
		return nil, nil, errSectionBlocked
	}

	if d.pendingByStream[streamID] != nil {
		err := fmt.Errorf("stream %d: field section while another one is still pending: %w", streamID, ErrDecompressionFailed)
		d.fatal = err
		return nil, nil, err
	}
	if uint64(len(d.pending)) >= d.maxBlockedStreams {
		err := fmt.Errorf("stream %d: %w", streamID, ErrBlockedStreamsExceeded)
		d.fatal = err
		return nil, nil, err
	}

	raw := append([]byte(nil), p...)
	sec := &blockedSection{
		streamID:  streamID,
		raw:       raw,
		minIndex:  minIndex,
		needCount: needCount,
	}
	d.pending = append(d.pending, sec)
	d.pendingByStream[streamID] = sec
	return nil, nil, nil
}

// CancelStream reports that the request stream with the given stream ID was
// cancelled by the application before its field section was acknowledged.
// A still-waiting section is discarded and a Stream Cancellation instruction
// is emitted. This is an application-level event and never causes the
// connection to fail.
func (d *ConnectionDecoder) CancelStream(streamID uint64) []byte {
	sec := d.pendingByStream[streamID]
	if sec == nil {
		return d.takeFeedback()
	}
	delete(d.pendingByStream, streamID)
	for i, s := range d.pending {
		if s == sec {
			d.pending = append(d.pending[:i], d.pending[i+1:]...)
			break
		}
	}
	off := len(d.feedback)
	d.feedback = appendVarInt(d.feedback, 6, streamID)
	d.feedback[off] ^= 0x40 // 01xxxxxx: Stream Cancellation
	return d.takeFeedback()
}

// flushPending handles waiting sections in arrival order. A section whose
// required entries have been inserted is re-parsed and delivered; if any
// referenced entry was evicted in the meantime, that is a connection error
// and no later section is delivered past it.
func (d *ConnectionDecoder) flushPending() {
	for len(d.pending) > 0 {
		sec := d.pending[0]
		if sec.needCount > d.table.knownReceivedCount {
			return
		}
		if sec.minIndex < d.table.smallestAbsoluteIndex {
			err := fmt.Errorf("stream %d: referenced entry evicted: %w", sec.streamID, InvalidIndexError{Index: sec.minIndex, Dynamic: true})
			d.fatal = err
			return
		}
		parsed, err := d.parseFieldSection(sec.raw)
		if err != nil {
			d.fatal = err
			return
		}
		d.deliverParsed(sec.streamID, parsed)
		d.pending = d.pending[1:]
		delete(d.pendingByStream, sec.streamID)
	}
}

func (d *ConnectionDecoder) deliverParsed(streamID uint64, sec parsedSection) {
	fields := make([]HeaderField, 0, len(sec.fields))
	for _, f := range sec.fields {
		switch f.kind {
		case fieldLiteral:
			fields = append(fields, HeaderField{Name: f.name, Value: f.value})
		case fieldStaticIndex:
			fields = append(fields, staticTableEntries[f.index])
		case fieldStaticName:
			hf := staticTableEntries[f.index]
			hf.Value = f.value
			fields = append(fields, hf)
		case fieldDynamic:
			e, _ := d.table.at(f.index)
			fields = append(fields, HeaderField{Name: e.Name, Value: e.Value})
		case fieldDynamicName:
			e, _ := d.table.at(f.index)
			fields = append(fields, HeaderField{Name: e.Name, Value: f.value})
		}
	}
	d.ready = append(d.ready, DecodedFieldSection{StreamID: streamID, Fields: fields})
	off := len(d.feedback)
	d.feedback = appendVarInt(d.feedback, 6, streamID)
	d.feedback[off] ^= 0x80 // 1xxxxxxx: Section Acknowledgment
}

func (d *ConnectionDecoder) emitInsertCountIncrement() {
	count := d.table.knownReceivedCount
	if count == d.insertCountReported {
		return
	}
	d.feedback = appendVarInt(d.feedback, 6, count-d.insertCountReported) // 00xxxxxx
	d.insertCountReported = count
}

func (d *ConnectionDecoder) takeReady() []DecodedFieldSection {
	if len(d.ready) == 0 {
		return nil
	}
	r := d.ready
	d.ready = nil
	return r
}

func (d *ConnectionDecoder) takeFeedback() []byte {
	if len(d.feedback) == 0 {
		return nil
	}
	b := d.feedback
	d.feedback = nil
	return b
}
