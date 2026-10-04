package qpack

import (
	"bytes"
	"io"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/stretchr/testify/require"
)

// --- encoder stream instruction builders (fixed byte vectors) ---

func encSetCapacity(capacity uint64) []byte {
	buf := appendVarInt(nil, 5, capacity) // 001xxxxx
	buf[0] |= 0x20
	return buf
}

func encInsertStaticName(nameIndex uint64, value string) []byte {
	var buf []byte
	buf = appendVarInt(buf, 6, nameIndex)
	buf[0] |= 0xc0 // 1 T=1 xxxxxx
	buf = appendPlainString(buf, 7, value)
	return buf
}

func encInsertLiteralName(name, value string) []byte {
	var buf []byte
	buf = appendVarInt(buf, 5, uint64(len(name)))
	buf[0] |= 0x40 // 01 H=0 xxxxx
	buf = append(buf, name...)
	buf = appendPlainString(buf, 7, value)
	return buf
}

func encDuplicate(relativeIndex uint64) []byte {
	var buf []byte
	buf = appendVarInt(buf, 5, relativeIndex) // 000xxxxx
	return buf
}

func appendPlainString(dst []byte, prefix byte, s string) []byte {
	dst = appendVarInt(dst, prefix, uint64(len(s)))
	return append(dst, s...)
}

// --- field section builders ---

func encSection(ric, signDeltaBase uint64, body []byte) []byte {
	var buf []byte
	buf = appendVarInt(buf, 8, ric)
	baseStart := len(buf)
	buf = appendVarInt(buf, 7, signDeltaBase&0x7f)
	buf[baseStart] |= byte(signDeltaBase & 0x80)
	return append(buf, body...)
}

// encRelativeIndexed encodes an Indexed Field Line referencing dynamic table
// relative index (1 T=0 xxxxxx).
func encRelativeIndexed(relativeIndex uint64) []byte {
	buf := appendVarInt(nil, 6, relativeIndex)
	buf[0] |= 0x80
	return buf
}

// encStaticIndexed encodes an Indexed Field Line referencing static table
// index (1 T=1 xxxxxx).
func encStaticIndexed(index uint64) []byte {
	buf := appendVarInt(nil, 6, index)
	buf[0] |= 0xc0
	return buf
}

// encPostBaseIndexed encodes an Indexed Field Line With Post-Base Index
// (0001xxxx).
func encPostBaseIndexed(postBaseIndex uint64) []byte {
	buf := appendVarInt(nil, 4, postBaseIndex)
	buf[0] |= 0x10
	return buf
}

// encRelativeNameLiteral encodes a Literal Field Line With Name Reference to a
// dynamic entry (01 N=0 T=0 xxxx).
func encRelativeNameLiteral(relativeNameIndex uint64, value string) []byte {
	var buf []byte
	buf = appendVarInt(buf, 4, relativeNameIndex)
	buf[0] |= 0x40
	buf = appendPlainString(buf, 7, value)
	return buf
}

// encPostBaseNameLiteral encodes a Literal Field Line With Post-Base Name
// Reference (0000 H=0 xxx).
func encPostBaseNameLiteral(postBaseNameIndex uint64, value string) []byte {
	var buf []byte
	buf = appendVarInt(buf, 3, postBaseNameIndex)
	buf = appendPlainString(buf, 7, value)
	return buf
}

func encLiteralNameValue(name, value string) []byte {
	var buf []byte
	buf = appendVarInt(buf, 4, uint64(len(name)))
	buf[0] |= 0x20 // 001 N=0 H=0 0000
	buf = append(buf, name...)
	buf = appendPlainString(buf, 7, value)
	return buf
}

// --- tests ---

// feedOneByteAtATime splits the encoder stream instructions into individual
// bytes and verifies that the decoder assembles them correctly.
func TestDynamicDecoderEncoderInstructionsByteByByte(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)

	instructions := [][]byte{
		encSetCapacity(4096),
		encInsertLiteralName("foo", "bar"),
		encInsertStaticName(1, "/index.html"), // static table entry 1 is ":path"
		encDuplicate(0),                       // duplicate the newest entry (:path)
	}

	var allFeedback []byte
	var allSections []DecodedSection
	for _, instruction := range instructions {
		for _, b := range instruction {
			feedback, sections, err := d.FeedEncoderStream([]byte{b})
			require.NoError(t, err)
			allFeedback = append(allFeedback, feedback...)
			allSections = append(allSections, sections...)
		}
	}
	require.Empty(t, allSections)
	require.Equal(t, 3, d.KnownInsertCount())
	// A single Insert Count Increment of 1 per inserting instruction.
	require.Equal(t, []byte{0x01, 0x01, 0x01}, allFeedback)

	// Now send a field section that references all three entries.
	// Relative indices: 0 -> newest (duplicated :path), 1 -> first :path,
	// 2 -> foo. Base = 3 (ric=3, sign bit 1, delta 0).
	body := bytes.Join([][]byte{
		encRelativeIndexed(0),
		encRelativeIndexed(1),
		encRelativeIndexed(2),
	}, nil)
	section := encSection(3, 0x80, body)
	fields, feedback, err := d.FeedFieldSection(0, section)
	require.NoError(t, err)
	require.Equal(t, []HeaderField{
		{Name: ":path", Value: "/index.html"},
		{Name: ":path", Value: "/index.html"},
		{Name: "foo", Value: "bar"},
	}, fields)
	// Section Acknowledgment for stream 0: type 1, 7-bit prefix: 0x80.
	require.Equal(t, []byte{0x80}, feedback)
}

// TestDynamicDecoderReverseArrival delivers two field sections before the
// encoder stream instructions, on two different streams. Each section must be
// delivered exactly once, in insertion-satisfiable order.
func TestDynamicDecoderReverseArrival(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	// Stream 4: ric=2, sign=1, delta=2 -> base=0, post-base index 1 -> absolute 1.
	section4 := encSection(2, 0x80|2, encPostBaseIndexed(1))
	// Stream 8: ric=3, sign=1, delta=3 -> base=0, post-base index 2 -> absolute 2.
	section8 := encSection(3, 0x80|3, encPostBaseIndexed(2))

	fields4, feedback, err := d.FeedFieldSection(4, section4)
	require.NoError(t, err)
	require.Nil(t, fields4)
	require.Nil(t, feedback)
	require.Equal(t, 1, d.BlockedStreams())

	fields8, feedback, err := d.FeedFieldSection(8, section8)
	require.NoError(t, err)
	require.Nil(t, fields8)
	require.Nil(t, feedback)
	require.Equal(t, 2, d.BlockedStreams())

	// First insert (absolute index 0) satisfies neither section.
	feedback, sections, err := d.FeedEncoderStream(encInsertLiteralName("name1", "value1"))
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Equal(t, []byte{0x01}, feedback)

	// Second insert (absolute index 1) releases stream 4.
	feedback, sections, err = d.FeedEncoderStream(encInsertLiteralName("name2", "value2"))
	require.NoError(t, err)
	require.Equal(t, []DecodedSection{
		{StreamID: 4, HeaderFields: []HeaderField{{Name: "name2", Value: "value2"}}},
	}, sections)
	require.Equal(t, []byte{0x01, 0x84}, feedback)

	// Third insert (absolute index 2) releases stream 8.
	feedback, sections, err = d.FeedEncoderStream(encInsertLiteralName("name3", "value3"))
	require.NoError(t, err)
	require.Equal(t, []DecodedSection{
		{StreamID: 8, HeaderFields: []HeaderField{{Name: "name3", Value: "value3"}}},
	}, sections)
	require.Equal(t, 0, d.BlockedStreams())
	require.Equal(t, []byte{0x01, 0x88}, feedback)

	// Feeding the sections again is not a thing (they were already consumed),
	// but verify no section is delivered twice on further encoder input.
	feedback, sections, err = d.FeedEncoderStream(nil)
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Empty(t, feedback)
}

// setCapacityForTest applies a Set Dynamic Table Capacity instruction.
func (d *DynamicDecoder) setCapacityForTest(capacity int) error {
	_, _, err := d.FeedEncoderStream(encSetCapacity(uint64(capacity)))
	return err
}

// TestDynamicDecoderPostBaseNameReference exercises the With Post-Base Name
// Reference representation and static references in a blocked section.
func TestDynamicDecoderPostBaseNameReference(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	// ric=1, sign=1, delta=1 -> base=0.
	// Post-base name reference 0 -> absolute index 0, literal value.
	// Plus a static indexed reference (:method GET, index 17).
	body := bytes.Join([][]byte{
		encPostBaseNameLiteral(0, "custom-value"),
		encStaticIndexed(17),
	}, nil)
	section := encSection(1, 0x80|1, body)

	fields, _, err := d.FeedFieldSection(12, section)
	require.NoError(t, err)
	require.Nil(t, fields)

	feedback, sections, err := d.FeedEncoderStream(encInsertLiteralName("custom-name", "ignored-by-section"))
	require.NoError(t, err)
	require.Equal(t, []DecodedSection{{
		StreamID: 12,
		HeaderFields: []HeaderField{
			{Name: "custom-name", Value: "custom-value"},
			{Name: ":method", Value: "GET"},
		},
	}}, sections)
	require.Equal(t, []byte{0x01, 0x8c}, feedback)
}

// TestDynamicDecoderRelativeNameReferenceOnInsert verifies that an Insert With
// Name Reference referencing the dynamic table resolves a relative index.
func TestDynamicDecoderInsertWithDynamicNameReference(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	_, _, err := d.FeedEncoderStream(encInsertLiteralName("foo", "bar"))
	require.NoError(t, err)

	// Insert With Name Reference, T=0, relative index 0 (the "foo" entry),
	// value "baz": 1 T=0 000000 then value string.
	ref := []byte{0x80}
	ref = appendPlainString(ref, 7, "baz")
	feedback, sections, err := d.FeedEncoderStream(ref)
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Equal(t, []byte{0x01}, feedback)
	require.Equal(t, 2, d.KnownInsertCount())

	section := encSection(2, 0x80, encRelativeNameLiteral(0, "qux"))
	fields, secFeedback, err := d.FeedFieldSection(0, section)
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "foo", Value: "qux"}}, fields)
	require.Equal(t, []byte{0x80}, secFeedback)
}

// TestDynamicDecoderCapacityShrink verifies that shrinking the table capacity
// evicts the oldest entries and that references to evicted entries are
// detected as protocol errors.
func TestDynamicDecoderCapacityShrink(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(256))

	// Three empty entries (size 32 each): all fit in capacity 256.
	for range 3 {
		_, _, err := d.FeedEncoderStream(encInsertLiteralName("", ""))
		require.NoError(t, err)
	}
	require.Equal(t, 3, d.residentCountForTest())

	// An empty field section referencing relative index 2 (absolute 0, base=3).
	section0 := encSection(3, 0x80, encRelativeIndexed(2))
	fields, _, err := d.FeedFieldSection(0, section0)
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "", Value: ""}}, fields)

	// Shrink to 64: only the two newest entries survive. The oldest (absolute
	// index 0) is evicted.
	_, _, err = d.FeedEncoderStream(encSetCapacity(64))
	require.NoError(t, err)
	require.Equal(t, 2, d.residentCountForTest())

	// A section referencing the evicted entry is an invalid index error.
	_, _, err = d.FeedFieldSection(0, section0)
	require.ErrorIs(t, err, ErrInvalidIndex)
	require.ErrorIs(t, err, ErrDecompressionFailed)

	// Shrinking beyond the negotiated maximum is an invalid capacity error.
	_, _, err = d.FeedEncoderStream(encSetCapacity(4097))
	require.ErrorIs(t, err, ErrInvalidTableCapacity)
}

func (d *DynamicDecoder) residentCountForTest() int { return d.resident }

// TestDynamicDecoderRequiredInsertCountWraparound exercises the wrap-around
// encoding of the Required Insert Count near a power-of-two MaxValue boundary.
func TestDynamicDecoderWraparound(t *testing.T) {
	const maxCap = 128 // MaxEntries = 4, MaxValue = 8
	d := NewDynamicDecoder(maxCap, 4)
	require.NoError(t, d.setCapacityForTest(maxCap))

	// Insert 8 empty entries, in two groups, to reach known insert count 8.
	insertEmpty := func(n int) {
		t.Helper()
		for range n {
			_, _, err := d.FeedEncoderStream(encInsertLiteralName("", ""))
			require.NoError(t, err)
		}
	}
	insertEmpty(8)
	require.Equal(t, 8, d.KnownInsertCount())

	// ric=8 at full=8: rse is 8 (in this window, 0 would mean zero inserts).
	section := encSection(8, 0x80, encRelativeIndexed(0)) // sign=1, delta=0, base=8
	fields, _, err := d.FeedFieldSection(0, section)
	require.NoError(t, err)
	require.Len(t, fields, 1)

	// Blocked section with ric=10 at full=8 (rse=2, wraps into the next
	// window). It is blocked initially, then satisfied by two more inserts.
	// sign=1, delta=10 -> base=0; post-base index 9 -> absolute index 9.
	blocked := encSection(2, 0x80|10, encPostBaseIndexed(9)) // absolute index 9

	fields, _, err = d.FeedFieldSection(4, blocked)
	require.NoError(t, err)
	require.Nil(t, fields)
	require.Equal(t, 1, d.BlockedStreams())

	insertEmpty(2)
	require.Equal(t, 10, d.KnownInsertCount())
	require.Equal(t, 0, d.BlockedStreams())
}

// TestDynamicDecoderCancelThenInsert makes sure an application cancel removes
// the blocked section without being treated as a connection error and emits a
// Stream Cancellation; subsequent inserts do not resurrect the section.
func TestDynamicDecoderCancelThenInsert(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	section := encSection(1, 0x80|1, encPostBaseIndexed(0))
	fields, feedback, err := d.FeedFieldSection(100, section)
	require.NoError(t, err)
	require.Nil(t, fields)
	require.Nil(t, feedback)

	// Stream Cancellation: type 1 (01) with 6-bit prefix, stream ID 100:
	// first byte 0x3f|0x40 = 0x7f, continuation 100-63.
	cancelFeedback := d.CancelStream(100)
	require.Equal(t, []byte{0x7f, 100 - 63}, cancelFeedback)
	require.Equal(t, 0, d.BlockedStreams())

	// Canceling an unknown stream is a no-op and not an error.
	require.Nil(t, d.CancelStream(100))
	require.Nil(t, d.CancelStream(999))

	// The insert must not deliver the canceled section.
	feedback, sections, err := d.FeedEncoderStream(encInsertLiteralName("foo", "bar"))
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Equal(t, []byte{0x01}, feedback)
}

// TestDynamicDecoderBoundedBlockedStreams checks that exceeding the advertised
// blocked streams limit is reported as a distinct protocol error.
func TestDynamicDecoderBoundedBlockedStreams(t *testing.T) {
	d := NewDynamicDecoder(4096, 1)
	require.NoError(t, d.setCapacityForTest(4096))

	section := encSection(1, 0x80|1, encPostBaseIndexed(0))
	_, _, err := d.FeedFieldSection(0, section)
	require.NoError(t, err)
	require.Equal(t, 1, d.BlockedStreams())

	_, _, err = d.FeedFieldSection(4, section)
	require.ErrorIs(t, err, ErrTooManyBlockedStreams)
	require.ErrorIs(t, err, ErrDecompressionFailed)

	// With no blocked streams allowed, any blocking is rejected.
	d2 := NewDynamicDecoder(4096, 0)
	require.NoError(t, d2.setCapacityForTest(4096))
	_, _, err = d2.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrTooManyBlockedStreams)
}

func TestDynamicDecoderInvalidIndexErrors(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	// Insert With Name Reference to a non-existent static table index.
	bad := encInsertStaticName(uint64(len(staticTableEntries)+10), "x")
	_, _, err := d.FeedEncoderStream(bad)
	require.ErrorIs(t, err, ErrInvalidIndex)

	// Field section referencing a static table index that doesn't exist.
	body := encStaticIndexed(uint64(len(staticTableEntries) + 5))
	section := encSection(0, 0, body)
	_, _, err = d.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrInvalidIndex)

	// Relative reference into an empty dynamic table.
	section = encSection(0, 0x80, encRelativeIndexed(0))
	_, _, err = d.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrInvalidIndex)

	// Duplicate of a non-existent relative index.
	_, _, err = d.FeedEncoderStream(encDuplicate(0))
	require.ErrorIs(t, err, ErrInvalidIndex)
}

func TestDynamicDecoderInvalidBaseAndRIC(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	// sign=0, delta=1: base = ric+1 = 1 > ric -> invalid base.
	section := encSection(1, 1, encPostBaseIndexed(0))
	_, _, err := d.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrInvalidBase)

	// sign=1, delta=ric+1 -> negative base.
	section = encSection(2, 0x80|3, nil)
	_, _, err = d.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrInvalidBase)

	// Invalid Required Insert Count wire value (larger than 2*MaxEntries-1=255).
	section = encSection(300, 0, nil)
	_, _, err = d.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrInvalidRequiredInsertCount)

	// A non-zero RIC is illegal when the dynamic table can hold no entries.
	d0 := NewDynamicDecoder(16, 0)
	section = encSection(1, 0x80|1, nil)
	_, _, err = d0.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrInvalidRequiredInsertCount)
}

func TestDynamicDecoderBlockedSectionEvicted(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(256))

	// Blocked section requires ric=8, base=8, relative index 7 -> absolute 0.
	section := encSection(8, 0x80, encRelativeIndexed(7))
	fields, _, err := d.FeedFieldSection(4, section)
	require.NoError(t, err)
	require.Nil(t, fields)

	// Seven inserts leave known insert count at 7 (still blocked) and keep
	// absolute index 0 resident.
	for range 7 {
		_, _, err := d.FeedEncoderStream(encInsertLiteralName("", ""))
		if err != nil {
			t.Fatalf("unexpected insert error: %v", err)
		}
	}
	require.Equal(t, 1, d.BlockedStreams())

	// Shrink to 32: only the newest entry survives; absolute index 0 is
	// evicted, but the section is still blocked (ric=8 > known insert count 7).
	_, _, err = d.FeedEncoderStream(encSetCapacity(32))
	require.NoError(t, err)
	require.Equal(t, 1, d.BlockedStreams())

	// The 8th insert satisfies ric=8, but relative index 7 (absolute 0) was
	// evicted: a protocol error surfaces while releasing the section.
	_, _, err = d.FeedEncoderStream(encInsertLiteralName("", ""))
	require.ErrorIs(t, err, ErrInvalidIndex)
}

func TestDynamicDecoderTruncatedInstruction(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)

	instruction := encSetCapacity(4000) // multi-byte varint, <= negotiated 4096
	// Feed all but the last byte: nothing is applied, no error.
	feedback, sections, err := d.FeedEncoderStream(instruction[:len(instruction)-1])
	require.NoError(t, err)
	require.Empty(t, feedback)
	require.Empty(t, sections)

	// Deliver the remaining byte: capacity is now applied.
	feedback, _, err = d.FeedEncoderStream(instruction[len(instruction)-1:])
	require.NoError(t, err)
	require.Empty(t, feedback)

	// A completely empty buffer is harmless.
	_, _, err = d.FeedEncoderStream(nil)
	require.NoError(t, err)
}

// TestDynamicDecoderImmediateSection ensures that sections referencing only
// already-available entries are delivered immediately with an ack, including
// literal fields without name references.
func TestDynamicDecoderImmediateSection(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)

	body := bytes.Join([][]byte{
		encStaticIndexed(17),
		encLiteralNameValue("x-custom", "value"),
	}, nil)
	section := encSection(0, 0, body)
	fields, feedback, err := d.FeedFieldSection(200, section)
	require.NoError(t, err)
	require.Equal(t, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: "x-custom", Value: "value"},
	}, fields)
	// Section Acknowledgment with stream ID 200 (type 1, 7-bit prefix):
	// 0x80|0x7f = 0xff, continuation 200-127.
	require.Equal(t, []byte{0xff, 200 - 127}, feedback)
}

func TestLegacyDecoderStillStateless(t *testing.T) {
	// The old stateless API must keep working.
	data := insertPrefix(encStaticIndexed(17))
	decode := NewDecoder().Decode(data)
	hf, err := decode()
	require.NoError(t, err)
	require.Equal(t, HeaderField{Name: ":method", Value: "GET"}, hf)
	_, err = decode()
	require.ErrorIs(t, err, io.EOF)
}

// TestDynamicDecoderHuffmanValues feeds a Huffman-encoded value in an encoder
// stream instruction and a Huffman-encoded literal name in a field section.
func TestDynamicDecoderHuffmanValues(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	// Insert With Literal Name: value uses Huffman encoding.
	insert := []byte{
		0x40 | byte(len("huff-name")), // 01 H=0 + 5-bit name length
	}
	insert = append(insert, "huff-name"...)
	encodedValue := hpack.AppendHuffmanString(nil, "huff-value")
	valueLen := appendVarInt(nil, 7, uint64(len(encodedValue)))
	valueLen[0] |= 0x80
	insert = append(insert, valueLen...)
	insert = append(insert, encodedValue...)

	feedback, _, err := d.FeedEncoderStream(insert)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, feedback)

	// Field section: literal with Huffman-encoded name and plain value.
	encodedName := hpack.AppendHuffmanString(nil, "custom")
	body := []byte{0x20 | 0x04 | byte(len(encodedName))} // 001 N=0 H=1 + length
	body = append(body, encodedName...)
	body = appendPlainString(body, 7, "plain")

	fields, secFeedback, err := d.FeedFieldSection(0, encSection(0, 0, body))
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "custom", Value: "plain"}}, fields)
	require.Equal(t, []byte{0x80}, secFeedback)

	// And the Huffman value inserted via the encoder stream resolves correctly.
	fields, _, err = d.FeedFieldSection(4, encSection(1, 0x80, encRelativeIndexed(0)))
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "huff-name", Value: "huff-value"}}, fields)
}

// TestDynamicDecoderDuplicate verifies that Duplicate copies an existing
// (possibly not newest) entry and bumps the insert count.
func TestDynamicDecoderDuplicate(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	require.NoError(t, d.setCapacityForTest(4096))

	instructions := bytes.Join([][]byte{
		encInsertLiteralName("a", "1"),
		encInsertLiteralName("b", "2"),
		encDuplicate(1), // duplicate relative index 1 = the older entry "a:1"
	}, nil)
	feedback, sections, err := d.FeedEncoderStream(instructions)
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Equal(t, []byte{0x03}, feedback)

	fields, _, err := d.FeedFieldSection(0, encSection(3, 0x80, encRelativeIndexed(0)))
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "a", Value: "1"}}, fields)
}
