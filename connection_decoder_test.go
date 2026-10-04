package qpack

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- fixed byte vector builders -------------------------------------------

func encCapacity(capacity uint64) []byte {
	b := appendVarInt(nil, 4, capacity)
	b[0] ^= 0x20 // 0010xxxx
	return b
}

func encInsertLiteralName(name, value string) []byte {
	b := appendVarInt(nil, 5, uint64(len(name)))
	b[0] ^= 0x40 // 010xxxxx
	b = append(b, name...)
	b = appendVarInt(b, 7, uint64(len(value)))
	return append(b, value...)
}

func encInsertStaticName(staticIndex uint64, value string) []byte {
	b := appendVarInt(nil, 6, staticIndex)
	b[0] ^= 0xc0 // 11xxxxxx: T=1
	b = appendVarInt(b, 7, uint64(len(value)))
	return append(b, value...)
}

func encInsertDynamicName(relativeIndex uint64, value string) []byte {
	b := appendVarInt(nil, 6, relativeIndex)
	b[0] ^= 0x80 // 10xxxxxx: T=0
	b = appendVarInt(b, 7, uint64(len(value)))
	return append(b, value...)
}

func encDuplicate(relativeIndex uint64) []byte {
	// 000xxxxx, 5-bit prefix
	return appendVarInt(nil, 5, relativeIndex)
}

// encRIC encodes the Required Insert Count per RFC 9204, Section 4.5.1.1.
func encRIC(requiredInsertCount, maxEntries uint64) []byte {
	if requiredInsertCount == 0 {
		return appendVarInt(nil, 8, 0)
	}
	fullRange := 2 * maxEntries
	if fullRange == 0 {
		fullRange = 1
	}
	encoded := (requiredInsertCount-1)%fullRange + 1
	return appendVarInt(nil, 8, encoded)
}

// encSectionPrefix writes RIC and Base Delta (sign = 0, base = ric + delta).
func encSectionPrefix(requiredInsertCount, maxEntries, baseDelta uint64) []byte {
	b := encRIC(requiredInsertCount, maxEntries)
	return appendVarInt(b, 7, baseDelta)
}

// encSectionPrefixSigned writes RIC and signed Base Delta (base = ric - delta - 1).
func encSectionPrefixSigned(requiredInsertCount, maxEntries, baseDelta uint64) []byte {
	b := encRIC(requiredInsertCount, maxEntries)
	off := len(b)
	b = appendVarInt(b, 7, baseDelta)
	b[off] ^= 0x80
	return b
}

func encDynamicIndexed(relativeIndex uint64) []byte {
	// 10xxxxxx: varint prefix already starts at 10 when the value < 63.
	b := appendVarInt(nil, 6, relativeIndex)
	b[0] ^= 0x80
	return b
}

func encPostBaseIndexed(postBaseIndex uint64) []byte {
	// 0000xxxx
	b := appendVarInt(nil, 4, postBaseIndex)
	return b
}

func encStaticIndexed(staticIndex uint64) []byte {
	b := appendVarInt(nil, 6, staticIndex)
	b[0] ^= 0xc0
	return b
}

func encDynamicNameLiteral(relativeIndex uint64, value string) []byte {
	// 0100xxxx: N=0, T=0
	b := appendVarInt(nil, 4, relativeIndex)
	b[0] |= 0x40
	b = appendVarInt(b, 7, uint64(len(value)))
	return append(b, value...)
}

func encPostBaseNameLiteral(postBaseIndex uint64, value string) []byte {
	// 0001xxxx
	b := appendVarInt(nil, 4, postBaseIndex)
	b[0] |= 0x10
	b = appendVarInt(b, 7, uint64(len(value)))
	return append(b, value...)
}

func encStaticNameLiteral(staticIndex uint64, value string) []byte {
	// 0101xxxx: N=0, T=1
	b := appendVarInt(nil, 4, staticIndex)
	b[0] |= 0x50
	b = appendVarInt(b, 7, uint64(len(value)))
	return append(b, value...)
}

func encLiteral(name, value string) []byte {
	b := appendVarInt(nil, 3, uint64(len(name)))
	b[0] |= 0x20
	b = append(b, name...)
	b = appendVarInt(b, 7, uint64(len(value)))
	return append(b, value...)
}

func mustFeedEnc(t *testing.T, d *ConnectionDecoder, p []byte) ([]byte, []DecodedFieldSection) {
	t.Helper()
	fb, delivered, err := d.FeedEncoderStream(p)
	require.NoError(t, err)
	return fb, delivered
}

func parseFeedback(t *testing.T, p []byte) []struct {
	kind  string
	value uint64
} {
	t.Helper()
	var out []struct {
		kind  string
		value uint64
	}
	for len(p) > 0 {
		b := p[0]
		switch {
		case b&0x80 > 0:
			v, rest, err := readVarInt(6, p)
			require.NoError(t, err)
			out = append(out, struct {
				kind  string
				value uint64
			}{"ack", v})
			p = rest
		case b&0xc0 == 0x40:
			v, rest, err := readVarInt(6, p)
			require.NoError(t, err)
			out = append(out, struct {
				kind  string
				value uint64
			}{"cancel", v})
			p = rest
		default:
			v, rest, err := readVarInt(6, p)
			require.NoError(t, err)
			out = append(out, struct {
				kind  string
				value uint64
			}{"increment", v})
			p = rest
		}
	}
	return out
}

// --- tests ----------------------------------------------------------------

func TestConnectionDecoderEncoderInstructionsByteByByte(t *testing.T) {
	// Fixed vector:
	//   0x3e 0x80 -> Set Dynamic Table Capacity(128)
	//   0x43 'b' 'a' 'r' 0x03 'f' 'o' 'o'
	//     -> Insert With Literal Name, name "bar", value "foo"
	//   0x00 -> Duplicate(0)
	//   0xd8 0x05 'h' 'e' 'l' 'l' 'o'
	//     -> Insert With Name Reference (static index 24, ":scheme"), value "hello"
	instructions := [][]byte{
		encCapacity(128),
		encInsertLiteralName("bar", "foo"),
		encDuplicate(0),
		encInsertStaticName(24, "hello"),
	}
	var all []byte
	for _, ins := range instructions {
		all = append(all, ins...)
	}

	d := NewConnectionDecoder(128, 4)

	// Feed the entire byte stream one byte at a time. No instruction may be
	// executed until all its bytes have arrived.
	var feedback []byte
	for i, b := range all {
		fb, delivered, err := d.FeedEncoderStream([]byte{b})
		require.NoError(t, err, "byte %d", i)
		require.Empty(t, delivered)
		feedback = append(feedback, fb...)
	}

	require.Equal(t, uint64(3), d.table.knownReceivedCount)
	require.Equal(t, "bar", d.table.entries[d.table.head].Name)
	require.Equal(t, "foo", d.table.entries[d.table.head].Value)

	msgs := parseFeedback(t, feedback)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{
		{"increment", 1},
		{"increment", 1},
		{"increment", 1},
	}, msgs)

	// Trailing (incomplete) bytes are buffered, not an error.
	fb, delivered, err := d.FeedEncoderStream([]byte{0x41})
	require.NoError(t, err)
	require.Nil(t, fb)
	require.Nil(t, delivered)
	fb, delivered, err = d.FeedEncoderStream([]byte{'z', 0x01, 'q'})
	require.NoError(t, err)
	require.Nil(t, delivered)
	msgs = parseFeedback(t, fb)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"increment", 1}}, msgs)
	require.Equal(t, uint64(4), d.table.knownReceivedCount)
}

func TestConnectionDecoderTwoStreamsReversedArrival(t *testing.T) {
	const capacity = 128
	d := NewConnectionDecoder(capacity, 4)
	mustFeedEnc(t, d, encCapacity(capacity))

	// Build two field sections, both referencing dynamic entries.
	ins0 := encInsertLiteralName("x-custom-a", "1") // absolute index 0
	ins1 := encInsertLiteralName("x-custom-b", "2") // absolute index 1

	// Stream 0: RIC 2, delta 0 -> base 2, relative 0 -> absolute 1.
	sec0 := encSectionPrefix(2, capacity/32, 0)
	sec0 = append(sec0, encDynamicIndexed(0)...)
	// Stream 4: post-base name reference to absolute index 1.
	// base = ric - delta - 1 = 0, post-base index 0 -> absolute base+1+0 = 1.
	sec4 := encSectionPrefixSigned(2, capacity/32, 1)
	sec4 = append(sec4, encPostBaseNameLiteral(0, "val")...)

	// Field sections arrive first, in reversed stream order, before any
	// referenced insert.
	fb, delivered, err := d.FeedFieldSection(4, sec4)
	require.NoError(t, err)
	require.Nil(t, fb)
	require.Nil(t, delivered)
	fb, delivered, err = d.FeedFieldSection(0, sec0)
	require.NoError(t, err)
	require.Nil(t, fb)
	require.Nil(t, delivered)

	// Insert 0 arrives: neither section becomes deliverable.
	fb, got, err := d.FeedEncoderStream(ins0)
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"increment", 1}}, parseFeedback(t, fb))

	// Insert 1 arrives: both unblock in arrival order (stream 4 first).
	fb, got, err = d.FeedEncoderStream(ins1)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, uint64(4), got[0].StreamID)
	require.Equal(t, []HeaderField{{Name: "x-custom-b", Value: "val"}}, got[0].Fields)
	require.Equal(t, uint64(0), got[1].StreamID)
	require.Equal(t, []HeaderField{{Name: "x-custom-b", Value: "2"}}, got[1].Fields)

	msgs := parseFeedback(t, fb)
	// Insert Count Increment (1), then acks in delivery order.
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{
		{"increment", 1},
		{"ack", 4},
		{"ack", 0},
	}, msgs)

	// Each section is delivered exactly once: a later encoder stream feed
	// delivers nothing new.
	fb, got, err = d.FeedEncoderStream(encDuplicate(0))
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"increment", 1}}, parseFeedback(t, fb))
}

func TestConnectionDecoderCapacityShrink(t *testing.T) {
	const capacity uint64 = 500
	d := NewConnectionDecoder(capacity, 4)
	mustFeedEnc(t, d, encCapacity(capacity))

	// Blocked section: RIC 3, base 3, relative 3 -> abs 0; and post-base
	// index 0 -> abs 3 (future). It stays blocked until 4 inserts arrive.
	sec := encSectionPrefix(3, capacity/32, 0)  // base = 3
	sec = append(sec, encDynamicIndexed(2)...)  // relative 2 -> abs 0 (3-1-2)
	sec = append(sec, encPostBaseIndexed(0)...) // post-base 0 -> abs 3
	fb, delivered, err := d.FeedFieldSection(8, sec)
	require.NoError(t, err)
	require.Nil(t, fb)
	require.Nil(t, delivered)

	// Insert two entries after the section arrived; it stays blocked
	// (needCount 4 > KRC 2).
	mustFeedEnc(t, d, encInsertLiteralName("x-aaaa", "v1")) // abs 0, size 38
	mustFeedEnc(t, d, encInsertLiteralName("x-bbbb", "v2")) // abs 1, size 38

	// Shrinking to 40 evicts entry 0 (76 > 40), which the blocked section
	// references: this is an encoder stream error.
	_, _, err = d.FeedEncoderStream(encCapacity(40))
	var iie InvalidIndexError
	require.ErrorAs(t, err, &iie)
	require.True(t, iie.Dynamic)
	require.True(t, iie.OnEncoderStream)
	require.ErrorIs(t, err, ErrEncoderStreamError)
	require.Equal(t, uint64(0), iie.Index)

	// The connection is now broken; later feeds fail with the same error.
	_, _, err = d.FeedEncoderStream(encCapacity(capacity))
	require.Error(t, err)
	_, _, err = d.FeedFieldSection(12, encSectionPrefix(0, 0, 0))
	require.Error(t, err)
}

func TestConnectionDecoderCapacityShrinkKeepsReferencedEntries(t *testing.T) {
	const capacity uint64 = 500
	d := NewConnectionDecoder(capacity, 4)
	mustFeedEnc(t, d, encCapacity(capacity))

	// Blocked section with RIC 3, base 3:
	//   relative 1 -> abs 1 (existing after two inserts),
	//   relative 0 -> abs 2 (future).
	// It never references abs 0.
	sec := encSectionPrefix(3, capacity/32, 0)
	sec = append(sec, encDynamicIndexed(1)...) // abs 1
	sec = append(sec, encDynamicIndexed(0)...) // abs 2 (future)
	_, delivered, err := d.FeedFieldSection(8, sec)
	require.NoError(t, err)
	require.Nil(t, delivered)

	mustFeedEnc(t, d, encInsertLiteralName("x-aaaa", "v1")) // abs 0, size 38
	mustFeedEnc(t, d, encInsertLiteralName("x-bbbb", "v2")) // abs 1, size 38; still blocked on abs 2

	// Shrink to 72: abs 0 (40) is evicted, abs 1 (40) survives. The blocked
	// section references only abs 1 and abs 2, so this is legal.
	fb, got, err := d.FeedEncoderStream(encCapacity(72))
	require.NoError(t, err)
	require.Nil(t, got)
	require.Empty(t, parseFeedback(t, fb))
	require.Equal(t, uint64(1), d.table.smallestAbsoluteIndex)

	// A minimal new entry (size 32) provides abs 2 and fits next to abs 1
	// (40+32=72). The section is delivered.
	fb, got, err = d.FeedEncoderStream(encInsertLiteralName("", ""))
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, uint64(8), got[0].StreamID)
	require.Equal(t, []HeaderField{
		{Name: "x-bbbb", Value: "v2"},
		{Name: "", Value: ""},
	}, got[0].Fields)
	msgs := parseFeedback(t, fb)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{
		{"increment", 1},
		{"ack", 8},
	}, msgs)
}

func TestConnectionDecoderRICWraparound(t *testing.T) {
	// MaxEntries = 1 (capacity 32), FullRange = 2.
	d := NewConnectionDecoder(32, 4)
	mustFeedEnc(t, d, encCapacity(32))

	// Drive the table to Known Received Count 4 by inserting small entries and
	// duplicates; only one entry is present at a time.
	mustFeedEnc(t, d, encInsertLiteralName("", "")) // abs 0, size 32
	mustFeedEnc(t, d, encDuplicate(0))              // abs 1
	mustFeedEnc(t, d, encDuplicate(0))              // abs 2
	require.Equal(t, uint64(3), d.table.knownReceivedCount)

	// A section with RIC = 3 is immediately decodable: enc 1, base 3,
	// relative 0 -> absolute 2.
	sec := encSectionPrefix(3, 1, 0)
	sec = append(sec, encDynamicIndexed(0)...)
	fb, got, err := d.FeedFieldSection(0, sec)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, []HeaderField{{Name: "", Value: ""}}, got[0].Fields)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"ack", 0}}, parseFeedback(t, fb))

	// Wraparound while blocked: a section arrives before the entries it
	// references. With RIC = 4 (enc 2, which unwraps to 4 at KRC 3) and
	// delta 0, base = 4; post-base 0 points at absolute index 4, one insert
	// past the current KRC of 3.
	secFuture := encSectionPrefix(4, 1, 0)
	// base = 4, relative 0 -> absolute 3 (4-1-0): requires 4 inserts.
	secFuture = append(secFuture, encDynamicIndexed(0)...)
	fb, got, err = d.FeedFieldSection(4, secFuture)
	require.NoError(t, err)
	require.Nil(t, fb)
	require.Nil(t, got)

	// abs 3 arrives: KRC 4, the same enc 2 unwraps to FIC 4, and abs 3 is
	// present. The section is delivered exactly once.
	fb, got, err = d.FeedEncoderStream(encDuplicate(0)) // abs 3
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, uint64(4), got[0].StreamID)
	require.Equal(t, []HeaderField{{Name: "", Value: ""}}, got[0].Fields)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{
		{"increment", 1},
		{"ack", 4},
	}, parseFeedback(t, fb))

	// RIC encoded larger than MaxValue (2) is a decompression error.
	bad := []byte{0x03, 0x00} // raw encoded value 3 > FullRange 2
	_, _, err = d.FeedFieldSection(8, bad)
	require.ErrorIs(t, err, ErrDecompressionFailed)
}

func TestConnectionDecoderCancelThenInsert(t *testing.T) {
	const capacity uint64 = 128
	d := NewConnectionDecoder(capacity, 4)
	mustFeedEnc(t, d, encCapacity(capacity))

	sec := encSectionPrefix(1, capacity/32, 0)
	sec = append(sec, encDynamicIndexed(0)...)
	_, delivered, err := d.FeedFieldSection(12, sec)
	require.NoError(t, err)
	require.Nil(t, delivered)

	// Application cancels: Stream Cancellation, no error.
	fb := d.CancelStream(12)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"cancel", 12}}, parseFeedback(t, fb))

	// Cancelling again (nothing pending) produces nothing and no error.
	require.Nil(t, d.CancelStream(12))

	// The insert arrives: the section is not delivered (it was discarded),
	// and no section acknowledgment is emitted.
	fb, got, err := d.FeedEncoderStream(encInsertLiteralName("x-a", "v"))
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"increment", 1}}, parseFeedback(t, fb))

	// The blocked slot is reusable: the same stream can block again.
	// RIC 2 with KRC 1: base 2, relative 1 -> absolute 1 (needs 2 inserts).
	sec2 := encSectionPrefix(2, capacity/32, 0)
	sec2 = append(sec2, encDynamicIndexed(0)...) // relative 0 -> absolute 1
	fb, got, err = d.FeedFieldSection(12, sec2)
	require.NoError(t, err)
	require.Nil(t, fb)
	require.Nil(t, got)
	fb, got, err = d.FeedEncoderStream(encDuplicate(0)) // abs 2; KRC 2 unblocks
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, uint64(12), got[0].StreamID)
	require.Equal(t, []HeaderField{{Name: "x-a", Value: "v"}}, got[0].Fields)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{
		{"increment", 1},
		{"ack", 12},
	}, parseFeedback(t, fb))
}

func TestConnectionDecoderErrorsAreDistinguishable(t *testing.T) {
	t.Run("capacity larger than advertised", func(t *testing.T) {
		d := NewConnectionDecoder(100, 4)
		_, _, err := d.FeedEncoderStream(encCapacity(101))
		var ice InvalidCapacityError
		require.ErrorAs(t, err, &ice)
		require.Equal(t, uint64(101), ice.Requested)
		require.Equal(t, uint64(100), ice.Maximum)
		require.ErrorIs(t, err, ErrEncoderStreamError)
		require.False(t, errors.Is(err, ErrDecompressionFailed))
	})

	t.Run("invalid static index", func(t *testing.T) {
		d := NewConnectionDecoder(100, 4)
		mustFeedEnc(t, d, encCapacity(100))
		// Encoder stream: insert with name reference to static index 99.
		_, _, err := d.FeedEncoderStream(encInsertStaticName(99, "v"))
		var iie InvalidIndexError
		require.ErrorAs(t, err, &iie)
		require.False(t, iie.Dynamic)
		require.True(t, iie.OnEncoderStream)
		require.ErrorIs(t, err, ErrEncoderStreamError)
	})

	t.Run("invalid dynamic relative insert", func(t *testing.T) {
		d := NewConnectionDecoder(100, 4)
		mustFeedEnc(t, d, encCapacity(100))
		_, _, err := d.FeedEncoderStream(encInsertDynamicName(0, "v"))
		var iie InvalidIndexError
		require.ErrorAs(t, err, &iie)
		require.True(t, iie.Dynamic)
		require.True(t, iie.OnEncoderStream)
	})

	t.Run("invalid static index in field section", func(t *testing.T) {
		d := NewConnectionDecoder(100, 4)
		sec := encSectionPrefix(0, 0, 0)
		sec = append(sec, encStaticIndexed(99)...)
		_, _, err := d.FeedFieldSection(0, sec)
		var iie InvalidIndexError
		require.ErrorAs(t, err, &iie)
		require.False(t, iie.Dynamic)
		require.False(t, iie.OnEncoderStream)
		require.ErrorIs(t, err, ErrDecompressionFailed)
	})

	t.Run("blocked streams limit", func(t *testing.T) {
		d := NewConnectionDecoder(100, 1)
		mustFeedEnc(t, d, encCapacity(100))
		sec := encSectionPrefix(1, 100/32, 0)
		sec = append(sec, encDynamicIndexed(0)...)
		_, _, err := d.FeedFieldSection(0, sec)
		require.NoError(t, err)
		_, _, err = d.FeedFieldSection(4, sec)
		require.ErrorIs(t, err, ErrBlockedStreamsExceeded)
		require.False(t, errors.Is(err, ErrEncoderStreamError))
	})

	t.Run("invalid encoder stream type byte", func(t *testing.T) {
		d := NewConnectionDecoder(100, 4)
		// 0b00110000 is not a valid encoder stream instruction prefix.
		_, _, err := d.FeedEncoderStream([]byte{0x30})
		require.ErrorIs(t, err, ErrEncoderStreamError)
	})
}

func TestConnectionDecoderStaticAndLiteralSections(t *testing.T) {
	d := NewConnectionDecoder(0, 0)

	sec := encSectionPrefix(0, 0, 0)
	sec = append(sec, encStaticIndexed(20)...)            // :method POST
	sec = append(sec, encStaticNameLiteral(81, "GET")...) // access-control-request-method
	sec = append(sec, encLiteral("x-cust", "y")...)

	fb, got, err := d.FeedFieldSection(0, sec)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: "access-control-request-method", Value: "GET"},
		{Name: "x-cust", Value: "y"},
	}, got[0].Fields)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"ack", 0}}, parseFeedback(t, fb))
}

func TestConnectionDecoderDynamicNameInsertAndReference(t *testing.T) {
	const capacity uint64 = 256
	d := NewConnectionDecoder(capacity, 4)
	mustFeedEnc(t, d, encCapacity(capacity))

	// Insert ("x-name", "a") with a literal name, then insert with a name
	// reference to that dynamic entry (relative index 0), with a new value.
	mustFeedEnc(t, d, encInsertLiteralName("x-name", "a"))
	mustFeedEnc(t, d, encInsertDynamicName(0, "b"))

	// Field section referencing the second entry (absolute index 1) by name
	// and overriding the value, plus an indexed reference to it.
	sec := encSectionPrefix(2, capacity/32, 0)          // base 2
	sec = append(sec, encDynamicNameLiteral(0, "c")...) // name from abs 1
	sec = append(sec, encDynamicIndexed(0)...)          // abs 1 complete

	fb, got, err := d.FeedFieldSection(0, sec)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, []HeaderField{
		{Name: "x-name", Value: "c"},
		{Name: "x-name", Value: "b"},
	}, got[0].Fields)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"ack", 0}}, parseFeedback(t, fb))
}

func TestConnectionDecoderZeroCapacityInserts(t *testing.T) {
	d := NewConnectionDecoder(0, 0)
	// No capacity instruction (capacity stays 0): a literal-name insert that
	// fits nowhere is an encoder stream error (the table is not empty because
	// capacity is zero -- per RFC this is only allowed after a set-capacity
	// of zero, in which case inserts of entries that do not fit are errors).
	_, _, err := d.FeedEncoderStream(encInsertLiteralName("x", "y"))
	require.ErrorIs(t, err, ErrEncoderStreamError)
}

func TestConnectionDecoderEvictedReferenceIsError(t *testing.T) {
	const capacity uint64 = 64
	d := NewConnectionDecoder(capacity, 4)
	mustFeedEnc(t, d, encCapacity(capacity))

	// Two 32-byte entries fit (32 + 32 = 64). A third evicts the first.
	mustFeedEnc(t, d, encInsertLiteralName("", "")) // abs 0
	mustFeedEnc(t, d, encInsertLiteralName("", "")) // abs 1
	mustFeedEnc(t, d, encInsertLiteralName("", "")) // abs 2, evicts abs 0
	require.Equal(t, uint64(1), d.table.smallestAbsoluteIndex)

	// RIC 3, base 3, relative 2 -> absolute 0, which was evicted.
	sec := encSectionPrefix(3, capacity/32, 0)
	sec = append(sec, encDynamicIndexed(2)...)
	_, _, err := d.FeedFieldSection(0, sec)
	var iie InvalidIndexError
	require.ErrorAs(t, err, &iie)
	require.True(t, iie.Dynamic)
	require.Equal(t, uint64(0), iie.Index)
	require.ErrorIs(t, err, ErrDecompressionFailed)
	require.False(t, errors.Is(err, ErrEncoderStreamError))

	// The connection is dead: further feeds fail.
	_, _, err = d.FeedFieldSection(4, encSectionPrefix(0, 0, 0))
	require.Error(t, err)
}

func TestConnectionDecoderSectionDeliveredOnceOnly(t *testing.T) {
	const capacity uint64 = 128
	d := NewConnectionDecoder(capacity, 4)
	mustFeedEnc(t, d, encCapacity(capacity))

	sec := encSectionPrefix(2, capacity/32, 0) // base 2
	sec = append(sec, encDynamicIndexed(0)...) // abs 1
	_, got, err := d.FeedFieldSection(0, sec)
	require.NoError(t, err)
	require.Nil(t, got)

	// Multiple encoder feeds before the unblocking insert deliver nothing.
	mustFeedEnc(t, d, encCapacity(capacity))
	mustFeedEnc(t, d, encInsertLiteralName("x-a", "v")) // abs 0, still blocked

	fb, got, err := d.FeedEncoderStream(encDuplicate(0)) // abs 1, unblocks
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{
		{"increment", 1},
		{"ack", 0},
	}, parseFeedback(t, fb))

	// Further inserts never re-deliver the section.
	fb, got, err = d.FeedEncoderStream(encDuplicate(0))
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"increment", 1}}, parseFeedback(t, fb))
	fb, got, err = d.FeedEncoderStream(encDuplicate(0))
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, []struct {
		kind  string
		value uint64
	}{{"increment", 1}}, parseFeedback(t, fb))
}
