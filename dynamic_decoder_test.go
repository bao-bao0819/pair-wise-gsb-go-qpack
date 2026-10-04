package qpack

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func dynSetCapacity(capacity uint64) []byte {
	buf := appendVarInt(nil, 5, capacity)
	buf[0] |= 0x20
	return buf
}

func dynInsertLiteralName(name, value string) []byte {
	buf := appendVarInt(nil, 4, uint64(len(name)))
	buf[0] |= 0x40
	buf = append(buf, name...)
	return appendPlainFieldString(buf, value)
}

func dynInsertStaticName(index uint64, value string) []byte {
	buf := appendVarInt(nil, 6, index)
	buf[0] |= 0xc0
	return appendPlainFieldString(buf, value)
}

func dynDuplicate(relativeIndex uint64) []byte {
	return appendVarInt(nil, 5, relativeIndex)
}

func appendPlainFieldString(dst []byte, value string) []byte {
	dst = appendVarInt(dst, 7, uint64(len(value)))
	return append(dst, value...)
}

func dynSection(required uint64, signDelta uint64, body ...[]byte) []byte {
	buf := appendVarInt(nil, 8, required)
	if signDelta >= 0x80 && signDelta <= 0xfe {
		buf = append(buf, byte(signDelta))
	} else {
		buf = appendVarInt(buf, 7, signDelta)
	}
	return append(buf, bytes.Join(body, nil)...)
}

func dynSignedSection(required, delta uint64, body ...[]byte) []byte {
	buf := appendVarInt(nil, 8, required)
	if delta < 127 {
		buf = append(buf, 0x80|byte(delta))
	} else {
		buf = appendVarInt(buf, 7, delta)
		offset := len(appendVarInt(nil, 7, delta))
		buf[len(buf)-offset] |= 0x80
	}
	return append(buf, bytes.Join(body, nil)...)
}

func dynRelativeIndexed(relative uint64) []byte {
	buf := appendVarInt(nil, 6, relative)
	buf[0] |= 0x80
	return buf
}

func dynStaticIndexed(index uint64) []byte {
	buf := appendVarInt(nil, 6, index)
	buf[0] |= 0xc0
	return buf
}

func dynPostBaseIndexed(index uint64) []byte {
	buf := appendVarInt(nil, 4, index)
	buf[0] |= 0x10
	return buf
}

func dynRelativeNameLiteral(relative uint64, value string) []byte {
	buf := appendVarInt(nil, 4, relative)
	buf[0] |= 0x40
	return appendPlainFieldString(buf, value)
}

func dynPostBaseNameLiteral(index uint64, value string) []byte {
	buf := appendVarInt(nil, 3, index)
	return appendPlainFieldString(buf, value)
}

func dynLiteralNameValue(name, value string) []byte {
	buf := appendVarInt(nil, 3, uint64(len(name)))
	buf[0] |= 0x20
	buf = append(buf, name...)
	return appendPlainFieldString(buf, value)
}

func TestDynamicDecoderEncoderInstructionsByteByByte(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	instructions := [][]byte{
		dynSetCapacity(4096),
		dynInsertLiteralName("foo", "bar"),
		dynInsertStaticName(1, "/index.html"),
		dynDuplicate(0),
	}

	var feedback []byte
	var released []DecodedSection
	for _, instruction := range instructions {
		for _, b := range instruction {
			fb, sections, err := d.FeedEncoderStream([]byte{b})
			require.NoError(t, err)
			feedback = append(feedback, fb...)
			released = append(released, sections...)
		}
	}
	require.Empty(t, released)
	require.Equal(t, 3, d.KnownInsertCount())
	require.Equal(t, []byte{0x01, 0x01, 0x01}, feedback)

	body := bytes.Join([][]byte{
		dynRelativeIndexed(0),
		dynRelativeIndexed(1),
		dynRelativeIndexed(2),
	}, nil)
	fields, ack, err := d.FeedFieldSection(0, dynSignedSection(3, 0, body))
	require.NoError(t, err)
	require.Equal(t, []HeaderField{
		{Name: ":path", Value: "/index.html"},
		{Name: ":path", Value: "/index.html"},
		{Name: "foo", Value: "bar"},
	}, fields)
	require.Equal(t, []byte{0x80}, ack)
}

func TestDynamicDecoderTwoSectionsReverseArrival(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(4096))
	require.NoError(t, err)

	section4 := dynSignedSection(2, 2, dynPostBaseIndexed(1))
	section8 := dynSignedSection(3, 3, dynPostBaseIndexed(2))
	fields, feedback, err := d.FeedFieldSection(4, section4)
	require.NoError(t, err)
	require.Nil(t, fields)
	require.Nil(t, feedback)
	fields, feedback, err = d.FeedFieldSection(8, section8)
	require.NoError(t, err)
	require.Nil(t, fields)
	require.Nil(t, feedback)
	require.Equal(t, 2, d.BlockedStreams())

	feedback, sections, err := d.FeedEncoderStream(dynInsertLiteralName("one", "1"))
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Equal(t, []byte{0x01}, feedback)

	feedback, sections, err = d.FeedEncoderStream(dynInsertLiteralName("two", "2"))
	require.NoError(t, err)
	require.Equal(t, []DecodedSection{{StreamID: 4, HeaderFields: []HeaderField{{Name: "two", Value: "2"}}}}, sections)
	require.Equal(t, []byte{0x01, 0x84}, feedback)

	feedback, sections, err = d.FeedEncoderStream(dynInsertLiteralName("three", "3"))
	require.NoError(t, err)
	require.Equal(t, []DecodedSection{{StreamID: 8, HeaderFields: []HeaderField{{Name: "three", Value: "3"}}}}, sections)
	require.Equal(t, []byte{0x01, 0x88}, feedback)

	feedback, sections, err = d.FeedEncoderStream(nil)
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Empty(t, feedback)
}

func TestDynamicDecoderPostBaseAndRelativeReferences(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(4096))
	require.NoError(t, err)
	_, _, err = d.FeedEncoderStream(dynInsertLiteralName("name", "value"))
	require.NoError(t, err)

	body := bytes.Join([][]byte{
		dynRelativeNameLiteral(0, "relative"),
		dynStaticIndexed(17),
		dynLiteralNameValue("x-test", "literal"),
	}, nil)
	fields, _, err := d.FeedFieldSection(12, dynSignedSection(1, 0, body))
	require.NoError(t, err)
	require.Equal(t, []HeaderField{
		{Name: "name", Value: "relative"},
		{Name: ":method", Value: "GET"},
		{Name: "x-test", Value: "literal"},
	}, fields)
}

func TestDynamicDecoderCapacityShrinkAndProtectedBlockedSection(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(256))
	require.NoError(t, err)
	for range 3 {
		_, _, err = d.FeedEncoderStream(dynInsertLiteralName("", ""))
		require.NoError(t, err)
	}

	fields, _, err := d.FeedFieldSection(0, dynSignedSection(3, 0, dynRelativeIndexed(2)))
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "", Value: ""}}, fields)

	_, _, err = d.FeedEncoderStream(dynSetCapacity(64))
	require.NoError(t, err)
	_, _, err = d.FeedFieldSection(0, dynSignedSection(3, 0, dynRelativeIndexed(2)))
	require.ErrorIs(t, err, ErrInvalidIndex)

	blockedDecoder := NewDynamicDecoder(4096, 4)
	_, _, err = blockedDecoder.FeedEncoderStream(dynSetCapacity(1024))
	require.NoError(t, err)
	for range 9 {
		_, _, err = blockedDecoder.FeedEncoderStream(dynInsertLiteralName("", ""))
		require.NoError(t, err)
	}

	blocked := dynSignedSection(10, 0, dynRelativeIndexed(9))
	_, _, err = blockedDecoder.FeedFieldSection(4, blocked)
	require.NoError(t, err)
	require.Equal(t, 1, blockedDecoder.BlockedStreams())

	_, _, err = blockedDecoder.FeedEncoderStream(dynSetCapacity(256))
	require.ErrorIs(t, err, ErrInvalidTableCapacity)

	_, _, err = blockedDecoder.FeedEncoderStream(dynInsertLiteralName("", ""))
	require.ErrorIs(t, err, ErrInvalidTableCapacity)

	_, _, err = blockedDecoder.FeedEncoderStream(dynSetCapacity(256))
	require.ErrorIs(t, err, ErrInvalidTableCapacity)

	_, _, err = blockedDecoder.FeedEncoderStream(nil)
	require.ErrorIs(t, err, ErrInvalidTableCapacity)

	_, _, err = blockedDecoder.FeedFieldSection(8, dynSection(0, 0))
	require.ErrorIs(t, err, ErrInvalidTableCapacity)
}

func TestDynamicDecoderRequiredInsertCountWraparound(t *testing.T) {
	const capacity = 128
	d := NewDynamicDecoder(capacity, 4)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(capacity))
	require.NoError(t, err)
	for range 8 {
		_, _, err = d.FeedEncoderStream(dynInsertLiteralName("", ""))
		require.NoError(t, err)
	}

	fields, _, err := d.FeedFieldSection(0, dynSignedSection(8, 0, dynRelativeIndexed(0)))
	require.NoError(t, err)
	require.Len(t, fields, 1)

	blocked := dynSection(2, 0x80|10, dynPostBaseIndexed(9))
	fields, _, err = d.FeedFieldSection(4, blocked)
	require.NoError(t, err)
	require.Nil(t, fields)

	var sections []DecodedSection
	for range 2 {
		var released []DecodedSection
		_, released, err = d.FeedEncoderStream(dynInsertLiteralName("", ""))
		require.NoError(t, err)
		sections = append(sections, released...)
	}
	require.Equal(t, 10, d.KnownInsertCount())
	require.Zero(t, d.BlockedStreams())
	require.Equal(t, []DecodedSection{{StreamID: 4, HeaderFields: []HeaderField{{Name: "", Value: ""}}}}, sections)
}

func TestDynamicDecoderCancelThenInsert(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(4096))
	require.NoError(t, err)

	section := dynSignedSection(1, 1, dynPostBaseIndexed(0))
	fields, feedback, err := d.FeedFieldSection(100, section)
	require.NoError(t, err)
	require.Nil(t, fields)
	require.Nil(t, feedback)

	require.Equal(t, []byte{0x7f, 100 - 63}, d.CancelStream(100))
	require.Nil(t, d.CancelStream(100))

	feedback, sections, err := d.FeedEncoderStream(dynInsertLiteralName("foo", "bar"))
	require.NoError(t, err)
	require.Empty(t, sections)
	require.Equal(t, []byte{0x01}, feedback)
}

func TestDynamicDecoderBlockedStreamLimitAndInvalidIndex(t *testing.T) {
	d := NewDynamicDecoder(4096, 1)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(4096))
	require.NoError(t, err)
	section := dynSignedSection(1, 1, dynPostBaseIndexed(0))
	_, _, err = d.FeedFieldSection(0, section)
	require.NoError(t, err)
	_, _, err = d.FeedFieldSection(4, section)
	require.ErrorIs(t, err, ErrTooManyBlockedStreams)

	d0 := NewDynamicDecoder(4096, 0)
	_, _, err = d0.FeedEncoderStream(dynSetCapacity(4096))
	require.NoError(t, err)
	_, _, err = d0.FeedFieldSection(0, section)
	require.ErrorIs(t, err, ErrTooManyBlockedStreams)

	badStatic := NewDynamicDecoder(4096, 1)
	_, _, err = badStatic.FeedEncoderStream(dynSetCapacity(4096))
	require.NoError(t, err)
	_, _, err = badStatic.FeedEncoderStream(dynInsertStaticName(uint64(len(staticTableEntries)+1), "x"))
	require.ErrorIs(t, err, ErrInvalidIndex)
	badDuplicate := NewDynamicDecoder(4096, 1)
	_, _, err = badDuplicate.FeedEncoderStream(dynDuplicate(10))
	require.ErrorIs(t, err, ErrInvalidIndex)
}

func TestDynamicDecoderTruncatedAndLegacyStatelessAPI(t *testing.T) {
	d := NewDynamicDecoder(4096, 4)
	capacity := dynSetCapacity(4000)
	feedback, sections, err := d.FeedEncoderStream(capacity[:len(capacity)-1])
	require.NoError(t, err)
	require.Empty(t, feedback)
	require.Empty(t, sections)

	feedback, _, err = d.FeedEncoderStream(capacity[len(capacity)-1:])
	require.NoError(t, err)
	require.Empty(t, feedback)

	_, _, err = d.FeedEncoderStream(dynInsertStaticName(1, "x"))
	require.NoError(t, err)
	duplicate := dynDuplicate(0)
	require.Len(t, duplicate, 1)
	feedback, _, err = d.FeedEncoderStream(duplicate)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, feedback)
	require.Equal(t, 2, d.KnownInsertCount())

	data := insertPrefix(dynStaticIndexed(17))
	decode := NewDecoder().Decode(data)
	hf, err := decode()
	require.NoError(t, err)
	require.Equal(t, staticTableEntries[17], hf)
	_, err = decode()
	require.ErrorIs(t, err, io.EOF)
}

func TestDynamicDecoderProtocolErrorClassification(t *testing.T) {
	errorsForCheck := []error{
		ErrInvalidIndex,
		ErrInvalidTableCapacity,
		ErrTooManyBlockedStreams,
	}
	for _, err := range errorsForCheck {
		require.True(t, errors.Is(err, ErrDecompressionFailed))
	}

	d := NewDynamicDecoder(4096, 4)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(4097))
	require.ErrorIs(t, err, ErrInvalidTableCapacity)
	require.ErrorIs(t, err, ErrDecompressionFailed)

	canceled := NewDynamicDecoder(4096, 1)
	_, _, err = canceled.FeedFieldSection(0, dynSignedSection(1, 1, dynPostBaseIndexed(0)))
	require.NoError(t, err)
	require.NotNil(t, canceled.CancelStream(0))
	require.False(t, errors.Is(io.EOF, ErrDecompressionFailed))
}

func TestDynamicDecoderOversizedEntryDoesNotIncrement(t *testing.T) {
	d := NewDynamicDecoder(32, 1)
	_, _, err := d.FeedEncoderStream(dynSetCapacity(32))
	require.NoError(t, err)

	feedback, sections, err := d.FeedEncoderStream(dynInsertLiteralName("x", ""))
	require.ErrorIs(t, err, ErrInvalidTableCapacity)
	require.Empty(t, feedback)
	require.Empty(t, sections)
	require.Zero(t, d.KnownInsertCount())

	_, _, err = d.FeedEncoderStream(nil)
	require.ErrorIs(t, err, ErrInvalidTableCapacity)
}
