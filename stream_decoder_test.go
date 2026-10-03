package qpack

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

var streamTestCases = []testcase{
	literalFieldWithoutNameReference,
	literalFieldWithNameReference,
	literalFieldWithHuffmanEncoding,
	indexedField,
}

// pushAll pushes every chunk, asserting that each is fully consumed,
// and returns all completed header fields.
func pushAll(t *testing.T, sd *StreamDecoder, chunks ...[]byte) []HeaderField {
	t.Helper()
	var hfs []HeaderField
	for i, c := range chunks {
		last := i == len(chunks)-1
		n, got, needMore, err := sd.Push(c, last)
		require.NoError(t, err)
		require.Equal(t, len(c), n)
		require.Equal(t, !last, needMore)
		hfs = append(hfs, got...)
	}
	return hfs
}

// TestStreamDecoderSplitPoints decodes every test vector split into two
// chunks at every possible split point.
func TestStreamDecoderSplitPoints(t *testing.T) {
	for _, tc := range streamTestCases {
		for i := 0; i <= len(tc.Data); i++ {
			t.Run(fmt.Sprintf("split at %d", i), func(t *testing.T) {
				sd := NewStreamDecoder(Limits{})
				require.Equal(t, tc.Expected, pushAll(t, sd, tc.Data[:i], tc.Data[i:]))
			})
		}
	}
}

// TestStreamDecoderByteByByte feeds every test vector one byte at a time,
// reusing the same one-byte buffer for every Push.
func TestStreamDecoderByteByByte(t *testing.T) {
	for _, tc := range streamTestCases {
		sd := NewStreamDecoder(Limits{})
		var hfs []HeaderField
		buf := make([]byte, 1)
		for _, b := range tc.Data {
			buf[0] = b
			n, got, needMore, err := sd.Push(buf, false)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			require.True(t, needMore)
			hfs = append(hfs, got...)
		}
		require.NoError(t, sd.Finish())
		require.Equal(t, tc.Expected, hfs)
	}
}

// TestStreamDecoderInputReuse overwrites the input buffer as soon as Push
// returns, verifying that the decoder doesn't retain references to it.
func TestStreamDecoderInputReuse(t *testing.T) {
	for _, tc := range streamTestCases {
		for i := 1; i < len(tc.Data); i++ {
			sd := NewStreamDecoder(Limits{})
			buf := make([]byte, len(tc.Data))
			copy(buf, tc.Data[:i])
			n, hfs, needMore, err := sd.Push(buf[:i], false)
			require.NoError(t, err)
			require.Equal(t, i, n)
			require.True(t, needMore)
			// overwrite the previously pushed bytes
			copy(buf, tc.Data[i:])
			n, got, needMore, err := sd.Push(buf[:len(tc.Data)-i], true)
			require.NoError(t, err)
			require.Equal(t, len(tc.Data)-i, n)
			require.False(t, needMore)
			require.Equal(t, tc.Expected, append(hfs, got...))
		}
	}
}

func TestStreamDecoderZeroLengthPush(t *testing.T) {
	sd := NewStreamDecoder(Limits{})
	n, hfs, needMore, err := sd.Push(nil, false)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Empty(t, hfs)
	require.True(t, needMore)

	// zero-length pushes interleaved with real data don't change the result
	data := literalFieldWithHuffmanEncoding.Data
	got := pushAll(t, sd, nil, data[:5], nil, data[5:], nil)
	require.Equal(t, literalFieldWithHuffmanEncoding.Expected, got)
}

func TestStreamDecoderFinish(t *testing.T) {
	t.Run("distinguishes a truncated prefix from an empty field section", func(t *testing.T) {
		// no input at all: the prefix is missing, the section is truncated
		sd := NewStreamDecoder(Limits{})
		err := sd.Finish()
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		var perr *ParseError
		require.ErrorAs(t, err, &perr)
		require.Equal(t, uint64(0), perr.Offset)

		// a bare prefix is a valid, empty field section
		sd = NewStreamDecoder(Limits{})
		n, hfs, needMore, err := sd.Push(insertPrefix(nil), true)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		require.Empty(t, hfs)
		require.False(t, needMore)
	})

	t.Run("truncated mid-field", func(t *testing.T) {
		data := literalFieldWithoutNameReference.Data
		sd := NewStreamDecoder(Limits{})
		_, hfs, _, err := sd.Push(data[:len(data)-1], true)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		var perr *ParseError
		require.ErrorAs(t, err, &perr)
		// the first field was completed before the truncation was detected
		require.Equal(t, literalFieldWithoutNameReference.Expected[:1], hfs)
	})

	t.Run("truncated prefix", func(t *testing.T) {
		sd := NewStreamDecoder(Limits{})
		_, _, _, err := sd.Push([]byte{0x00}, true)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

func TestStreamDecoderErrorOffset(t *testing.T) {
	t.Run("offset within a single push", func(t *testing.T) {
		sd := NewStreamDecoder(Limits{})
		_, _, _, err := sd.Push([]byte{0x00, 0x00, 0x10}, true)
		var perr *ParseError
		require.ErrorAs(t, err, &perr)
		require.Equal(t, uint64(2), perr.Offset)
		require.EqualError(t, perr.Err, "unexpected type byte: 0x10")
	})

	t.Run("offset accumulates across pushes", func(t *testing.T) {
		sd := NewStreamDecoder(Limits{})
		_, _, _, err := sd.Push(indexedField.Data, false)
		require.NoError(t, err)
		_, _, _, err = sd.Push([]byte{0x10}, false)
		var perr *ParseError
		require.ErrorAs(t, err, &perr)
		require.Equal(t, uint64(len(indexedField.Data)), perr.Offset)
		// the error is sticky
		_, _, _, err = sd.Push([]byte{0x00}, false)
		require.ErrorAs(t, err, &perr)
	})
}

func TestStreamDecoderInvalidHuffman(t *testing.T) {
	// literal field with name reference, Huffman-encoded value of length 1.
	// 0x00 is not valid Huffman: padding must consist of 1-bits.
	data := appendVarInt(nil, 4, 49)
	data[0] ^= 0x40 | 0x10
	l := len(data)
	data = appendVarInt(data, 7, 1)
	data[l] ^= 0x80
	data = insertPrefix(append(data, 0x00))

	sd := NewStreamDecoder(Limits{})
	// the error only surfaces once the final byte of the string arrives
	n, hfs, needMore, err := sd.Push(data[:len(data)-1], false)
	require.NoError(t, err)
	require.Equal(t, len(data)-1, n)
	require.Empty(t, hfs)
	require.True(t, needMore)
	_, _, _, err = sd.Push(data[len(data)-1:], true)
	require.Error(t, err)
	require.NotErrorIs(t, err, io.ErrUnexpectedEOF)
	var perr *ParseError
	require.ErrorAs(t, err, &perr)
	// the offset points at the start of the field that failed to parse,
	// right after the 2-byte prefix
	require.Equal(t, uint64(2), perr.Offset)
}

func TestStreamDecoderVarintOverflow(t *testing.T) {
	// a varint with too many continuation bytes overflows;
	// split it across two pushes to exercise cross-chunk integer parsing
	data := bytes.Repeat([]byte{0xff}, 10)
	sd := NewStreamDecoder(Limits{})
	n, _, needMore, err := sd.Push(data[:5], false)
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.True(t, needMore)
	_, _, _, err = sd.Push(data[5:], true)
	require.ErrorIs(t, err, errVarintOverflow)
	var perr *ParseError
	require.ErrorAs(t, err, &perr)
	require.Equal(t, uint64(0), perr.Offset)
}

func TestStreamDecoderDynamicTableReferences(t *testing.T) {
	t.Run("non-zero required insert count", func(t *testing.T) {
		sd := NewStreamDecoder(Limits{})
		data := append(appendVarInt(nil, 8, 1), appendVarInt(nil, 7, 0)...)
		_, _, _, err := sd.Push(data, true)
		require.EqualError(t, err, "qpack: parse error at offset 0: expected Required Insert Count to be zero")
	})

	t.Run("indexed field referencing the dynamic table", func(t *testing.T) {
		data := appendVarInt(nil, 6, 20)
		data[0] ^= 0x80 // don't set the static flag (0x40)
		sd := NewStreamDecoder(Limits{})
		_, _, _, err := sd.Push(insertPrefix(data), true)
		require.ErrorIs(t, err, errNoDynamicTable)
	})
}

func TestStreamDecoderLimits(t *testing.T) {
	t.Run("encoded bytes", func(t *testing.T) {
		data := literalFieldWithoutNameReference.Data
		// a limit large enough for the entire section passes
		sd := NewStreamDecoder(Limits{MaxEncodedBytes: uint64(len(data))})
		require.Equal(t, literalFieldWithoutNameReference.Expected, pushAll(t, sd, data))

		// the limit is enforced across pushes
		sd = NewStreamDecoder(Limits{MaxEncodedBytes: uint64(len(data) - 1)})
		_, _, _, err := sd.Push(data[:len(data)/2], false)
		require.NoError(t, err)
		_, _, _, err = sd.Push(data[len(data)/2:], true)
		require.ErrorIs(t, err, errEncodedSectionTooLarge)
		var perr *ParseError
		require.ErrorAs(t, err, &perr)
		require.Equal(t, uint64(len(data)-1), perr.Offset)
	})

	t.Run("field section size", func(t *testing.T) {
		fields := literalFieldWithoutNameReference.Expected
		size := func(hf HeaderField) uint64 { return uint64(len(hf.Name) + len(hf.Value) + 32) }
		limit := size(fields[0]) + size(fields[1])
		// a limit large enough for the entire section passes
		sd := NewStreamDecoder(Limits{MaxFieldSectionSize: limit})
		require.Equal(t, fields, pushAll(t, sd, literalFieldWithoutNameReference.Data))

		// the decoded size accumulates across pushes
		sd = NewStreamDecoder(Limits{MaxFieldSectionSize: limit - 1})
		data := literalFieldWithoutNameReference.Data
		_, hfs, _, err := sd.Push(data, true)
		require.ErrorIs(t, err, errFieldSectionTooLarge)
		// the first field was delivered before the limit was exceeded
		require.Equal(t, fields[:1], hfs)
	})

	t.Run("field length", func(t *testing.T) {
		fields := literalFieldWithoutNameReference.Expected
		limit := uint64(len(fields[0].Name) + len(fields[0].Value))
		// the first field fits, the second (longer) one doesn't
		sd := NewStreamDecoder(Limits{MaxFieldLength: limit})
		_, hfs, _, err := sd.Push(literalFieldWithoutNameReference.Data, true)
		require.ErrorIs(t, err, errFieldTooLarge)
		require.Equal(t, fields[:1], hfs)

		// a declared string length exceeding the limit is rejected early,
		// before the string is buffered in full
		sd = NewStreamDecoder(Limits{MaxFieldLength: 10})
		_, _, _, err = sd.Push(literalFieldWithoutNameReference.Data[:8], false)
		require.ErrorIs(t, err, errFieldTooLarge)
	})
}

func TestStreamDecoderPushAfterCompletion(t *testing.T) {
	sd := NewStreamDecoder(Limits{})
	require.Equal(t, indexedField.Expected, pushAll(t, sd, indexedField.Data))
	_, _, _, err := sd.Push([]byte{0x00}, false)
	require.ErrorIs(t, err, errSectionComplete)
}
