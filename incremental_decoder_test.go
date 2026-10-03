package qpack

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

var successTestcases = []testcase{
	literalFieldWithoutNameReference,
	literalFieldWithNameReference,
	literalFieldWithHuffmanEncoding,
	indexedField,
}

// pushAll feeds data to the decoder in chunks, re-presenting unconsumed
// bytes as part of the next chunk. It returns all header fields delivered
// along the way, the total number of bytes consumed, and the first error
// encountered (if any).
func pushAll(t *testing.T, dec *IncrementalDecoder, chunks [][]byte) ([]HeaderField, int, error) {
	t.Helper()
	var hfs []HeaderField
	var totalConsumed int
	var buf []byte
	for i, chunk := range chunks {
		buf = append(buf, chunk...)
		consumed, fields, _, err := dec.Push(buf, i == len(chunks)-1)
		totalConsumed += consumed
		hfs = append(hfs, fields...)
		buf = buf[consumed:]
		if err != nil {
			return hfs, totalConsumed, err
		}
	}
	return hfs, totalConsumed, nil
}

func TestIncrementalDecoderSplitPoints(t *testing.T) {
	for _, tc := range successTestcases {
		for i := 0; i <= len(tc.Data); i++ {
			dec := NewIncrementalDecoder()
			hfs, consumed, err := pushAll(t, dec, [][]byte{tc.Data[:i], tc.Data[i:]})
			require.NoError(t, err)
			require.Equal(t, len(tc.Data), consumed)
			require.Equal(t, tc.Expected, hfs)
			require.NoError(t, dec.Finish())
		}
	}
}

func TestIncrementalDecoderByteByByte(t *testing.T) {
	for _, tc := range successTestcases {
		dec := NewIncrementalDecoder()
		var hfs []HeaderField
		var totalConsumed int
		var buf []byte
		for i := range tc.Data {
			buf = append(buf, tc.Data[i])
			consumed, fields, needMore, err := dec.Push(buf, false)
			require.NoError(t, err)
			require.True(t, needMore)
			totalConsumed += consumed
			hfs = append(hfs, fields...)
			buf = buf[consumed:]
		}
		consumed, fields, needMore, err := dec.Push(nil, true)
		require.NoError(t, err)
		require.False(t, needMore)
		totalConsumed += consumed
		hfs = append(hfs, fields...)
		require.Equal(t, len(tc.Data), totalConsumed)
		require.Equal(t, tc.Expected, hfs)
	}
}

func TestIncrementalDecoderZeroLengthPush(t *testing.T) {
	dec := NewIncrementalDecoder()
	// zero-length pushes before any data was received
	consumed, fields, needMore, err := dec.Push(nil, false)
	require.NoError(t, err)
	require.Zero(t, consumed)
	require.Empty(t, fields)
	require.True(t, needMore)

	data := literalFieldWithoutNameReference.Data
	// zero-length pushes interleaved with data
	hfs, totalConsumed, err := pushAll(t, dec, [][]byte{
		nil,
		data[:5],
		nil,
		data[5:],
	})
	require.NoError(t, err)
	require.Equal(t, len(data), totalConsumed)
	require.Equal(t, literalFieldWithoutNameReference.Expected, hfs)
	require.NoError(t, dec.Finish())

	// pushing after the field section completed is an error
	_, _, _, err = dec.Push(nil, false)
	require.ErrorIs(t, err, errPushAfterFinish)
}

func TestIncrementalDecoderFinish(t *testing.T) {
	t.Run("empty field section", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		_, fields, needMore, err := dec.Push(insertPrefix(nil), true)
		require.NoError(t, err)
		require.Empty(t, fields)
		require.False(t, needMore)
		require.NoError(t, dec.Finish())
	})

	t.Run("empty field section, finished via Finish", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		_, _, needMore, err := dec.Push(insertPrefix(nil), false)
		require.NoError(t, err)
		require.True(t, needMore)
		require.NoError(t, dec.Finish())
	})

	t.Run("truncated field section", func(t *testing.T) {
		data := literalFieldWithoutNameReference.Data
		dec := NewIncrementalDecoder()
		_, _, _, err := dec.Push(data[:len(data)-1], false)
		require.NoError(t, err)
		err = dec.Finish()
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		var derr *DecodeError
		require.ErrorAs(t, err, &derr)
	})

	t.Run("truncated prefix", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		_, _, _, err := dec.Push([]byte{0x0}, false)
		require.NoError(t, err)
		require.ErrorIs(t, dec.Finish(), io.ErrUnexpectedEOF)
	})

	t.Run("no input at all", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		require.ErrorIs(t, dec.Finish(), io.ErrUnexpectedEOF)
	})

	t.Run("truncation reported by Push with end", func(t *testing.T) {
		data := literalFieldWithoutNameReference.Data
		dec := NewIncrementalDecoder()
		_, _, _, err := dec.Push(data[:len(data)-1], true)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		// the error is sticky
		_, _, _, err = dec.Push(nil, false)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

func TestIncrementalDecoderInvalidHuffman(t *testing.T) {
	// a literal field without name reference, with a Huffman-encoded value
	// that has an invalid (non-EOS) padding at the end
	data := appendVarInt(nil, 3, 3)
	data[0] ^= 0x20
	data = append(data, []byte("foo")...)
	val := appendVarInt(nil, 7, 1)
	val[0] ^= 0x80         // Huffman-encoded
	val = append(val, 0x0) // 0x0 is not a valid EOS padding
	data = insertPrefix(append(data, val...))

	// the field section prefix is 2 bytes, the name takes 4 bytes
	const expectedOffset = 2

	t.Run("single push", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		_, _, _, err := dec.Push(data, true)
		require.Error(t, err)
		var derr *DecodeError
		require.ErrorAs(t, err, &derr)
		require.Equal(t, uint64(expectedOffset), derr.Offset)
	})

	t.Run("byte by byte", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		var buf []byte
		for i := 0; i < len(data)-1; i++ {
			buf = append(buf, data[i])
			consumed, _, _, err := dec.Push(buf, false)
			require.NoError(t, err)
			buf = buf[consumed:]
		}
		buf = append(buf, data[len(data)-1])
		_, _, _, err := dec.Push(buf, true)
		require.Error(t, err)
		var derr *DecodeError
		require.ErrorAs(t, err, &derr)
		require.Equal(t, uint64(expectedOffset), derr.Offset)
	})
}

func TestIncrementalDecoderVarintOverflow(t *testing.T) {
	// an overlong Required Insert Count: 0xff followed by 9 continuation bytes
	data := append([]byte{0xff}, make([]byte, 9)...)
	for i := 1; i < len(data); i++ {
		data[i] = 0xff
	}

	t.Run("single push", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		_, _, _, err := dec.Push(data, true)
		require.ErrorIs(t, err, errVarintOverflow)
		var derr *DecodeError
		require.ErrorAs(t, err, &derr)
		require.Zero(t, derr.Offset)
	})

	t.Run("byte by byte", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		var buf []byte
		for i := 0; i < len(data)-1; i++ {
			buf = append(buf, data[i])
			consumed, _, needMore, err := dec.Push(buf, false)
			require.NoError(t, err)
			require.True(t, needMore)
			buf = buf[consumed:]
		}
		buf = append(buf, data[len(data)-1])
		_, _, _, err := dec.Push(buf, false)
		require.ErrorIs(t, err, errVarintOverflow)
	})
}

func TestIncrementalDecoderLimits(t *testing.T) {
	data := literalFieldWithoutNameReference.Data
	var maxFieldSize, sectionSize uint64
	for _, hf := range literalFieldWithoutNameReference.Expected {
		size := uint64(len(hf.Name) + len(hf.Value))
		maxFieldSize = max(maxFieldSize, size)
		sectionSize += size
	}

	t.Run("encoded bytes", func(t *testing.T) {
		dec := NewIncrementalDecoder(WithMaxEncodedBytes(uint64(len(data) - 1)))
		_, _, _, err := dec.Push(data, true)
		require.ErrorIs(t, err, errEncodedSectionTooLarge)
		var derr *DecodeError
		require.ErrorAs(t, err, &derr)
		require.Equal(t, uint64(len(data)-1), derr.Offset)
	})

	t.Run("field size", func(t *testing.T) {
		dec := NewIncrementalDecoder(WithMaxFieldSize(maxFieldSize - 1))
		_, _, _, err := dec.Push(data, true)
		require.ErrorIs(t, err, errFieldTooLarge)
	})

	t.Run("section size", func(t *testing.T) {
		dec := NewIncrementalDecoder(WithMaxSectionSize(sectionSize - 1))
		_, fields, _, err := dec.Push(data, true)
		require.ErrorIs(t, err, errDecodedSectionTooLarge)
		// the first field was delivered before the limit was exceeded
		require.Equal(t, literalFieldWithoutNameReference.Expected[:1], fields)
	})

	t.Run("limits not exceeded", func(t *testing.T) {
		dec := NewIncrementalDecoder(
			WithMaxEncodedBytes(uint64(len(data))),
			WithMaxFieldSize(maxFieldSize),
			WithMaxSectionSize(sectionSize),
		)
		_, fields, _, err := dec.Push(data, true)
		require.NoError(t, err)
		require.Equal(t, literalFieldWithoutNameReference.Expected, fields)
	})
}

func TestIncrementalDecoderDynamicTableReferences(t *testing.T) {
	t.Run("non-zero required insert count", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		input := append(appendVarInt(nil, 8, 1), appendVarInt(nil, 7, 0)...)
		_, _, _, err := dec.Push(input, true)
		require.EqualError(t, err, "decoding error at offset 0: expected Required Insert Count to be zero")
	})

	t.Run("non-zero delta base", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		input := append(appendVarInt(nil, 8, 0), appendVarInt(nil, 7, 1)...)
		_, _, _, err := dec.Push(input, true)
		require.EqualError(t, err, "decoding error at offset 1: expected Base to be zero")
	})

	t.Run("indexed field referencing the dynamic table", func(t *testing.T) {
		dec := NewIncrementalDecoder()
		data := appendVarInt(nil, 6, 20)
		data[0] ^= 0x80 // don't set the static flag (0x40)
		_, _, _, err := dec.Push(insertPrefix(data), true)
		require.ErrorIs(t, err, errNoDynamicTable)
		var derr *DecodeError
		require.ErrorAs(t, err, &derr)
		require.Equal(t, uint64(2), derr.Offset)
	})
}

// TestIncrementalDecoderMatchesDecode checks that the incremental decoder
// delivers the same header fields as Decode.
func TestIncrementalDecoderMatchesDecode(t *testing.T) {
	for _, tc := range successTestcases {
		expected := decodeAll(t, NewDecoder().Decode(tc.Data))
		dec := NewIncrementalDecoder()
		hfs, _, err := pushAll(t, dec, [][]byte{tc.Data})
		require.NoError(t, err)
		require.Equal(t, expected, hfs)
	}
}

func TestIncrementalDecoderHuffmanRoundTrip(t *testing.T) {
	// make sure a valid Huffman-encoded string that spans chunk boundaries
	// is only decoded once complete
	data := literalFieldWithHuffmanEncoding.Data
	for i := 0; i <= len(data); i++ {
		dec := NewIncrementalDecoder()
		hfs, consumed, err := pushAll(t, dec, [][]byte{data[:i], data[i:]})
		require.NoError(t, err)
		require.Equal(t, len(data), consumed)
		require.Equal(t, literalFieldWithHuffmanEncoding.Expected, hfs)
	}
}

func TestDecodeErrorUnwrap(t *testing.T) {
	err := &DecodeError{Offset: 42, Err: io.ErrUnexpectedEOF}
	require.Equal(t, "decoding error at offset 42: unexpected EOF", err.Error())
	require.True(t, errors.Is(err, io.ErrUnexpectedEOF))
}
