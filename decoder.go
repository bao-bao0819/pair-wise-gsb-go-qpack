package qpack

import (
	"errors"
	"fmt"
	"io"
)

// An invalidIndexError is returned when decoding encounters an invalid index
// (e.g., an index that is out of bounds for the static table).
type invalidIndexError int

func (e invalidIndexError) Error() string {
	return fmt.Sprintf("invalid indexed representation index %d", int(e))
}

var errNoDynamicTable = errors.New("no dynamic table")

// A Decoder decodes QPACK header blocks.
// A Decoder can be reused to decode multiple header blocks on different streams
// on the same connection (e.g., headers then trailers).
// This will be useful when dynamic table support is added.
type Decoder struct{}

// DecodeFunc is a function that decodes the next header field from a header block.
// It should be called repeatedly until it returns io.EOF.
// It returns io.EOF when all header fields have been decoded.
// Any error other than io.EOF indicates a decoding error.
type DecodeFunc func() (HeaderField, error)

// NewDecoder returns a new Decoder.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode returns a function that decodes header fields from the given header block.
// It is a convenience wrapper around StreamDecoder for callers that have
// already buffered the entire field section.
func (d *Decoder) Decode(p []byte) DecodeFunc {
	sd := NewStreamDecoder(Limits{})
	_, hfs, _, err := sd.Push(p, true)
	if err != nil {
		// Unwrap the ParseError to preserve the historical error values.
		var perr *ParseError
		if errors.As(err, &perr) {
			err = perr.Err
		}
		return func() (HeaderField, error) { return HeaderField{}, err }
	}
	var i int
	return func() (HeaderField, error) {
		if i >= len(hfs) {
			return HeaderField{}, io.EOF
		}
		hf := hfs[i]
		i++
		return hf, nil
	}
}
