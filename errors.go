package qpack

import (
	"errors"
	"fmt"
)

// ErrDecompressionFailed corresponds to the QPACK_DECOMPRESSION_FAILED
// connection error (0x02). It is returned for malformed or invalid field
// sections.
var ErrDecompressionFailed = errors.New("qpack: decompression failed")

// ErrEncoderStreamError corresponds to the QPACK_ENCODER_STREAM_ERROR
// connection error (0x03). It is returned for malformed or invalid encoder
// stream instructions.
var ErrEncoderStreamError = errors.New("qpack: encoder stream error")

// ErrBlockedStreamsExceeded corresponds to QPACK_DECOMPRESSION_FAILED, raised
// when a field section references dynamic table entries that have not yet been
// inserted while the number of blocked field sections is already at the
// configured limit.
var ErrBlockedStreamsExceeded = errors.New("qpack: blocked streams limit exceeded")

// errSectionBlocked is internal: a field section references dynamic table
// entries that have not been inserted yet.
var errSectionBlocked = errors.New("qpack: field section blocked on missing inserts")

// An InvalidIndexError indicates that a field section or an encoder stream
// instruction referenced a static or dynamic table entry that does not exist
// (or has already been evicted). When returned while processing encoder
// stream instructions, it maps to QPACK_ENCODER_STREAM_ERROR; otherwise it
// maps to QPACK_DECOMPRESSION_FAILED.
type InvalidIndexError struct {
	// Index is the offending index.
	Index uint64
	// Dynamic reports whether the index referenced the dynamic table.
	// When false, it referenced the static table.
	Dynamic bool
	// OnEncoderStream reports whether the error occurred while processing
	// encoder stream instructions.
	OnEncoderStream bool
}

func (e InvalidIndexError) Error() string {
	table := "static"
	if e.Dynamic {
		table = "dynamic"
	}
	return fmt.Sprintf("qpack: invalid %s table index %d", table, e.Index)
}

func (e InvalidIndexError) Unwrap() error {
	if e.OnEncoderStream {
		return ErrEncoderStreamError
	}
	return ErrDecompressionFailed
}

// InvalidCapacityError indicates that the encoder attempted to set a dynamic
// table capacity larger than the value advertised to the peer via the HTTP/3
// SETTINGS_QPACK_MAX_TABLE_CAPACITY parameter. It maps to
// QPACK_ENCODER_STREAM_ERROR.
type InvalidCapacityError struct {
	// Requested is the capacity requested by the encoder.
	Requested uint64
	// Maximum is the capacity advertised to the encoder.
	Maximum uint64
}

func (e InvalidCapacityError) Error() string {
	return fmt.Sprintf("qpack: requested dynamic table capacity %d exceeds maximum %d", e.Requested, e.Maximum)
}

func (e InvalidCapacityError) Unwrap() error { return ErrEncoderStreamError }
