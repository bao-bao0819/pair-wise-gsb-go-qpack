package qpack

// A HeaderField is a name-value pair. Both the name and value are
// treated as opaque sequences of octets.
type HeaderField struct {
	Name  string
	Value string
	// Sensitive indicates that the field must not be indexed by an
	// intermediary. It corresponds to the QPACK Never Indexed (N) bit.
	// When decoding, it is set if the peer sent the field with the N bit
	// set in either of the two literal representations.
	// When encoding, sensitive fields are always encoded using a literal
	// representation carrying the N bit, even if the field fully matches
	// a static table entry.
	Sensitive bool
}

// IsPseudo reports whether the header field is an HTTP3 pseudo header.
// That is, it reports whether it starts with a colon.
// It is not otherwise guaranteed to be a valid pseudo header field,
// though.
func (hf HeaderField) IsPseudo() bool {
	return len(hf.Name) != 0 && hf.Name[0] == ':'
}
