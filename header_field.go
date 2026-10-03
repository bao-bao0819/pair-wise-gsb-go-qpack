package qpack

// A HeaderField is a name-value pair. Both the name and value are
// treated as opaque sequences of octets.
type HeaderField struct {
	Name  string
	Value string

	// NeverIndex indicates that this field was received with the Never-Index
	// bit (N) set in its literal representation, or that the local field
	// policy decided that the field must never be indexed when re-encoded.
	// It is only meaningful for literal header field representations;
	// indexed representations do not carry the N bit.
	NeverIndex bool
}

// IsPseudo reports whether the header field is an HTTP3 pseudo header.
// That is, it reports whether it starts with a colon.
// It is not otherwise guaranteed to be a valid pseudo header field,
// though.
func (hf HeaderField) IsPseudo() bool {
	return len(hf.Name) != 0 && hf.Name[0] == ':'
}
