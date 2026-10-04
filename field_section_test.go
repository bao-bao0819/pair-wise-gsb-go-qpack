package qpack

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/stretchr/testify/require"
)

type expectedCandidate struct {
	representation fieldRepresentation
	staticIndex    uint8
	nameHuffman    bool
	valueHuffman   bool
	length         int
}

func plannedStringLength(t *testing.T, value string, prefixBits uint8, useHuffman bool) int {
	t.Helper()
	if useHuffman {
		length := int(hpack.HuffmanEncodeLength(value))
		return length + varIntLength(prefixBits, uint64(length))
	}
	return len(value) + varIntLength(prefixBits, uint64(len(value)))
}

func enumerateFieldCandidates(t *testing.T, field HeaderField) []expectedCandidate {
	t.Helper()

	candidates := make([]expectedCandidate, 0, len(staticTableEntries)*4+4)
	for i, entry := range staticTableEntries {
		if entry.Name == field.Name && entry.Value == field.Value {
			candidates = append(candidates, expectedCandidate{
				representation: indexedRepresentation,
				staticIndex:    uint8(i),
				length:         varIntLength(6, uint64(i)),
			})
		}
	}

	for i, entry := range staticTableEntries {
		if entry.Name != field.Name {
			continue
		}
		candidates = append(candidates, expectedCandidate{
			representation: literalNameReferenceRepresentation,
			staticIndex:    uint8(i),
			valueHuffman:   false,
			length:         varIntLength(4, uint64(i)) + plannedStringLength(t, field.Value, 7, false),
		})
		candidates = append(candidates, expectedCandidate{
			representation: literalNameReferenceRepresentation,
			staticIndex:    uint8(i),
			valueHuffman:   true,
			length:         varIntLength(4, uint64(i)) + plannedStringLength(t, field.Value, 7, true),
		})
	}

	for _, nameHuffman := range []bool{false, true} {
		for _, valueHuffman := range []bool{false, true} {
			candidates = append(candidates, expectedCandidate{
				representation: literalNameRepresentation,
				nameHuffman:    nameHuffman,
				valueHuffman:   valueHuffman,
				length: plannedStringLength(t, field.Name, 3, nameHuffman) +
					plannedStringLength(t, field.Value, 7, valueHuffman),
			})
		}
	}

	return candidates
}

func bestExpectedCandidate(candidates []expectedCandidate) expectedCandidate {
	best := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.length < best.length {
			best = candidate
		}
	}
	return best
}

func requirePlannedFieldMatches(t *testing.T, field HeaderField, expected plannedField) {
	t.Helper()
	plan := PlanFields([]HeaderField{field})
	require.Len(t, plan.fields, 1)
	actual := plan.fields[0]
	require.Equal(t, expected.representation, actual.representation)
	require.Equal(t, expected.staticIndex, actual.staticIndex)
	require.Equal(t, expected.name.huffman, actual.name.huffman)
	require.Equal(t, expected.value.huffman, actual.value.huffman)
	require.Equal(t, expected.length, actual.length)
	require.Equal(t, headerBlockPrefixSize+expected.length, plan.Len())
}

func TestPlanFieldsSelectsMinimumExhaustiveCandidate(t *testing.T) {
	fields := []HeaderField{
		{Name: ":status", Value: "204"},
		{Name: ":status", Value: "666"},
		{Name: ":method", Value: "DELETE"},
		{Name: ":method", Value: "PATCH"},
		{Name: "set-cookie", Value: "session=1"},
		{Name: "foo", Value: "bar"},
		{Name: "\x00", Value: "\x00"},
		{Name: "\x00", Value: "lorem"},
		{Name: "lorem", Value: "\x00"},
		{Name: strings.Repeat("\x00", 7), Value: ""},
		{Name: strings.Repeat("\x00", 8), Value: ""},
		{Name: ":method", Value: strings.Repeat("\x00", 127)},
		{Name: ":method", Value: strings.Repeat("\x00", 128)},
	}

	for i := range staticTableEntries {
		fields = append(fields, staticTableEntries[i])
	}

	for _, field := range fields {
		t.Run(field.Name+"="+field.Value, func(t *testing.T) {
			candidates := enumerateFieldCandidates(t, field)
			require.NotEmpty(t, candidates)
			best := bestExpectedCandidate(candidates)

			planned := planField(field)
			require.Equal(t, best.length, planned.length)
			require.Equal(t, best.representation, planned.representation)
			require.Equal(t, best.staticIndex, planned.staticIndex)
			require.Equal(t, best.nameHuffman, planned.name.huffman)
			require.Equal(t, best.valueHuffman, planned.value.huffman)
		})
	}
}

func TestPlanFieldsIntegerPrefixBoundaries(t *testing.T) {
	require.Equal(t, 1, varIntLength(3, 6))
	require.Equal(t, 2, varIntLength(3, 7))
	require.Equal(t, 2, varIntLength(3, 8))

	require.Equal(t, 1, varIntLength(4, 14))
	require.Equal(t, 2, varIntLength(4, 15))
	require.Equal(t, 2, varIntLength(4, 16))

	require.Equal(t, 1, varIntLength(6, 62))
	require.Equal(t, 2, varIntLength(6, 64))
	require.Equal(t, 2, varIntLength(6, 63))

	require.Equal(t, 1, varIntLength(7, 126))
	require.Equal(t, 2, varIntLength(7, 127))
	require.Equal(t, 2, varIntLength(7, 128))

	requirePlannedFieldMatches(t, staticTableEntries[62], plannedField{
		representation: indexedRepresentation,
		staticIndex:    62,
		value:          plannedString{},
		length:         1,
	})
	requirePlannedFieldMatches(t, staticTableEntries[63], plannedField{
		representation: indexedRepresentation,
		staticIndex:    63,
		length:         2,
	})
	requirePlannedFieldMatches(t, staticTableEntries[64], plannedField{
		representation: indexedRepresentation,
		staticIndex:    64,
		length:         2,
	})

	shortName := HeaderField{Name: strings.Repeat("\x00", 7), Value: ""}
	requirePlannedFieldMatches(t, shortName, plannedField{
		representation: literalNameRepresentation,
		name:           plannedString{length: 9},
		value:          plannedString{length: 1},
		length:         10,
	})
	longName := HeaderField{Name: strings.Repeat("\x00", 8), Value: ""}
	requirePlannedFieldMatches(t, longName, plannedField{
		representation: literalNameRepresentation,
		name:           plannedString{length: 10},
		value:          plannedString{length: 1},
		length:         11,
	})

	shortValue := HeaderField{Name: ":method", Value: strings.Repeat("\x00", 127)}
	requirePlannedFieldMatches(t, shortValue, plannedField{
		representation: literalNameReferenceRepresentation,
		staticIndex:    15,
		value:          plannedString{length: 128},
		length:         131,
	})
	longValue := HeaderField{Name: ":method", Value: strings.Repeat("\x00", 128)}
	requirePlannedFieldMatches(t, longValue, plannedField{
		representation: literalNameReferenceRepresentation,
		staticIndex:    15,
		value:          plannedString{length: 130},
		length:         132,
	})
}

func TestPlanFieldsUsesAllDuplicateNameReferencesAndDeterministicTies(t *testing.T) {
	require.Equal(t, []uint8{24, 25, 26, 27, 28, 63, 64, 65, 66, 67, 68, 69, 70, 71}, staticTableNameIndices[":status"])

	duplicateName := HeaderField{Name: ":status", Value: "666"}
	requirePlannedFieldMatches(t, duplicateName, plannedField{
		representation: literalNameReferenceRepresentation,
		staticIndex:    24,
		value:          plannedString{huffman: false, length: 4},
		length:         6,
	})

	require.Equal(t, uint64(1), hpack.HuffmanEncodeLength(";"))
	equalString := HeaderField{Name: "cookie", Value: ";"}
	requirePlannedFieldMatches(t, equalString, plannedField{
		representation: literalNameReferenceRepresentation,
		staticIndex:    5,
		value:          plannedString{huffman: false, length: 2},
		length:         3,
	})
	equalNameAndValue := HeaderField{Name: ";", Value: ";"}
	requirePlannedFieldMatches(t, equalNameAndValue, plannedField{
		representation: literalNameRepresentation,
		name:           plannedString{huffman: false, length: 2},
		value:          plannedString{huffman: false, length: 2},
		length:         4,
	})

	first := PlanFields([]HeaderField{duplicateName, equalString, equalNameAndValue})
	second := PlanFields([]HeaderField{duplicateName, equalString, equalNameAndValue})
	require.Equal(t, first, second)
}

func TestPlanFieldsChoosesRawWhenHuffmanIsLonger(t *testing.T) {
	field := HeaderField{Name: "\x00", Value: "\x00"}
	require.Equal(t, uint64(2), hpack.HuffmanEncodeLength("\x00"))
	requirePlannedFieldMatches(t, field, plannedField{
		representation: literalNameRepresentation,
		name:           plannedString{huffman: false, length: 2},
		value:          plannedString{huffman: false, length: 2},
		length:         4,
	})

	compressed := HeaderField{Name: "lorem", Value: "ipsum"}
	requirePlannedFieldMatches(t, compressed, plannedField{
		representation: literalNameRepresentation,
		name:           plannedString{huffman: true, length: 5},
		value:          plannedString{huffman: true, length: 5},
		length:         10,
	})

	nameRawValueHuffman := HeaderField{Name: "\x00", Value: "lorem"}
	requirePlannedFieldMatches(t, nameRawValueHuffman, plannedField{
		representation: literalNameRepresentation,
		name:           plannedString{huffman: false, length: 2},
		value:          plannedString{huffman: true, length: 5},
		length:         7,
	})
	nameHuffmanValueRaw := HeaderField{Name: "lorem", Value: "\x00"}
	requirePlannedFieldMatches(t, nameHuffmanValueRaw, plannedField{
		representation: literalNameRepresentation,
		name:           plannedString{huffman: true, length: 5},
		value:          plannedString{huffman: false, length: 2},
		length:         7,
	})
}

func TestWritePlanPreservesOrderDuplicatesAndDecodes(t *testing.T) {
	fields := []HeaderField{
		{Name: ":status", Value: "204"},
		{Name: "foo", Value: "bar"},
		{Name: ":status", Value: "204"},
		{Name: "\x00", Value: "\x00"},
	}
	plan := PlanFields(fields)

	output := &bytes.Buffer{}
	encoder := NewEncoder(output)
	n, err := encoder.WritePlan(plan, plan.Len())
	require.NoError(t, err)
	require.Equal(t, plan.Len(), n)
	require.Len(t, output.Bytes(), plan.Len())

	decoded := decodeAll(t, NewDecoder().Decode(output.Bytes()))
	require.Equal(t, fields, decoded)

	again := &bytes.Buffer{}
	_, err = NewEncoder(again).WriteFields(fields, plan.Len())
	require.NoError(t, err)
	require.Equal(t, output.Bytes(), again.Bytes())
}

func TestWritePlanEmptyFieldSectionUsesLegalPrefix(t *testing.T) {
	plan := PlanFields(nil)
	require.Equal(t, headerBlockPrefixSize, plan.Len())

	output := &bytes.Buffer{}
	n, err := NewEncoder(output).WritePlan(plan, plan.Len())
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte{0, 0}, output.Bytes())

	emptyOutput := &bytes.Buffer{}
	n, err = NewEncoder(emptyOutput).WritePlan(plan, 1)
	require.ErrorIs(t, err, ErrFieldSectionTooLarge)
	require.Equal(t, 2, n)
	require.Empty(t, emptyOutput.Bytes())

	decode := NewDecoder().Decode(output.Bytes())
	_, err = decode()
	require.ErrorIs(t, err, io.EOF)
}

func TestWritePlanRejectsBudgetBeforeWriting(t *testing.T) {
	fields := []HeaderField{{Name: "foo", Value: "bar"}}
	plan := PlanFields(fields)

	output := &errWriter{fail: true}
	n, err := NewEncoder(output).WritePlan(plan, plan.Len()-1)
	require.ErrorIs(t, err, ErrFieldSectionTooLarge)
	require.Equal(t, plan.Len(), n)
	require.Empty(t, output.Bytes())

	output.fail = false
	n, err = NewEncoder(output).WriteFields(fields, plan.Len())
	require.NoError(t, err)
	require.Equal(t, plan.Len(), n)
}
