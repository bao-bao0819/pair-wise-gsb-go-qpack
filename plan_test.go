package qpack

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/stretchr/testify/require"
)

// bruteFieldLen enumerates every legal representation for hf, independently
// computes the emitted bytes for the raw and Huffman variants of every
// literal string, and returns the minimum byte count and the number of
// candidates that attain it. It is written independently of the planner to
// cross-check PlanFieldSection.
func bruteFieldLen(hf HeaderField) int {
	var candidates []int
	// Indexed Field Line (1Txxxxxx, 6-bit prefix) and Literal Field Line With
	// Name Reference (01NTxxxx, 4-bit prefix): one candidate per matching
	// static table entry.
	for idx := range staticTableEntries {
		if staticTableEntries[idx].Name != hf.Name {
			continue
		}
		if staticTableEntries[idx].Value == hf.Value {
			candidates = append(candidates, varIntLen(6, uint64(idx)))
		}
		candidates = append(candidates, varIntLen(4, uint64(idx))+
			min(stringLen(7, len(hf.Value)), stringLen(7, int(hpack.HuffmanEncodeLength(hf.Value)))))
	}
	// Literal Field Line Without Name Reference (001Hxxxx, 3-bit name prefix).
	candidates = append(candidates,
		min(stringLen(3, len(hf.Name)), stringLen(3, int(hpack.HuffmanEncodeLength(hf.Name))))+
			min(stringLen(7, len(hf.Value)), stringLen(7, int(hpack.HuffmanEncodeLength(hf.Value)))),
	)
	minLen := candidates[0]
	for _, c := range candidates[1:] {
		if c < minLen {
			minLen = c
		}
	}
	return minLen
}

func TestPlanFieldSectionEmpty(t *testing.T) {
	plan := PlanFieldSection(nil)
	require.Equal(t, 2, plan.Len())

	buf := &bytes.Buffer{}
	n, err := plan.Encode(buf)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte{0x00, 0x00}, buf.Bytes())

	// An empty field section decodes to zero fields and has a legal prefix.
	require.Empty(t, decodeAll(t, NewDecoder().Decode(buf.Bytes())))
}

func TestPlanMatchesExhaustiveSearch(t *testing.T) {
	corpus := []HeaderField{
		{Name: ":method", Value: "GET"},   // indexed
		{Name: ":status", Value: "200"},   // indexed, duplicate :status name
		{Name: ":status", Value: "666"},   // name reference
		{Name: "set-cookie", Value: ""},   // name reference, index 14 (4-bit boundary)
		{Name: ":method", Value: "PATCH"}, // name reference, index 15 (4-bit boundary)
		{Name: "server", Value: "x"},
		{Name: "x-custom-header", Value: "value"},
		{Name: string(make([]byte, 7)), Value: ""},           // 3-bit name boundary, raw
		{Name: string(make([]byte, 8)), Value: ""},           // 3-bit name expansion
		{Name: "\xff\xff\xff\xff", Value: ""},                // Huffman longer than raw
		{Name: "x-custom", Value: string(make([]byte, 127))}, // 7-bit value boundary
		{Name: "x-custom", Value: string(make([]byte, 128))}, // 7-bit value expansion
		{Name: "date", Value: "Mon, 01 Jan 2024 00:00:00 GMT"},
	}
	for idx := range staticTableEntries {
		corpus = append(corpus, staticTableEntries[idx])
	}

	for _, hf := range corpus {
		t.Run(hf.Name+"/"+hf.Value, func(t *testing.T) {
			fp := planField(hf)
			want := bruteFieldLen(hf)
			require.Equal(t, want, fieldPlanLen(fp))

			plan := PlanFieldSection([]HeaderField{hf})
			require.Equal(t, 2+want, plan.Len())

			buf := &bytes.Buffer{}
			n, err := plan.Encode(buf)
			require.NoError(t, err)
			require.Equal(t, plan.Len(), n)
			require.Len(t, buf.Bytes(), plan.Len())
			require.Equal(t, []HeaderField{hf}, decodeAll(t, NewDecoder().Decode(buf.Bytes())))
		})
	}
}

// Random small samples: enumerate every legal candidate (full indexed
// references, name references at every matching index, and the literal with
// every raw/Huffman combination) and verify the planner picks its minimum,
// deterministically, and that the encoding round-trips.
func TestPlanRandomSmallSamples(t *testing.T) {
	const alphabet = "a0/: \xff\x00"
	names := []string{":method", ":status", "set-cookie", "x-custom", "cookie"}
	rng := rand.New(rand.NewPCG(1, 2))
	randomString := func() string {
		b := make([]byte, rng.IntN(12))
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(b)
	}

	for range 500 {
		hf := HeaderField{Name: names[rng.IntN(len(names))], Value: randomString()}
		// Sometimes corrupt the name so only the literal representation is
		// possible.
		if rng.IntN(3) == 0 {
			hf.Name = "x-" + randomString()
		}

		want := bruteFieldLen(hf)
		fp := planField(hf)
		require.Equal(t, want, fieldPlanLen(fp), "field %+v", hf)
		require.Equal(t, fp, planField(hf))

		buf := &bytes.Buffer{}
		_, err := PlanFieldSection([]HeaderField{hf}).Encode(buf)
		require.NoError(t, err)
		require.Equal(t, []HeaderField{hf}, decodeAll(t, NewDecoder().Decode(buf.Bytes())))
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	hfs := []HeaderField{
		{Name: ":status", Value: "666"},
		{Name: "x-custom", Value: "\xff\xff"},
		{Name: ":method", Value: "GET"},
	}
	first := PlanFieldSection(hfs)
	for range 20 {
		got := PlanFieldSection(hfs)
		require.Equal(t, first.fields, got.fields)
		require.Equal(t, first.Len(), got.Len())
	}
}

func TestPlanPreservesOrderAndDuplicates(t *testing.T) {
	hfs := []HeaderField{
		{Name: "x-a", Value: "1"},
		{Name: ":status", Value: "200"},
		{Name: "x-a", Value: "1"}, // duplicate
		{Name: ":status", Value: "200"},
		{Name: "x-b", Value: ""},
	}
	plan := PlanFieldSection(hfs)

	buf := &bytes.Buffer{}
	_, err := plan.Encode(buf)
	require.NoError(t, err)
	require.Len(t, buf.Bytes(), plan.Len())
	require.Equal(t, hfs, decodeAll(t, NewDecoder().Decode(buf.Bytes())))
}

func TestPlanEstimateMatchesEncoding(t *testing.T) {
	hfs := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/index.html"},
		{Name: "x-custom", Value: "raw\xff\xff"},
	}
	plan := PlanFieldSection(hfs)

	buf := &bytes.Buffer{}
	_, err := plan.Encode(buf)
	require.NoError(t, err)
	require.Len(t, buf.Bytes(), plan.Len())
}

func TestPlanEncodePropagatesWriterError(t *testing.T) {
	plan := PlanFieldSection([]HeaderField{{Name: "x-custom", Value: "v"}})
	out := &errWriter{fail: true}
	n, err := plan.Encode(out)
	require.Error(t, err)
	require.Zero(t, n)
	require.Empty(t, out.Bytes())
}

func TestEncodeFieldSectionBudget(t *testing.T) {
	hfs := []HeaderField{{Name: "x-custom", Value: "hello"}}
	required := PlanFieldSection(hfs).Len()

	t.Run("fits exactly", func(t *testing.T) {
		buf := &bytes.Buffer{}
		n, err := EncodeFieldSection(buf, hfs, required)
		require.NoError(t, err)
		require.Equal(t, required, n)
		require.Len(t, buf.Bytes(), required)
	})

	t.Run("too large", func(t *testing.T) {
		buf := &bytes.Buffer{}
		n, err := EncodeFieldSection(buf, hfs, required-1)
		require.Error(t, err)
		require.Zero(t, n)
		require.Empty(t, buf.Bytes())

		var tooLong *FieldSectionTooLongError
		require.True(t, errors.As(err, &tooLong))
		require.Equal(t, required, tooLong.Required)
		require.Equal(t, required-1, tooLong.Budget)
	})

	t.Run("empty section requires a prefix", func(t *testing.T) {
		buf := &bytes.Buffer{}
		n, err := EncodeFieldSection(buf, nil, 1)
		require.Error(t, err)
		require.Zero(t, n)
		require.Empty(t, buf.Bytes())

		var tooLong *FieldSectionTooLongError
		require.True(t, errors.As(err, &tooLong))
		require.Equal(t, 2, tooLong.Required)
	})
}

// 6-bit prefix boundary: static indices 62 and below fit in one byte, index
// 63 requires a continuation byte. Entry 63 is :status 100.
func TestSixBitPrefixBoundary(t *testing.T) {
	below := HeaderField{Name: "x-xss-protection", Value: "1; mode=block"} // index 62
	at := HeaderField{Name: ":status", Value: "100"}                       // index 63
	require.Equal(t, 1, fieldPlanLen(planField(below)))
	require.Equal(t, 2, fieldPlanLen(planField(at)))
	require.Equal(t, repIndexed, planField(below).rep)
	require.Equal(t, repIndexed, planField(at).rep)
}

// 4-bit prefix boundary: name references to index 14 fit in one byte, index
// 15 needs a continuation byte.
func TestFourBitPrefixBoundary(t *testing.T) {
	below := HeaderField{Name: "set-cookie", Value: "abc"} // name index 14
	at := HeaderField{Name: ":method", Value: "PATCH"}     // name index 15

	fpBelow := planField(below)
	fpAt := planField(at)
	require.Equal(t, repNameReference, fpBelow.rep)
	require.Equal(t, repNameReference, fpAt.rep)
	require.Equal(t, uint64(14), fpBelow.idx)
	require.Equal(t, uint64(15), fpAt.idx)
	require.Equal(t, varIntLen(4, 14), 1)
	require.Equal(t, varIntLen(4, 15), 2)

	// Even after the expansion the name reference must beat the literal name.
	require.Equal(t, varIntLen(4, 15)+stringLen(7, fpAt.val.rawLen), fieldPlanLen(fpAt))
}

// 3-bit prefix boundary for the literal name length: a 6-byte payload fits,
// 7 (= 2^3 - 1) and above need a continuation byte. The name is not in the
// static table.
func TestThreeBitPrefixBoundary(t *testing.T) {
	require.Equal(t, 7, stringLen(3, 6))
	require.Equal(t, 9, stringLen(3, 7))
	require.Equal(t, 10, stringLen(3, 8))

	// "abcdefg" Huffman-encodes to 5 bytes, which stays below the boundary.
	hf := HeaderField{Name: "abcdefg", Value: ""}
	fp := planField(hf)
	require.Equal(t, repLiteral, fp.rep)
	require.True(t, fp.name.huffman)
	require.Equal(t, 5, fp.name.rawLen)
	require.Equal(t, stringLen(3, 5)+stringLen(7, 0), fieldPlanLen(fp))
}

// 7-bit prefix boundary for the literal value length: a 126-byte payload
// fits, 127 (= 2^7 - 1) and above need a continuation byte.
func TestSevenBitPrefixBoundary(t *testing.T) {
	require.Equal(t, 127, stringLen(7, 126))
	require.Equal(t, 129, stringLen(7, 127))
	require.Equal(t, 130, stringLen(7, 128))

	// NUL bytes expand under Huffman (4 bytes each), so the raw representation
	// is chosen and exercises the boundary exactly.
	below := HeaderField{Name: "x-custom", Value: string(make([]byte, 126))}
	at := HeaderField{Name: "x-custom", Value: string(make([]byte, 127))}
	require.False(t, planField(below).val.huffman)
	require.Equal(t, 126, planField(below).val.rawLen)
	require.Equal(t, 127, planField(at).val.rawLen)
}

// Bytes outside the low-value Huffman alphabet expand under Huffman, so raw
// must be chosen. An ordinary ASCII string must still use Huffman.
func TestPlanChoosesRawWhenHuffmanIsLonger(t *testing.T) {
	hf := HeaderField{Name: "\xff\xff\xff\xff", Value: "\xff\xff"}
	require.Greater(t, hpack.HuffmanEncodeLength(hf.Name), uint64(len(hf.Name)))

	fp := planField(hf)
	require.Equal(t, repLiteral, fp.rep)
	require.False(t, fp.name.huffman)
	require.False(t, fp.val.huffman)

	ascii := HeaderField{Name: "custom-header", Value: "some-ordinary-value"}
	require.Less(t, hpack.HuffmanEncodeLength(ascii.Name), uint64(len(ascii.Name)))
	require.True(t, planField(ascii).name.huffman)
	require.True(t, planField(ascii).val.huffman)

	// The raw encoding round-trips through the decoder.
	buf := &bytes.Buffer{}
	_, err := PlanFieldSection([]HeaderField{hf}).Encode(buf)
	require.NoError(t, err)
	require.Equal(t, []HeaderField{hf}, decodeAll(t, NewDecoder().Decode(buf.Bytes())))
}

// :status and :method appear at multiple static indices. The planner must
// always resolve them to the smallest matching index, even when only the name
// matches.
func TestPlanResolvesDuplicateStaticNames(t *testing.T) {
	require.Equal(t, uint64(25), planField(HeaderField{Name: ":status", Value: "200"}).idx)
	require.Equal(t, repIndexed, planField(HeaderField{Name: ":status", Value: "200"}).rep)

	fp := planField(HeaderField{Name: ":status", Value: "666"})
	require.Equal(t, repNameReference, fp.rep)
	require.Equal(t, uint64(24), fp.idx) // first :status entry, not 63

	fp = planField(HeaderField{Name: ":method", Value: "PATCH"})
	require.Equal(t, repNameReference, fp.rep)
	require.Equal(t, uint64(15), fp.idx) // first :method entry

	fp = planField(HeaderField{Name: ":method", Value: "PUT"})
	require.Equal(t, repIndexed, fp.rep)
	require.Equal(t, uint64(21), fp.idx)

	fp = planField(HeaderField{Name: "access-control-allow-headers", Value: "x-unknown"})
	require.Equal(t, repNameReference, fp.rep)
	require.Equal(t, uint64(33), fp.idx) // duplicated name, first occurrence
}

// When several representations have identical costs, the documented order is
// indexed < name reference < literal, and raw < Huffman for strings.
func TestPlanTieBreaking(t *testing.T) {
	// A full match is always at least as cheap as a name reference, and wins
	// ties.
	fp := planField(HeaderField{Name: ":method", Value: "GET"})
	require.Equal(t, repIndexed, fp.rep)

	// A single printable byte has a one-byte Huffman encoding, so raw and
	// Huffman are tied; raw must win.
	require.Equal(t, uint64(1), hpack.HuffmanEncodeLength("0"))
	require.False(t, planString("0").huffman)

	// Representation order on equal cost: indexed < name reference < literal.
	// Build three two-byte plans: the indexed field uses an expanded 6-bit
	// index (63); the name reference uses a one-byte 4-bit index (14) with an
	// empty value; the literal uses an empty name and an empty value.
	indexed := fieldPlan{rep: repIndexed, idx: 63}
	nameRef := fieldPlan{rep: repNameReference, idx: 14}
	literal := fieldPlan{rep: repLiteral}
	require.Equal(t, 2, fieldPlanLen(indexed))
	require.Equal(t, 2, fieldPlanLen(nameRef))
	require.Equal(t, 2, fieldPlanLen(literal))
	require.True(t, cheaperField(indexed, nameRef))
	require.True(t, cheaperField(nameRef, literal))
	require.True(t, cheaperField(indexed, literal))
	require.False(t, cheaperField(nameRef, indexed))

	// Equal representation and equal cost: the smaller index wins.
	require.True(t, cheaperField(fieldPlan{rep: repIndexed, idx: 2}, fieldPlan{rep: repIndexed, idx: 63}))
}
