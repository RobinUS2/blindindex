package blindindex

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"
)

// filterFormat is the on-disk format version. It is stored in every filter so that a future
// change to the layout can be detected rather than misread.
const filterFormat uint16 = 2

// headerBytes is the fixed-size prefix of a marshalled filter:
// format(2) + keyVersion(4) + bits(4) + hashCount(1).
const headerBytes = 2 + 4 + 4 + 1

// Filter is one document's searchable representation.
//
// It carries the key version it was built under so that a mismatched test fails loudly
// instead of returning a false negative that looks like an honest miss.
//
// # Bit layout
//
// Bits are packed so that bit i lives in byte i/8 at shift i%8, which is exactly
// PostgreSQL's `get_bit(bytea, i)` convention. That is deliberate: it lets a caller push
// membership testing into the database as a WHERE clause instead of transferring every
// filter out of it. Changing this layout breaks that, so it is part of the format contract,
// not an implementation detail.
type Filter struct {
	KeyVersion uint32

	bits      uint
	hashCount uint
	data      []byte
}

func newFilter(nbits, hashCount uint, keyVersion uint32) Filter {
	return Filter{
		KeyVersion: keyVersion,
		bits:       nbits,
		hashCount:  hashCount,
		data:       make([]byte, (nbits+7)/8),
	}
}

func (f *Filter) setBit(i uint) { f.data[i/8] |= 1 << (i % 8) }

func (f Filter) testBit(i uint) bool { return f.data[i/8]&(1<<(i%8)) != 0 }

func (f *Filter) add(d Digest) {
	for _, p := range Positions(d, f.bits, f.hashCount) {
		f.setBit(p)
	}
}

func (f Filter) count() uint {
	var n uint
	for _, b := range f.data {
		n += uint(bits.OnesCount8(b))
	}
	return n
}

// Positions returns the bit positions a digest sets, in ascending order.
//
// This is the whole reason a caller can push membership testing into a datastore rather than
// loading filters out of it. A Bloom test is k bit lookups at known offsets, and most stores
// can express that directly. In PostgreSQL:
//
//	WHERE get_bit(blind_filter, 91) = 1 AND get_bit(blind_filter, 2207) = 1 AND ...
//
// At a few thousand documents, shipping every filter to the application per query costs far
// more than the test itself does.
//
// Positions derive from the digest alone, so they are stable across processes and safe to
// embed in a query. They reveal nothing without the key, because the digest does not.
//
// Pass the geometry the filters were built with. Positions computed for a different m or k
// test the wrong bits.
func Positions(d Digest, nbits, hashCount uint) []uint {
	if nbits == 0 || hashCount == 0 {
		return nil
	}
	// Double hashing: two independent 64-bit values taken from the digest, combined as
	// h1 + i*h2. Kirsch and Mitzenmacher showed this gives the same false-positive behaviour
	// as k independent hash functions, and it means the digest is the only source of
	// randomness, so Positions and the filter can never disagree.
	h1 := binary.BigEndian.Uint64(d[0:8])
	h2 := binary.BigEndian.Uint64(d[8:16])
	if h2 == 0 {
		h2 = 1 // a zero step would set the same bit k times
	}
	seen := make(map[uint]struct{}, hashCount)
	out := make([]uint, 0, hashCount)
	for i := uint64(0); i < uint64(hashCount); i++ {
		p := uint((h1 + i*h2) % uint64(nbits))
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// Positions returns the bit positions this filter tests for a digest, using its own geometry.
// Prefer this over the package-level function when you already hold a filter.
func (f Filter) Positions(d Digest) []uint { return Positions(d, f.bits, f.hashCount) }

// TestPositions reports whether every given bit position is set.
//
// It is the in-process equivalent of a pushed-down predicate, so a caller with both paths can
// prove they agree on the same input rather than hoping.
func (f Filter) TestPositions(positions []uint) bool {
	if len(f.data) == 0 || len(positions) == 0 {
		return false
	}
	for _, p := range positions {
		if p >= f.bits || !f.testBit(p) {
			return false
		}
	}
	return true
}

// Bits reports the filter size m.
func (f Filter) Bits() uint { return f.bits }

// HashCount reports k, the number of positions set per token.
func (f Filter) HashCount() uint { return f.hashCount }

// SetBits reports how many bits are set. After Build this is the configured target density
// for every document regardless of length, which is the property that stops the filter
// leaking document size.
func (f Filter) SetBits() uint { return f.count() }

// Bytes returns the raw bit array, for storing in a datastore column that the pushed-down
// predicate will read. The slice is a copy; mutating it does not affect the filter.
func (f Filter) Bytes() []byte {
	cp := make([]byte, len(f.data))
	copy(cp, f.data)
	return cp
}

// MayContainAll reports whether every queried digest is present.
//
// "May" is the operative word. False positives are inherent to the structure, so a true
// result means the document is a candidate worth confirming, never that it definitely
// contains the terms. A false result is definitive: the document does not contain them,
// unless the vocabulary policy discarded them at index time.
func (f Filter) MayContainAll(qd QueryDigests) (bool, error) {
	return f.MayContainAtLeast(qd, len(qd.Digests))
}

// MayContainAtLeast reports whether at least n of the queried digests are present.
//
// This exists because requiring every term is strict, and a caller whose goal is finding
// more candidates rather than exact matches may prefer a partial match. Loosening n costs
// only additional false positives.
//
// n <= 0 is treated as 1. An empty query matches nothing, because treating "no terms" as
// "matches everything" would turn an analysis failure into a silent full-corpus scan.
func (f Filter) MayContainAtLeast(qd QueryDigests, n int) (bool, error) {
	if qd.KeyVersion != f.KeyVersion {
		return false, fmt.Errorf("%w: filter is version %d, query digests are version %d",
			ErrKeyVersionMismatch, f.KeyVersion, qd.KeyVersion)
	}
	if len(qd.Digests) == 0 {
		return false, nil
	}
	if n <= 0 {
		n = 1
	}
	if n > len(qd.Digests) {
		n = len(qd.Digests)
	}
	hits := 0
	for _, d := range qd.Digests {
		if f.TestPositions(f.Positions(d)) {
			hits++
			if hits >= n {
				return true, nil
			}
		}
	}
	return false, nil
}

// MarshalBinary renders the filter for storage. Output is deterministic: the same document,
// key and geometry always produce identical bytes, which makes rebuilds diffable and makes
// "did this change?" answerable without decrypting anything.
func (f Filter) MarshalBinary() ([]byte, error) {
	if len(f.data) == 0 {
		return nil, fmt.Errorf("%w: filter is not initialised", ErrBadFilter)
	}
	out := make([]byte, headerBytes, headerBytes+len(f.data))
	binary.BigEndian.PutUint16(out[0:2], filterFormat)
	binary.BigEndian.PutUint32(out[2:6], f.KeyVersion)
	binary.BigEndian.PutUint32(out[6:10], uint32(f.bits))
	out[10] = byte(f.hashCount)
	return append(out, f.data...), nil
}

// UnmarshalFilter reads a filter produced by MarshalBinary.
func UnmarshalFilter(b []byte) (Filter, error) {
	if len(b) < headerBytes {
		return Filter{}, fmt.Errorf("%w: %d bytes is shorter than the header", ErrBadFilter, len(b))
	}
	format := binary.BigEndian.Uint16(b[0:2])
	if format != filterFormat {
		return Filter{}, fmt.Errorf("%w: unsupported format version %d", ErrBadFilter, format)
	}
	f := Filter{
		KeyVersion: binary.BigEndian.Uint32(b[2:6]),
		bits:       uint(binary.BigEndian.Uint32(b[6:10])),
		hashCount:  uint(b[10]),
	}
	want := int((f.bits + 7) / 8)
	body := b[headerBytes:]
	if len(body) != want {
		return Filter{}, fmt.Errorf("%w: header says %d bits (%d bytes), body is %d bytes",
			ErrBadFilter, f.bits, want, len(body))
	}
	f.data = make([]byte, want)
	copy(f.data, body)
	return f, nil
}

// FilterFromBytes rebuilds a filter from a raw bit array plus its geometry.
//
// This is the counterpart to Bytes, for callers that store the bit array on its own rather
// than the self-describing MarshalBinary form. Storing raw is what makes a pushed-down
// predicate possible: Positions are offsets into the bit array, so if the stored column
// carries a header the database reads the wrong bits while an in-process check, which parses
// the header first, reads the right ones. The two then disagree in a way that looks like an
// honest miss.
//
// The caller supplies the geometry and key version because a raw array does not describe
// itself. Use the same values the filter was built with; there is no way to detect a
// mismatch here, which is the cost of dropping the header.
func FilterFromBytes(data []byte, nbits, hashCount uint, keyVersion uint32) (Filter, error) {
	if nbits == 0 || hashCount == 0 {
		return Filter{}, fmt.Errorf("%w: geometry must be non-zero", ErrBadFilter)
	}
	want := int((nbits + 7) / 8)
	if len(data) != want {
		return Filter{}, fmt.Errorf("%w: %d bits needs %d bytes, got %d",
			ErrBadFilter, nbits, want, len(data))
	}
	f := Filter{KeyVersion: keyVersion, bits: nbits, hashCount: hashCount, data: make([]byte, want)}
	copy(f.data, data)
	return f, nil
}
