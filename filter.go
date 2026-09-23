package blindindex

import (
	"encoding/binary"
	"fmt"

	"github.com/bits-and-blooms/bloom/v3"
)

// filterFormat is the on-disk format version. It is stored in every filter so that a future
// change to the layout can be detected rather than misread.
const filterFormat uint16 = 1

// headerBytes is the fixed-size prefix of a marshalled filter:
// format(2) + keyVersion(4) + bits(4) + hashCount(1).
const headerBytes = 2 + 4 + 4 + 1

// Filter is one document's searchable representation.
//
// It carries the key version it was built under so that a mismatched test fails loudly
// instead of returning a false negative that looks like an honest miss.
type Filter struct {
	KeyVersion uint32

	bits      uint
	hashCount uint
	bf        *bloom.BloomFilter
}

func newFilter(bits, hashCount uint, keyVersion uint32) Filter {
	return Filter{
		KeyVersion: keyVersion,
		bits:       bits,
		hashCount:  hashCount,
		bf:         bloom.New(bits, hashCount),
	}
}

func (f *Filter) add(d Digest) { f.bf.Add(d[:]) }

func (f *Filter) count() uint {
	return f.bf.BitSet().Count()
}

// Bits reports the filter size m.
func (f Filter) Bits() uint { return f.bits }

// HashCount reports k, the number of positions set per token.
func (f Filter) HashCount() uint { return f.hashCount }

// SetBits reports how many bits are set. After Build this is the configured target density
// for every document regardless of length, which is the property that stops the filter
// leaking document size.
func (f Filter) SetBits() uint { return f.count() }

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
		if f.bf.Test(d[:]) {
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
	if f.bf == nil {
		return nil, fmt.Errorf("%w: filter is not initialised", ErrBadFilter)
	}
	body, err := f.bf.GobEncode()
	if err != nil {
		return nil, fmt.Errorf("blindindex: encode filter: %w", err)
	}
	out := make([]byte, headerBytes, headerBytes+len(body))
	binary.BigEndian.PutUint16(out[0:2], filterFormat)
	binary.BigEndian.PutUint32(out[2:6], f.KeyVersion)
	binary.BigEndian.PutUint32(out[6:10], uint32(f.bits))
	out[10] = byte(f.hashCount)
	return append(out, body...), nil
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
		bf:         &bloom.BloomFilter{},
	}
	if err := f.bf.GobDecode(b[headerBytes:]); err != nil {
		return Filter{}, fmt.Errorf("%w: %v", ErrBadFilter, err)
	}
	if f.bf.Cap() != f.bits || f.bf.K() != f.hashCount {
		return Filter{}, fmt.Errorf("%w: header says m=%d k=%d, body says m=%d k=%d",
			ErrBadFilter, f.bits, f.hashCount, f.bf.Cap(), f.bf.K())
	}
	return f, nil
}
