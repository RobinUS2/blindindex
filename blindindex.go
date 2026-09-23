// Package blindindex builds searchable, keyed representations of documents so that a
// datastore can answer "which documents might contain this term?" without ever storing the
// terms themselves.
//
// Each document becomes a Bloom filter of HMAC digests, one filter per document. Holding a
// filter without the key tells you nothing about which terms produced it. Holding the key
// lets you test any term against it.
//
// # What it is for
//
// The intended use is keyword lookup over content that is encrypted at rest. A plaintext
// keyword index would defeat the encryption; this gives approximate lookup while keeping the
// vocabulary secret from anyone holding only the data.
//
// # What it deliberately does not promise
//
//   - Exact recall. Bloom filters produce false positives by design, and the vocabulary
//     policy discards tokens on purpose. Callers must treat results as candidates to be
//     confirmed, not as answers. If you need exact membership, this is the wrong tool.
//   - Protection from an observer watching queries over time. Which documents a query
//     matched, and whether two queries were the same, are visible to anyone who can watch
//     the system run. This design targets an adversary who obtains stored data, not one who
//     observes live traffic.
//   - Protection from an adversary who can choose documents. Anyone able to insert content
//     and observe the resulting filter learns the mapping for the terms they inserted. Use
//     a separate key per tenant so that knowledge cannot cross a boundary.
//
// # Threat model in one line
//
// An adversary who obtains the stored filters, and not the key, should not learn the
// vocabulary of any document.
package blindindex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Errors returned by this package.
var (
	ErrKeyVersionMismatch = errors.New("blindindex: key version mismatch")
	ErrShortKey           = errors.New("blindindex: key material too short")
	ErrBadOptions         = errors.New("blindindex: invalid options")
	ErrBadFilter          = errors.New("blindindex: malformed filter")
)

// MinKeyBytes is the shortest key material accepted. The key is the only thing standing
// between an attacker with the stored filters and the document vocabulary, so a short key is
// refused rather than warned about.
const MinKeyBytes = 32

// digestBytes is how much of each HMAC output is kept. The digest is consumed only to derive
// bit positions in a filter; it is never stored or compared as an identifier, so the full
// 32 bytes buy nothing. 16 leaves generous headroom over the positions actually used.
const digestBytes = 16

// Domain separation strings. Every HMAC input is prefixed so that a key used here can never
// produce a value that collides with the same key used for another purpose.
const (
	domainToken = "blindindex/token/v1|"
	domainPad   = "blindindex/pad/v1|"
)

// Key is secret key material plus the version that identifies it.
//
// Version exists so that key rotation is expressible. A filter records the version it was
// built under, and testing a filter with digests from a different version is an error rather
// than a silent non-match, because during a rotation a silent non-match is indistinguishable
// from "nothing found" and would lose recall invisibly.
type Key struct {
	version  uint32
	material []byte
}

// NewKey returns a Key. Material must be at least MinKeyBytes long.
func NewKey(version uint32, material []byte) (Key, error) {
	if len(material) < MinKeyBytes {
		return Key{}, fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrShortKey, len(material), MinKeyBytes)
	}
	cp := make([]byte, len(material))
	copy(cp, material)
	return Key{version: version, material: cp}, nil
}

// Version reports which key this is, for storing alongside a filter.
func (k Key) Version() uint32 { return k.version }

// String deliberately never renders the key material, so that a Key caught in a log line,
// an error, or a struct dump cannot leak the one secret this package depends on.
func (k Key) String() string {
	return fmt.Sprintf("blindindex.Key{version:%d, material:REDACTED(%d bytes)}",
		k.version, len(k.material))
}

// GoString has the same guarantee as String, covering the %#v verb.
func (k Key) GoString() string { return k.String() }

// Digest is a keyed token representation. It reveals nothing about its token without the key.
type Digest [digestBytes]byte

// QueryDigests are the digests for one query under one key version.
//
// The version travels with the digests so that a caller holding filters from several key
// versions, which is the normal state during a rotation, cannot accidentally test digests
// against a filter they do not match.
type QueryDigests struct {
	KeyVersion uint32
	Digests    []Digest
}

// Policy decides which tokens are worth indexing. It is supplied by the caller and this
// package computes no corpus statistics of its own, so an Indexer stays stateless and cannot
// develop a hidden dependency on a datastore.
type Policy struct {
	// MinRunes drops very short tokens, which carry little signal and are common.
	MinRunes int

	// MaxTokens bounds how many distinct tokens a single document contributes. This is a
	// security parameter as much as a performance one: it bounds the densest possible filter,
	// which is what makes a single fixed filter size viable for every document. Documents
	// with more tokens are truncated, never given a larger filter.
	MaxTokens int

	// Drop is an optional set of tokens to discard, applied after analysis. Typical use is a
	// stopword list, or terms so common in a corpus that indexing them helps nobody and
	// gives frequency analysis something to work with.
	Drop map[string]struct{}
}

// Options configure the filter geometry. Every document in a deployment must use identical
// values, which is why they are set once on an Indexer rather than per call.
type Options struct {
	// Bits is the filter size m, in bits. Fixed for every document.
	Bits uint

	// HashCount is the number of bit positions k set per token.
	HashCount uint

	// TargetDensity is the fraction of bits set after padding, between 0 and 1.
	//
	// Padding to a fixed density is what stops the filter leaking document length. Without
	// it, a filter that is five percent set plainly came from a shorter document than one
	// that is forty percent set, and that is a length oracle over supposedly opaque data.
	//
	// The cost is real and is the caller's to accept: every document pays the false positive
	// rate implied by this density, including short ones that would otherwise have had a
	// much lower rate. Choose it from the rate that is tolerable at MaxTokens.
	TargetDensity float64
}

// DefaultOptions is a reasonable starting geometry: 8192 bits, 7 positions per token, padded
// to 35 percent. At 512 tokens per document that is roughly a 0.1 percent false positive
// rate and 1 KiB per document. Measure against a real corpus before treating it as final.
func DefaultOptions() Options {
	return Options{Bits: 8192, HashCount: 7, TargetDensity: 0.35}
}

// Analyzer turns text into tokens. Supplying this as an interface keeps language handling out
// of the core and lets a caller use whatever tokenizer their corpus needs.
//
// The same Analyzer must be used when building and when querying. Different tokenization on
// the two paths produces different digests and silently finds nothing.
type Analyzer interface {
	Tokens(text string) []string
}

// Indexer builds and queries filters under a fixed geometry and policy. It holds no mutable
// state and is safe for concurrent use.
type Indexer struct {
	analyzer Analyzer
	policy   Policy
	opts     Options
	padTo    uint // set-bit count to pad to, derived once from Bits and TargetDensity
}

// New returns an Indexer, or an error if the geometry is unusable.
func New(a Analyzer, p Policy, o Options) (*Indexer, error) {
	switch {
	case a == nil:
		return nil, fmt.Errorf("%w: analyzer is nil", ErrBadOptions)
	case o.Bits == 0 || o.Bits%8 != 0:
		return nil, fmt.Errorf("%w: Bits must be a positive multiple of 8, got %d", ErrBadOptions, o.Bits)
	case o.HashCount == 0:
		return nil, fmt.Errorf("%w: HashCount must be positive", ErrBadOptions)
	case o.TargetDensity <= 0 || o.TargetDensity >= 1:
		return nil, fmt.Errorf("%w: TargetDensity must be in (0,1), got %v", ErrBadOptions, o.TargetDensity)
	case p.MaxTokens <= 0:
		return nil, fmt.Errorf("%w: Policy.MaxTokens must be positive", ErrBadOptions)
	}
	return &Indexer{
		analyzer: a,
		policy:   p,
		opts:     o,
		padTo:    uint(float64(o.Bits) * o.TargetDensity),
	}, nil
}

// digest computes the keyed representation of one token.
func (ix *Indexer) digest(k Key, domain, s string) Digest {
	mac := hmac.New(sha256.New, k.material)
	mac.Write([]byte(domain))
	mac.Write([]byte(s))
	var d Digest
	copy(d[:], mac.Sum(nil)[:digestBytes])
	return d
}

// selectTokens analyses text and applies the policy, returning distinct tokens in a stable
// order so that building the same document twice yields identical output.
func (ix *Indexer) selectTokens(text string) []string {
	raw := ix.analyzer.Tokens(text)
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		if len([]rune(t)) < ix.policy.MinRunes {
			continue
		}
		if _, drop := ix.policy.Drop[t]; drop {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
		if len(out) >= ix.policy.MaxTokens {
			break // truncate; never grow the filter for a long document
		}
	}
	return out
}

// Build returns the filter for one document.
//
// docID is mixed into the padding so that two documents with identical text still produce
// different padding bits. It is not secret and need not be unpredictable; a primary key is
// fine.
func (ix *Indexer) Build(docID, text string, k Key) (Filter, error) {
	if len(k.material) < MinKeyBytes {
		return Filter{}, ErrShortKey
	}
	f := newFilter(ix.opts.Bits, ix.opts.HashCount, k.version)
	for _, tok := range ix.selectTokens(text) {
		f.add(ix.digest(k, domainToken, tok))
	}
	ix.pad(&f, docID, k)
	return f, nil
}

// pad tops the filter up to the configured density with key-derived bits, so that the number
// of real tokens cannot be read off the bit count.
//
// Padding digests are derived from the key, so an attacker cannot tell padding bits from
// token bits. They are derived deterministically from docID and a counter, so rebuilding a
// document produces byte-identical output.
func (ix *Indexer) pad(f *Filter, docID string, k Key) {
	// A document at MaxTokens may already exceed the target; in that case there is nothing to
	// hide and nothing to do.
	var counter uint64
	for f.count() < ix.padTo {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], counter)
		f.add(ix.digest(k, domainPad, docID+"|"+string(buf[:])))
		counter++
		// Defensive bound. With a sane geometry this is unreachable; without it a
		// misconfiguration would hang instead of failing.
		if counter > uint64(ix.opts.Bits)*16 {
			return
		}
	}
}

// Query returns the digests for a query under one key version.
//
// Call it once per key version in play. During a rotation an organisation legitimately holds
// filters under two versions, and that is the normal path rather than an edge case.
func (ix *Indexer) Query(text string, k Key) QueryDigests {
	toks := ix.selectTokens(text)
	ds := make([]Digest, 0, len(toks))
	for _, t := range toks {
		ds = append(ds, ix.digest(k, domainToken, t))
	}
	return QueryDigests{KeyVersion: k.version, Digests: ds}
}
