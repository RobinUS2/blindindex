# blindindex

Keyword lookup over content you cannot read.

`blindindex` turns a document into a keyed Bloom filter of HMAC digests. Store the filter
next to your encrypted content and you can still ask *"which documents might contain this
term?"*, without ever storing the terms. Hold the filter without the key and it tells you
nothing about the vocabulary that produced it.

```go
ix, _ := blindindex.New(
    blindindex.NewTextAnalyzer(blindindex.StemEnglish),
    blindindex.Policy{MinRunes: 2, MaxTokens: 512},
    blindindex.DefaultOptions(),
)

key, _ := blindindex.NewKey(1, keyMaterialFromYourKMS)

// At write time, alongside encrypting the document.
filter, _ := ix.Build(docID, plaintext, key)
blob, _ := filter.MarshalBinary()   // store this; 1 KiB per document

// At read time.
f, _ := blindindex.UnmarshalFilter(blob)
hit, err := f.MayContainAll(ix.Query("Zorbulax", key))
```

## Why this exists

If content is encrypted at rest, a plaintext keyword index hands back what the encryption
was protecting. The usual answers are to give up keyword search, or to adopt a searchable
encryption product. This is the small middle option: approximate lookup, keyed, with the
leakage written down.

## What it promises, and what it does not

**It promises** that an adversary holding the stored filters, and not the key, does not
learn the vocabulary of any document.

**It does not promise:**

- **Exact recall.** Bloom filters produce false positives by construction, and the
  vocabulary policy discards tokens deliberately. Results are candidates to confirm, not
  answers. If you need exact membership, use something else.
- **Protection from an observer of live queries.** Which documents a query matched, and
  whether two queries were the same, are visible to anyone watching the system run. This
  targets an adversary who obtains stored data, not one who observes traffic. If your threat
  model includes sustained live observation, this design is not adequate and you want
  ORAM-class defences or confidential computing.
- **Protection from chosen-document attacks.** Anyone who can insert content and observe the
  resulting filter learns the mapping for the terms they inserted. Use one key per tenant so
  that knowledge cannot cross a boundary.

### Leakage, stated plainly

| Property | Leaked? |
|---|---|
| Document vocabulary | No, not without the key |
| Document length | **No.** Every filter is padded to a fixed density |
| Term frequency | No. Membership only, no counts, no positions |
| Co-occurrence across documents | Not stored. There is no inverted index |
| Similarity between documents | **Yes.** Two documents with overlapping vocabulary have correlated bit patterns |
| Which documents matched a query | **Yes**, to anyone watching queries |

Padding to a fixed density is the reason length does not leak. Without it, a filter that is
five percent set obviously came from a shorter document than one that is forty percent set.
The cost is that short documents pay the same false-positive rate as long ones. Choose
`TargetDensity` from the rate you can tolerate at `MaxTokens`.

## Design

- **Digests** are `HMAC-SHA256(key, domain || token)`, truncated to 16 bytes. Domain
  separation means a key used here cannot collide with the same key used elsewhere.
- **Every filter is the same size.** `MaxTokens` bounds the densest possible document, which
  is what makes one fixed geometry viable. Long documents are truncated, never given a
  bigger filter.
- **Padding is key-derived** from the document ID and a counter, so it is indistinguishable
  from real bits, deterministic across rebuilds, and different for two documents with
  identical text.
- **Key versions travel with both filters and query digests.** Testing across versions is an
  error, never a silent `false`, because during a rotation a silent false is
  indistinguishable from an honest miss and would lose recall invisibly.
- **Keys never print.** `String` and `GoString` redact, so a key caught in a log line or a
  struct dump does not leak.
- **Stateless.** No corpus statistics are computed, so an `Indexer` cannot develop a hidden
  dependency on a datastore. Supply term-dropping through `Policy.Drop`.

## Measured

On an M-series laptop, default geometry (8192 bits, k=7, 35% density):

| | |
|---|---|
| Serialised filter | **1059 bytes** per document |
| Build, 400-token document | **311 µs** |
| Query and test 1000 filters | **29.5 µs** |
| False-positive rate, measured | **0.00060** against a theoretical 0.00065 |

The false-positive measurement is a test, not a claim: `TestFalsePositiveRateIsWithinTolerance`
runs 20,000 absent-term queries and compares against `density^k`.

Testing a thousand filters in 30 microseconds is why there is no two-level or union index
here. Keep filters in memory and scan them.

## Choosing parameters

`DefaultOptions()` is 8192 bits, 7 hashes, 35% density: roughly 0.06% false positives at 512
tokens per document, 1 KiB each. Measure against your own corpus before treating it as final.

Raising `TargetDensity` raises the false-positive rate and increases the noise an attacker
must work through. Lowering `MaxTokens` lets you shrink the filter. Adding tokens to
`Policy.Drop` removes terms whose frequency an attacker could otherwise exploit; very common
terms are worth dropping on both grounds, since they help recall least and help an attacker
most.

## Analysis

`TextAnalyzer` uses Unicode text segmentation (UAX #29) via
[blevesearch/segment](https://github.com/blevesearch/segment), with optional Snowball
stemmers from [blevesearch/snowballstem](https://github.com/blevesearch/snowballstem).

Segmentation is delegated rather than approximated with a character-class check, because a
naive "split on non-letters" tokenizer mangles exactly the terms a blind index is most useful
for. `Łukasz` loses its first letter, `Škoda` becomes `koda`, and Cyrillic or CJK can vanish
entirely. There are tests for each.

`Analyzer` is an interface. Supply your own if your corpus needs different handling. Use the
same one for building and querying, or the digests will not match and you will silently find
nothing.

## Dependencies

| | Licence |
|---|---|
| [bits-and-blooms/bloom](https://github.com/bits-and-blooms/bloom) | BSD-2-Clause |
| [blevesearch/segment](https://github.com/blevesearch/segment) | Apache-2.0 |
| [blevesearch/snowballstem](https://github.com/blevesearch/snowballstem) | BSD-3-Clause |

Hashing is `crypto/hmac` and `crypto/sha256` from the standard library. No cryptographic
primitive is implemented here; this package only composes standard ones.

## Status

Tested, benchmarked, fuzzed, and race-clean, but young. The construction is a keyed Bloom
filter, which is well understood, and the leakage table above is the honest account of what
it gives up. If your data is regulated or high-value, have someone review the leakage
properties against your threat model before relying on it.

## Licence

MIT
