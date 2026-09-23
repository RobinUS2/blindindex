package blindindex

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

func testKey(t testing.TB, version uint32, seed byte) Key {
	t.Helper()
	m := bytes.Repeat([]byte{seed}, MinKeyBytes)
	k, err := NewKey(version, m)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func testIndexer(t testing.TB, stemmers ...Stemmer) *Indexer {
	t.Helper()
	ix, err := New(NewTextAnalyzer(stemmers...), Policy{MinRunes: 2, MaxTokens: 512}, DefaultOptions())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ix
}

// --- T1: tokenisation must not mangle the terms this is most useful for ---

func TestAnalyzer_DoesNotMangleNonASCII(t *testing.T) {
	a := NewTextAnalyzer() // no stemming, so we see the tokenizer's own output
	cases := []struct {
		name, in, want string
	}{
		{"latin diacritics", "Müller", "müller"},
		{"nordic", "Björn", "björn"},
		{"polish", "Łukasz", "łukasz"},
		{"czech", "Škoda", "škoda"},
		{"cyrillic", "Ольга", "ольга"},
		{"turkish", "Şahin", "şahin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := a.Tokens(tc.in)
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("Tokens(%q) = %v, want [%q]. A naive letter-range tokenizer "+
					"truncates or drops exactly these.", tc.in, got, tc.want)
			}
		})
	}
}

func TestAnalyzer_CJKProducesTokens(t *testing.T) {
	got := NewTextAnalyzer().Tokens("東京")
	if len(got) == 0 {
		t.Fatal("CJK input produced no tokens at all")
	}
}

func TestAnalyzer_SplitsOnPunctuationAndKeepsDigits(t *testing.T) {
	// Unicode text segmentation keeps a full stop between letters inside the word, so "B.V."
	// stays one token rather than splitting into "b" and "v". That is the standard's
	// behaviour and it is the one we want: a Dutch company suffix is more useful intact.
	got := NewTextAnalyzer().Tokens("Acme B.V. - report 2026 (q3)")
	want := map[string]bool{"acme": true, "b.v": true, "report": true, "2026": true, "q3": true}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected token %q in %v", g, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want exactly the %d expected tokens", got, len(want))
	}
}

func TestAnalyzer_StemmingIsOptionalAndApplied(t *testing.T) {
	plain := NewTextAnalyzer().Tokens("running")
	stemmed := NewTextAnalyzer(StemEnglish).Tokens("running")
	if plain[0] == stemmed[0] {
		t.Fatalf("stemmer had no effect: %q vs %q", plain[0], stemmed[0])
	}
	if nl := NewTextAnalyzer(StemDutch).Tokens("lopende"); nl[0] == "lopende" {
		t.Fatalf("dutch stemmer had no effect on %q", nl[0])
	}
}

// --- T2: determinism, or rebuilds and diffs are meaningless ---

func TestBuild_IsDeterministic(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)
	const text = "the quarterly report mentions Acme and Umbrella"

	first, err := ix.Build("doc-1", text, k)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	second, err := ix.Build("doc-1", text, k)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	a, _ := first.MarshalBinary()
	b, _ := second.MarshalBinary()
	if !bytes.Equal(a, b) {
		t.Fatal("same document, key and geometry produced different bytes")
	}
}

func TestBuild_PaddingVariesByDocID(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)
	const text = "identical text in both documents"

	f1, _ := ix.Build("doc-1", text, k)
	f2, _ := ix.Build("doc-2", text, k)
	a, _ := f1.MarshalBinary()
	b, _ := f2.MarshalBinary()
	if bytes.Equal(a, b) {
		t.Fatal("two documents with identical text produced identical filters; padding " +
			"must be docID-derived so identical content is not trivially linkable")
	}
}

// --- The headline security property: length must not be readable off the filter ---

func TestBuild_PadsToFixedDensityRegardlessOfLength(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)

	short, err := ix.Build("short", "one two three", k)
	if err != nil {
		t.Fatalf("Build short: %v", err)
	}
	var long strings.Builder
	for i := range 400 {
		fmt.Fprintf(&long, "term%d ", i)
	}
	big, err := ix.Build("long", long.String(), k)
	if err != nil {
		t.Fatalf("Build long: %v", err)
	}

	target := uint(float64(DefaultOptions().Bits) * DefaultOptions().TargetDensity)
	for _, c := range []struct {
		name string
		f    Filter
	}{{"short", short}, {"long", big}} {
		if c.f.SetBits() < target {
			t.Errorf("%s document: %d bits set, want at least the %d target. Length is "+
				"readable off the filter.", c.name, c.f.SetBits(), target)
		}
	}
	// The two must be close enough that an attacker cannot rank them by length. A long
	// document may overshoot slightly because the last real token sets several bits at once.
	diff := int(big.SetBits()) - int(short.SetBits())
	if diff < 0 {
		diff = -diff
	}
	if diff > int(float64(target)*0.05) {
		t.Errorf("set-bit counts differ by %d (short=%d long=%d); that is a length oracle",
			diff, short.SetBits(), big.SetBits())
	}
}

func TestBuild_TruncatesRatherThanGrowing(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)
	var huge strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&huge, "unique%d ", i)
	}
	f, err := ix.Build("huge", huge.String(), k)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if f.Bits() != DefaultOptions().Bits {
		t.Fatalf("filter grew to %d bits for a long document; every document must be the "+
			"same size or size leaks length", f.Bits())
	}
}

// --- T3: key separation ---

func TestKeySeparation(t *testing.T) {
	ix := testIndexer(t)
	kA := testKey(t, 1, 0xAA)
	kB := testKey(t, 1, 0xBB) // same version, different material
	const text = "Umbrella Corporation quarterly summary"

	fA, _ := ix.Build("doc-1", text, kA)
	qB := ix.Query("Umbrella", kB)

	got, err := fA.MayContainAll(qB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("a query under key B matched a filter built under key A")
	}

	qA := ix.Query("Umbrella", kA)
	if ok, err := fA.MayContainAll(qA); err != nil || !ok {
		t.Fatalf("the correct key failed to match: ok=%v err=%v", ok, err)
	}
}

func TestKeyVersionMismatchIsAnErrorNotAMiss(t *testing.T) {
	ix := testIndexer(t)
	k1 := testKey(t, 1, 0xAA)
	k2 := testKey(t, 2, 0xAA)
	f, _ := ix.Build("doc-1", "Umbrella", k1)

	ok, err := f.MayContainAll(ix.Query("Umbrella", k2))
	if err == nil {
		t.Fatal("expected ErrKeyVersionMismatch; a silent false here is indistinguishable " +
			"from an honest miss and would lose recall invisibly during a rotation")
	}
	if ok {
		t.Fatal("mismatched version reported a match")
	}
}

func TestKeyNeverPrintsItsMaterial(t *testing.T) {
	secret := bytes.Repeat([]byte("S"), MinKeyBytes)
	k, err := NewKey(7, secret)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	for _, rendered := range []string{
		k.String(), k.GoString(), fmt.Sprintf("%v", k), fmt.Sprintf("%s", k),
		fmt.Sprintf("%#v", k), fmt.Sprintf("%+v", k),
	} {
		if strings.Contains(rendered, string(secret[:8])) {
			t.Fatalf("key material leaked into a rendered form: %q", rendered)
		}
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := NewKey(1, []byte("too short")); err == nil {
		t.Fatal("expected a short key to be refused")
	}
}

func TestKeyMaterialIsCopiedNotAliased(t *testing.T) {
	m := bytes.Repeat([]byte{0x11}, MinKeyBytes)
	k, _ := NewKey(1, m)
	ix := testIndexer(t)
	before := ix.Query("acme", k)
	for i := range m { // caller mutates or zeroes their buffer afterwards
		m[i] = 0x22
	}
	after := ix.Query("acme", k)
	if before.Digests[0] != after.Digests[0] {
		t.Fatal("mutating the caller's buffer changed the key; material must be copied")
	}
}

// --- T4: the test that would catch the whole thing being pointless ---

func TestNoPlaintextInSerialisedFilter(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)
	const sentinel = "Zorbulax"
	f, err := ix.Build("doc-1", "a report concerning "+sentinel+" and its subsidiaries", k)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	blob, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	for _, variant := range []string{sentinel, strings.ToLower(sentinel), strings.ToUpper(sentinel)} {
		if bytes.Contains(blob, []byte(variant)) {
			t.Fatalf("plaintext %q appears in the serialised filter; the index is not blind", variant)
		}
	}
	// And the key must not be in there either.
	if bytes.Contains(blob, bytes.Repeat([]byte{0xA1}, MinKeyBytes)) {
		t.Fatal("key material appears in the serialised filter")
	}
}

// --- Round trip ---

func TestMarshalRoundTrip(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 42, 0xA1)
	f, _ := ix.Build("doc-1", "Acme Umbrella Initech", k)
	blob, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	back, err := UnmarshalFilter(blob)
	if err != nil {
		t.Fatalf("UnmarshalFilter: %v", err)
	}
	if back.KeyVersion != 42 || back.Bits() != f.Bits() || back.HashCount() != f.HashCount() {
		t.Fatalf("geometry lost in round trip: %+v", back)
	}
	if ok, err := back.MayContainAll(ix.Query("Umbrella", k)); err != nil || !ok {
		t.Fatalf("round-tripped filter stopped matching: ok=%v err=%v", ok, err)
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", []byte{1, 2, 3}},
		{"bad format version", append([]byte{0xFF, 0xFF}, make([]byte, 32)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnmarshalFilter(tc.in); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// --- Matching semantics ---

func TestMayContainAtLeast(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)
	f, _ := ix.Build("doc-1", "Acme and Umbrella signed", k)

	both := ix.Query("Acme Umbrella", k)
	if ok, _ := f.MayContainAll(both); !ok {
		t.Fatal("both present terms did not match under MayContainAll")
	}

	// One present, one absent: strict fails, partial succeeds. This is the lever for
	// "find more candidates" when exact recall is not the goal.
	mixed := ix.Query("Acme Zorbulax", k)
	if ok, _ := f.MayContainAll(mixed); ok {
		t.Fatal("MayContainAll matched despite an absent term (or the FP rate is broken)")
	}
	if ok, _ := f.MayContainAtLeast(mixed, 1); !ok {
		t.Fatal("MayContainAtLeast(1) failed despite one present term")
	}
}

func TestEmptyQueryMatchesNothing(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)
	f, _ := ix.Build("doc-1", "Acme", k)
	// Only stopword-ish short tokens, all dropped by MinRunes.
	if ok, err := f.MayContainAll(ix.Query("a I", k)); err != nil || ok {
		t.Fatalf("an empty query matched; treating no-terms as match-everything turns an "+
			"analysis failure into a full scan (ok=%v err=%v)", ok, err)
	}
}

// --- T5: false positive rate must track theory ---

func TestFalsePositiveRateIsWithinTolerance(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)

	var doc strings.Builder
	for i := range 400 {
		fmt.Fprintf(&doc, "present%d ", i)
	}
	f, err := ix.Build("doc-1", doc.String(), k)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	const trials = 20000
	fp := 0
	for i := range trials {
		q := ix.Query(fmt.Sprintf("absent%d", i), k)
		if ok, _ := f.MayContainAll(q); ok {
			fp++
		}
	}
	rate := float64(fp) / trials

	// Theory for a filter at density d with k positions: FP ~= d^k.
	o := DefaultOptions()
	density := float64(f.SetBits()) / float64(o.Bits)
	want := math.Pow(density, float64(o.HashCount))

	t.Logf("density=%.4f measured FP=%.5f theoretical FP=%.5f (%d/%d)", density, rate, want, fp, trials)
	if rate > want*4+0.002 {
		t.Fatalf("measured FP rate %.5f far exceeds theory %.5f; the filter is not behaving "+
			"like a Bloom filter", rate, want)
	}
}

// --- T6: it must actually increase hits ---

func TestRareTermIsFound(t *testing.T) {
	ix := testIndexer(t)
	k := testKey(t, 1, 0xA1)

	corpus := map[string]string{
		"handbook":  "general company handbook covering expenses and travel",
		"offsite":   "notes from the team offsite about planning and goals",
		"agreement": "agreement with Zorbulax Industries concerning open questions",
	}
	filters := map[string]Filter{}
	for id, text := range corpus {
		f, err := ix.Build(id, text, k)
		if err != nil {
			t.Fatalf("Build %s: %v", id, err)
		}
		filters[id] = f
	}

	q := ix.Query("Zorbulax", k)
	var hits []string
	for id, f := range filters {
		if ok, err := f.MayContainAll(q); err == nil && ok {
			hits = append(hits, id)
		}
	}
	if len(hits) != 1 || hits[0] != "agreement" {
		t.Fatalf("rare-term query returned %v, want exactly [agreement]", hits)
	}
}

// --- T7: never panic on hostile input ---

func FuzzAnalyzerAndBuild(f *testing.F) {
	for _, s := range []string{"", "Acme", "Müller", "東京", "\x00\xff\xfe", strings.Repeat("a ", 5000)} {
		f.Add(s)
	}
	ix, err := New(NewTextAnalyzer(StemEnglish, StemDutch), Policy{MinRunes: 2, MaxTokens: 512}, DefaultOptions())
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	m := bytes.Repeat([]byte{0x5A}, MinKeyBytes)
	k, _ := NewKey(1, m)

	f.Fuzz(func(t *testing.T, s string) {
		filter, err := ix.Build("fuzz", s, k)
		if err != nil {
			t.Fatalf("Build returned an error on arbitrary input: %v", err)
		}
		if _, err := filter.MarshalBinary(); err != nil {
			t.Fatalf("MarshalBinary failed: %v", err)
		}
		if _, err := filter.MayContainAll(ix.Query(s, k)); err != nil {
			t.Fatalf("MayContainAll failed: %v", err)
		}
	})
}

// --- Guard rails on construction ---

func TestNewRejectsBadGeometry(t *testing.T) {
	a := NewTextAnalyzer()
	p := Policy{MinRunes: 2, MaxTokens: 512}
	for _, tc := range []struct {
		name string
		o    Options
	}{
		{"zero bits", Options{Bits: 0, HashCount: 7, TargetDensity: 0.35}},
		{"bits not byte aligned", Options{Bits: 8191, HashCount: 7, TargetDensity: 0.35}},
		{"zero hashes", Options{Bits: 8192, HashCount: 0, TargetDensity: 0.35}},
		{"density zero", Options{Bits: 8192, HashCount: 7, TargetDensity: 0}},
		{"density one", Options{Bits: 8192, HashCount: 7, TargetDensity: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(a, p, tc.o); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := New(a, Policy{MinRunes: 2, MaxTokens: 0}, DefaultOptions()); err == nil {
		t.Fatal("expected MaxTokens=0 to be refused")
	}
	if _, err := New(nil, p, DefaultOptions()); err == nil {
		t.Fatal("expected a nil analyzer to be refused")
	}
}

// --- T8: cost ---

func BenchmarkBuild(b *testing.B) {
	ix := testIndexer(b)
	k := testKey(b, 1, 0xA1)
	var doc strings.Builder
	r := rand.New(rand.NewSource(1))
	for range 400 {
		fmt.Fprintf(&doc, "term%d ", r.Intn(100000))
	}
	text := doc.String()
	b.ResetTimer()
	for b.Loop() {
		if _, err := ix.Build("doc", text, k); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryAndTest1000Filters(b *testing.B) {
	ix := testIndexer(b)
	k := testKey(b, 1, 0xA1)
	filters := make([]Filter, 1000)
	for i := range filters {
		f, err := ix.Build(fmt.Sprintf("doc-%d", i), fmt.Sprintf("document %d about things", i), k)
		if err != nil {
			b.Fatal(err)
		}
		filters[i] = f
	}
	b.ResetTimer()
	for b.Loop() {
		q := ix.Query("Zorbulax", k)
		for _, f := range filters {
			_, _ = f.MayContainAll(q)
		}
	}
}

func BenchmarkMarshalledSize(b *testing.B) {
	ix := testIndexer(b)
	k := testKey(b, 1, 0xA1)
	f, _ := ix.Build("doc", "a modest document", k)
	blob, _ := f.MarshalBinary()
	b.ReportMetric(float64(len(blob)), "bytes/filter")
	b.ResetTimer()
	for b.Loop() {
		_, _ = f.MarshalBinary()
	}
}
