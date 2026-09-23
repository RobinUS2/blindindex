package blindindex

import (
	"strings"
	"unicode"

	"github.com/blevesearch/segment"
	"github.com/blevesearch/snowballstem"
	"github.com/blevesearch/snowballstem/dutch"
	"github.com/blevesearch/snowballstem/english"
	"github.com/blevesearch/snowballstem/french"
	"github.com/blevesearch/snowballstem/german"
	"github.com/blevesearch/snowballstem/spanish"
	"golang.org/x/text/unicode/norm"
)

// Stemmer reduces a token to its stem. Supplying it as a function keeps language choice in
// the caller's hands and keeps this package from guessing.
type Stemmer func(string) string

// Stemmers for the languages wired up here. Add more by wrapping any snowballstem package;
// the list is short because each one should be justified by a real corpus, not added
// speculatively.
var (
	StemEnglish Stemmer = wrapSnowball(english.Stem)
	StemDutch   Stemmer = wrapSnowball(dutch.Stem)
	StemGerman  Stemmer = wrapSnowball(german.Stem)
	StemFrench  Stemmer = wrapSnowball(french.Stem)
	StemSpanish Stemmer = wrapSnowball(spanish.Stem)
)

func wrapSnowball(fn func(*snowballstem.Env) bool) Stemmer {
	return func(s string) string {
		env := snowballstem.NewEnv(s)
		fn(env)
		return env.Current()
	}
}

// TextAnalyzer tokenises with Unicode text segmentation (UAX #29) and optionally folds
// diacritics and stems.
//
// Segmentation is delegated rather than approximated with a character-class check. A naive
// "split on non-letters" tokenizer mangles exactly the terms a blind index is most useful
// for: names carrying diacritics lose their first letter, and scripts outside the tested
// range disappear entirely.
type TextAnalyzer struct {
	// Stemmers are applied in order until one changes the token. Leave empty for no stemming,
	// which is the right choice when the corpus is dominated by proper nouns and identifiers.
	Stemmers []Stemmer

	// Lowercase folds case before stemming. Almost always wanted; exposed because identifier
	// corpora sometimes need case preserved.
	Lowercase bool

	// FoldDiacritics maps accented characters to their base letter, so that someone typing
	// "Muller" reaches a document containing "Müller".
	//
	// Do not rely on a stemmer for this. Snowball stemmers fold only the diacritics their own
	// language uses, so a Dutch stemmer turns "ü" into "u" and leaves "š" and "ł" untouched.
	// That asymmetry is worse than no folding, because the unaccented spelling silently misses
	// while a nearby one works.
	//
	// Coverage is decomposition-based: anything that NFD splits into a base letter plus a
	// combining mark is folded, which covers most European accents. Letters with a stroke or
	// bar, such as ł, ø and đ, do not decompose and are handled by an explicit table below.
	// Non-Latin scripts are left alone.
	FoldDiacritics bool
}

// strokeLetters are letters that Unicode does not decompose, so NFD cannot fold them. The
// list is short and Latin-only on purpose: guessing at other scripts would do more harm than
// leaving them untouched.
var strokeLetters = strings.NewReplacer(
	"ł", "l", "ø", "o", "đ", "d", "ð", "d", "þ", "th", "ħ", "h", "ŀ", "l",
	"ı", "i", "ɨ", "i", "ƀ", "b", "ŧ", "t", "ꝺ", "d", "ß", "ss", "æ", "ae", "œ", "oe",
)

// NewTextAnalyzer returns an analyzer that lowercases, folds diacritics and applies the given
// stemmers. Folding is on by default because asymmetric matching is a subtle and expensive
// bug; turn it off explicitly if your corpus needs accents preserved.
func NewTextAnalyzer(stemmers ...Stemmer) *TextAnalyzer {
	return &TextAnalyzer{Stemmers: stemmers, Lowercase: true, FoldDiacritics: true}
}

// fold removes diacritics from a token.
func fold(s string) string {
	s = strokeLetters.Replace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range norm.NFD.String(s) {
		if unicode.Is(unicode.Mn, r) { // Mn: nonspacing combining mark
			continue
		}
		b.WriteRune(r)
	}
	return norm.NFC.String(b.String())
}

// Tokens implements Analyzer.
func (a *TextAnalyzer) Tokens(text string) []string {
	if a.Lowercase {
		text = strings.ToLower(text)
	}
	seg := segment.NewWordSegmenter(strings.NewReader(text))
	var out []string
	for seg.Segment() {
		// Segment classifies each run; keeping only letters and numbers discards whitespace
		// and punctuation without us deciding what counts as a letter.
		switch seg.Type() {
		case segment.Letter, segment.Number, segment.Ideo:
			tok := seg.Text()
			if a.FoldDiacritics {
				tok = fold(tok)
			}
			for _, st := range a.Stemmers {
				if s := st(tok); s != tok {
					tok = s
					break
				}
			}
			out = append(out, tok)
		}
	}
	return out
}
