package blindindex

import (
	"strings"

	"github.com/blevesearch/segment"
	"github.com/blevesearch/snowballstem"
	"github.com/blevesearch/snowballstem/dutch"
	"github.com/blevesearch/snowballstem/english"
	"github.com/blevesearch/snowballstem/french"
	"github.com/blevesearch/snowballstem/german"
	"github.com/blevesearch/snowballstem/spanish"
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

// TextAnalyzer tokenises with Unicode text segmentation (UAX #29) and optionally stems.
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
}

// NewTextAnalyzer returns an analyzer that lowercases and applies the given stemmers.
func NewTextAnalyzer(stemmers ...Stemmer) *TextAnalyzer {
	return &TextAnalyzer{Stemmers: stemmers, Lowercase: true}
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
