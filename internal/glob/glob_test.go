package glob

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"", "", true},
		{"", "a", false},
		{"abc", "abc", true},
		{"abc", "abcd", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a*c", "ac", true},
		{"a*c", "abbbc", true},
		{"a*c", "abbbd", false},
		{"*.txt", "notes.txt", true},
		{"*.txt", "notes.txt.bak", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxcyyb", false},
		{"??", "ab", true},
		{"??", "abc", false},
		{"logs/*/2026", "logs/x/y/2026", true},
		{"ü*", "über", true},
		{"?ber", "über", true},
		{"Get*", "getobject", false},
	}
	for _, c := range cases {
		if got := Match(c.p, c.s); got != c.want {
			t.Errorf("Match(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
}

func TestMatchFold(t *testing.T) {
	if !MatchFold("s3:Get*", "S3:GETOBJECT") {
		t.Fatal("fold match failed")
	}
	if !MatchFold("S3:GetObject", "s3:getobject") {
		t.Fatal("fold literal failed")
	}
	if MatchFold("s3:Put*", "s3:GetObject") {
		t.Fatal("unexpected match")
	}
}

func TestEscape(t *testing.T) {
	p := "home/" + Escape("a*b?") + "/*"
	if !Match(p, "home/a*b?/file") {
		t.Fatal("escaped literal should match itself")
	}
	if Match(p, "home/aXXb?/file") {
		t.Fatal("escaped star must not act as wildcard")
	}
	if Unescape(Escape("x*?y")) != "x*?y" {
		t.Fatal("unescape round trip")
	}
	if Escape("plain") != "plain" || Unescape("plain") != "plain" {
		t.Fatal("no-op escape")
	}
	if !MatchFold(Escape("A*"), "a*") {
		t.Fatal("fold with escape")
	}
}

func TestSubsumes(t *testing.T) {
	cases := []struct {
		g, s string
		want bool
	}{
		{"*", "anything*", true},
		{"a*", "abc", true},
		{"a*", "a/b/*", true},
		{"a/*", "a/b/*", true},
		{"a/b/*", "a/*", false},
		{"a?c", "abc", true},
		{"a?c", "a?c", true},
		{"a?c", "a*c", false},
		{"abc", "abc", true},
		{"abc", "ab?", false},
		{"*-prod", "api-prod", true},
		{"*-prod", "*-prod", true},
		{"*-prod", "*", false},
		{"x*y*z", "x1y2z", true},
		{"", "", true},
		{"", "a", false},
	}
	for _, c := range cases {
		if got := Subsumes(c.g, c.s); got != c.want {
			t.Errorf("Subsumes(%q,%q)=%v want %v", c.g, c.s, got, c.want)
		}
	}
	if !SubsumesFold("S3:get*", "s3:GetObject") {
		t.Fatal("fold subsumption")
	}
	if !Subsumes("a"+Escape("*"), "a"+Escape("*")) {
		t.Fatal("escaped literal subsumes itself")
	}
}

// globToRegexp is an independent oracle for Match.
func globToRegexp(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range p {
		switch r {
		case '*':
			b.WriteString("(?s:.*)")
		case '?':
			b.WriteString("(?s:.)")
		default:
			b.WriteString(regexp.QuoteMeta(string(literal(r))))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func randString(r *rand.Rand, alphabet string, maxLen int) string {
	n := r.IntN(maxLen + 1)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

func TestMatchAgainstRegexpOracle(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 5000; i++ {
		p := randString(r, "ab*?", 7)
		s := randString(r, "ab", 8)
		if got, want := Match(p, s), globToRegexp(p).MatchString(s); got != want {
			t.Fatalf("Match(%q,%q)=%v oracle=%v", p, s, got, want)
		}
	}
}

// instantiate replaces the wildcards of a pattern with random text, giving a
// concrete member of the pattern's language.
func instantiate(r *rand.Rand, p string) string {
	var b strings.Builder
	for _, c := range p {
		switch c {
		case '*':
			b.WriteString(randString(r, "ab/", 3))
		case '?':
			b.WriteByte("ab/"[r.IntN(3)])
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// TestSubsumesSoundness checks the property the generator depends on: if
// Subsumes(g, s) then every instance of s matches g.
func TestSubsumesSoundness(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	proved := 0
	for i := 0; i < 4000; i++ {
		g := randString(r, "ab/*?", 6)
		s := randString(r, "ab/*?", 6)
		if !Subsumes(g, s) {
			continue
		}
		proved++
		for k := 0; k < 20; k++ {
			inst := instantiate(r, s)
			if !Match(g, inst) {
				t.Fatalf("Subsumes(%q,%q) but %q not matched by general", g, s, inst)
			}
		}
	}
	if proved < 100 {
		t.Fatalf("too few subsumption proofs exercised: %d", proved)
	}
}

func FuzzMatch(f *testing.F) {
	f.Add("a*b?c", "axxbyc")
	f.Add("*", "")
	f.Add("??*", "ab")
	f.Fuzz(func(t *testing.T, p, s string) {
		if len(p) > 24 || len(s) > 24 || strings.ContainsAny(p+s, string([]rune{LiteralStar, LiteralQuestion})) {
			return
		}
		if got, want := Match(p, s), globToRegexp(p).MatchString(s); got != want {
			t.Fatalf("Match(%q,%q)=%v oracle=%v", p, s, got, want)
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	p := "arn:aws:s3:::acme-*-data/uploads/*/2026/*.json"
	s := "arn:aws:s3:::acme-app-data/uploads/tenant-42/2026/10/24/object-000123.json"
	for i := 0; i < b.N; i++ {
		Match(p, s)
	}
}

func BenchmarkSubsumes(b *testing.B) {
	g := "arn:aws:s3:::acme-*/uploads/*"
	s := "arn:aws:s3:::acme-app-data/uploads/2026/10/*"
	for i := 0; i < b.N; i++ {
		Subsumes(g, s)
	}
}

func randRunes(r *rand.Rand, alphabet []rune, maxLen int) string {
	n := r.IntN(maxLen + 1)
	out := make([]rune, n)
	for i := range out {
		out[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(out)
}

// TestMatchPathsAgree checks the ASCII fast path and the rune path against
// the regexp oracle, case-sensitively and case-insensitively, on mixed
// ASCII/non-ASCII inputs so both code paths are exercised.
func TestMatchPathsAgree(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 5000; i++ {
		var p, s string
		if i%2 == 0 {
			p, s = randString(r, "aB*?", 7), randString(r, "abAB", 8)
		} else {
			p, s = randRunes(r, []rune("aÉ*?"), 7), randRunes(r, []rune("aéÉA"), 8)
		}
		if got, want := Match(p, s), globToRegexp(p).MatchString(s); got != want {
			t.Fatalf("Match(%q,%q)=%v oracle=%v", p, s, got, want)
		}
		fold := regexp.MustCompile("(?i)" + globToRegexp(p).String())
		if got, want := MatchFold(p, s), fold.MatchString(s); got != want {
			t.Fatalf("MatchFold(%q,%q)=%v oracle=%v", p, s, got, want)
		}
	}
}
