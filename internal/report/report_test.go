package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/diff"
	"github.com/lutherleo/leastpriv/internal/gap"
	"github.com/lutherleo/leastpriv/internal/generator"
	"github.com/lutherleo/leastpriv/internal/policy"
	"github.com/lutherleo/leastpriv/internal/verify"
)

var update = flag.Bool("update", false, "rewrite golden files")

const fixturePrincipal = "arn:aws:iam::111122223333:role/ci-deployer"

// fixtureRun builds every report type for one principal of the committed
// acme scenario, exactly as the CLI does.
func fixtureRun(t *testing.T) (*Run, []*gap.Report, *diff.Result) {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "acme")
	cat := catalog.Default()
	inv, err := authz.LoadFile(filepath.Join(root, "authz.json"))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := activity.Load(filepath.Join(root, "cloudtrail"), cat, activity.Options{Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := inv.Find(fixturePrincipal)
	if !ok {
		t.Fatal("fixture principal missing")
	}
	key, _ := authz.Key(p.ARN)
	obs := ds.ByPrincipal[key]
	g, err := generator.Generate(cat, generator.Input{Principal: p, Observations: obs}, generator.Options{Level: generator.LevelModerate})
	if err != nil {
		t.Fatal(err)
	}
	docs := []*policy.Document{g.Policy}
	v, err := verify.Verify(cat, p, docs, obs, verify.Options{MaxPairs: 20000})
	if err != nil {
		t.Fatal(err)
	}
	var orig []*policy.Document
	for _, nd := range p.Policies {
		orig = append(orig, nd.Doc)
	}
	d, err := diff.Compare(cat, orig, docs)
	if err != nil {
		t.Fatal(err)
	}
	gr, err := gap.Analyze(cat, p, obs, gap.Options{WindowStart: ds.Stats.First, WindowEnd: ds.Stats.Last})
	if err != nil {
		t.Fatal(err)
	}
	run := &Run{Level: generator.LevelModerate, Input: ds.Stats, Principals: []PrincipalRun{{Generation: g, Verify: v, Diff: d}}}
	return run, []*gap.Report{gr}, d
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from golden file; rerun with -update if intended\n--- got ---\n%s", name, got)
	}
}

// TestGoldenReports pins the Markdown rendering of the generate, gap and
// diff reports for one fixture principal.
func TestGoldenReports(t *testing.T) {
	run, gaps, d := fixtureRun(t)
	var b bytes.Buffer
	if err := GenerateMarkdown(&b, run); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.ci-deployer.md", b.Bytes())
	b.Reset()
	if err := GapMarkdown(&b, gaps); err != nil {
		t.Fatal(err)
	}
	golden(t, "gap.ci-deployer.md", b.Bytes())
	b.Reset()
	if err := DiffMarkdown(&b, d); err != nil {
		t.Fatal(err)
	}
	golden(t, "diff.ci-deployer.md", b.Bytes())
}

func TestWriteJSONRoundTrip(t *testing.T) {
	run, gaps, _ := fixtureRun(t)
	for _, v := range []any{run, gaps} {
		var b bytes.Buffer
		if err := WriteJSON(&b, v); err != nil {
			t.Fatal(err)
		}
		var back any
		if err := json.Unmarshal(b.Bytes(), &back); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if strings.Contains(b.String(), `<`) {
			t.Error("HTML escaping should be disabled")
		}
	}
}

func TestRenderingEdgeCases(t *testing.T) {
	g := &generator.Result{
		Principal: "arn:aws:iam::1:role/empty",
		Warnings:  []string{"no granted activity observed"},
		Collapses: make([]generator.Collapse, 12),
		Expansions: []generator.Expansion{{
			Pattern: "s3:Get*", Observed: []string{"s3:GetObject"}, Unobserved: []string{"s3:GetObjectAcl"},
		}},
		Ungranted: []generator.Ungranted{{Action: "kms:Decrypt", Resource: "*", Reason: "implicit deny"}},
		Skipped:   []generator.Skipped{{Action: "sts:GetCallerIdentity", Resource: "*", Reason: "no IAM permission", Count: 2}},
	}
	v := &verify.Report{
		OK: false, SubsetSampled: true,
		Failures:   []verify.Failure{{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", Reason: "implicit deny"}},
		Violations: []verify.Violation{{Action: "s3:PutObject", Resource: "arn:aws:s3:::b/k", Original: "implicitDeny", Context: "unknown"}},
	}
	run := &Run{
		Level:      generator.LevelAggressive,
		Input:      activity.Stats{UnknownServices: map[string]int{"x.amazonaws.com": 3}},
		Principals: []PrincipalRun{{Generation: g, Verify: v}},
	}
	var b bytes.Buffer
	if err := GenerateMarkdown(&b, run); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"No policy generated.", "> Warning: no granted activity observed", "Verification: **FAIL**", "(stride-sampled)",
		"replay failure: `s3:GetObject`", "subset violation: `s3:PutObject`", "- ... 2 more", "action wildcard `s3:Get*`",
		"`kms:Decrypt` on `*`", "x2: no IAM permission", "x.amazonaws.com x3", "window - to -",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n%s", want, out)
		}
	}
	if got := code([]string{"a|b", "c", "d"}, 2); got != "`a\\|b`, `c`, +1 more" {
		t.Errorf("code() = %q", got)
	}
	if code(nil, 3) != "" || plural(1, "collapse") != "1 collapse" || plural(2, "collapse") != "2 collapses" {
		t.Error("helper formatting")
	}
	if day(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) != "2026-01-02" {
		t.Error("day()")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestWriteErrorsPropagate(t *testing.T) {
	if err := GenerateMarkdown(failWriter{}, &Run{}); err == nil {
		t.Error("GenerateMarkdown: want error")
	}
	if err := GapMarkdown(failWriter{}, nil); err == nil {
		t.Error("GapMarkdown: want error")
	}
	if err := DiffMarkdown(failWriter{}, &diff.Result{Counts: map[diff.Change]int{}}); err == nil {
		t.Error("DiffMarkdown: want error")
	}
}
