// Package evalharness measures generator and gap-report quality against the
// synthetic scenario's ground truth with a temporal train/test split:
// policies and gap reports are computed from the training window only, and
// scored on the held-out test window and on the ground-truth file.
//
// Metrics per (principal, level):
//   - held-out allow rate: share of test-window calls the original policies
//     allow that the generated policy also allows (1 - break rate);
//   - excess actions: catalog actions granted beyond the truly needed set,
//     for the original and the generated policy;
//   - decoys allowed: ground-truth decoy requests (never needed, sensitive)
//     the policy allows, evaluated with unknown context (an upper bound);
//   - needed actions granted: observable actions the workload truly needs
//     (over the whole 90 days) that the generated policy grants at all;
//   - gap-report precision/recall of "unused" against truly unneeded grants.
package evalharness

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/gap"
	"github.com/lutherleo/leastpriv/internal/generator"
	"github.com/lutherleo/leastpriv/internal/policy"
	"github.com/lutherleo/leastpriv/internal/synth"
)

// Row is the score of one principal at one level.
type Row struct {
	Principal          string  `json:"principal"`
	Level              string  `json:"level"`
	TrainCalls         int     `json:"trainCalls"`
	TestCalls          int     `json:"testCalls"`
	TestAllowed        int     `json:"testAllowed"`
	HeldOutAllowRate   float64 `json:"heldOutAllowRate"`
	BrokenPairs        int     `json:"brokenPairs"`
	Statements         int     `json:"statements"`
	Size               int     `json:"size"`
	ExcessOriginal     int     `json:"excessActionsOriginal"`
	ExcessGenerated    int     `json:"excessActionsGenerated"`
	DecoysTotal        int     `json:"decoys"`
	DecoysOriginal     int     `json:"decoysAllowedOriginal"`
	DecoysGenerated    int     `json:"decoysAllowedGenerated"`
	NeededActions      int     `json:"neededObservableActions"`
	NeededGranted      int     `json:"neededActionsGrantedByGenerated"`
	VerificationPassed bool    `json:"verificationPassed"`
}

// GapScore scores the training-window gap report for one principal.
type GapScore struct {
	Principal      string  `json:"principal"`
	ReportedUnused int     `json:"reportedUnused"`
	TruthUnneeded  int     `json:"truthUnneededGrants"`
	TruePositives  int     `json:"truePositives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	FalsePositives string  `json:"falsePositives,omitempty"`
}

// Result is the full evaluation.
type Result struct {
	Scenario string     `json:"scenario"`
	Seed     uint64     `json:"seed"`
	Train    string     `json:"trainWindow"`
	Test     string     `json:"testWindow"`
	Rows     []Row      `json:"rows"`
	Gap      []GapScore `json:"gap"`
}

// Run evaluates the scenario stored in dir (authz.json, truth.json, cloudtrail/).
func Run(dir string) (*Result, error) {
	cat := catalog.Default()
	var truth synth.Truth
	tb, err := os.ReadFile(filepath.Join(dir, "truth.json")) // #nosec G304 -- fixture path
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(tb, &truth); err != nil {
		return nil, fmt.Errorf("truth.json: %w", err)
	}
	inv, err := authz.LoadFile(filepath.Join(dir, "authz.json"))
	if err != nil {
		return nil, err
	}
	trail := filepath.Join(dir, "cloudtrail")
	train, err := activity.Load(trail, cat, activity.Options{Inventory: inv, From: truth.Start, To: truth.TrainEnd})
	if err != nil {
		return nil, err
	}
	test, err := activity.Load(trail, cat, activity.Options{Inventory: inv, From: truth.TrainEnd, To: truth.End})
	if err != nil {
		return nil, err
	}
	res := &Result{
		Scenario: truth.Scenario, Seed: truth.Seed,
		Train: truth.Start.Format("2006-01-02") + " to " + truth.TrainEnd.AddDate(0, 0, -1).Format("2006-01-02"),
		Test:  truth.TrainEnd.Format("2006-01-02") + " to " + truth.End.AddDate(0, 0, -1).Format("2006-01-02"),
	}
	for _, pt := range truth.Principals {
		p, ok := inv.Find(pt.ARN)
		if !ok {
			return nil, fmt.Errorf("truth principal %s missing from inventory", pt.ARN)
		}
		key, _ := authz.Key(p.ARN)
		orig, err := p.PolicySet()
		if err != nil {
			return nil, err
		}
		needed := map[string]bool{}
		for _, n := range pt.Needs {
			needed[strings.ToLower(n.Action)] = true
		}
		var boundary *policy.Document
		if p.Boundary != nil {
			boundary = p.Boundary.Doc
		}
		origGranted := gap.Granted(cat, p)
		for _, lvl := range []generator.Level{generator.LevelExact, generator.LevelModerate, generator.LevelAggressive} {
			g, err := generator.Generate(cat, generator.Input{Principal: p, Observations: train.ByPrincipal[key]}, generator.Options{Level: lvl})
			if err != nil {
				return nil, err
			}
			row := Row{Principal: pt.ARN, Level: string(lvl), TrainCalls: len(activity.Successful(train.ByPrincipal[key])), DecoysTotal: len(pt.Decoys)}
			gen := &engine.Set{Boundary: orig.Boundary}
			var genDocs []*policy.Document
			if g.Policy != nil {
				genDocs = []*policy.Document{g.Policy}
				c, err := engine.Compile("generated", g.Policy)
				if err != nil {
					return nil, err
				}
				gen.Identity = []*engine.Policy{c}
				row.Statements = len(g.Policy.Statement)
				row.Size = g.Size
			}
			broken := map[string]bool{}
			for _, o := range test.ByPrincipal[key] {
				if o.Denied || o.NoAuth {
					continue
				}
				req := o.Request()
				if !orig.Allows(req) {
					continue
				}
				row.TestCalls++
				if gen.Allows(req) {
					row.TestAllowed++
				} else {
					broken[o.Action+" "+o.Resource] = true
				}
			}
			row.BrokenPairs = len(broken)
			row.HeldOutAllowRate = ratio(row.TestAllowed, row.TestCalls)
			row.ExcessOriginal = excess(origGranted, needed)
			row.ExcessGenerated = excess(gap.GrantedByDocs(cat, genDocs, boundary), needed)
			for _, d := range pt.Decoys {
				req := engine.Request{Action: d.Action, Resource: d.Resource, Unknown: engine.AllUnknown}
				if orig.Allows(req) {
					row.DecoysOriginal++
				}
				if gen.Allows(req) {
					row.DecoysGenerated++
				}
			}
			genGranted := map[string]bool{}
			for _, a := range gap.GrantedByDocs(cat, genDocs, boundary) {
				genGranted[strings.ToLower(a)] = true
			}
			seenNeed := map[string]bool{}
			for _, n := range pt.Needs {
				key := strings.ToLower(n.Action)
				if a, ok := cat.Lookup(n.Action); !n.Observable || seenNeed[key] || (ok && a.NoAuth) {
					continue
				}
				seenNeed[key] = true
				row.NeededActions++
				if genGranted[key] {
					row.NeededGranted++
				}
			}
			row.VerificationPassed = verifyReplay(orig, gen, train.ByPrincipal[key])
			res.Rows = append(res.Rows, row)
		}
		rep, err := gap.Analyze(cat, p, train.ByPrincipal[key], gap.Options{WindowStart: truth.Start, WindowEnd: truth.TrainEnd})
		if err != nil {
			return nil, err
		}
		res.Gap = append(res.Gap, scoreGap(pt.ARN, rep, origGranted, needed))
	}
	return res, nil
}

func verifyReplay(orig, gen *engine.Set, obs []activity.Observation) bool {
	for _, o := range obs {
		if o.Denied || o.NoAuth {
			continue
		}
		req := o.Request()
		if orig.Allows(req) && !gen.Allows(req) {
			return false
		}
	}
	return true
}

func excess(granted []string, needed map[string]bool) int {
	n := 0
	for _, a := range granted {
		if !needed[strings.ToLower(a)] {
			n++
		}
	}
	return n
}

func scoreGap(principal string, rep *gap.Report, granted []string, needed map[string]bool) GapScore {
	s := GapScore{Principal: principal}
	truthUnneeded := map[string]bool{}
	for _, a := range granted {
		if !needed[strings.ToLower(a)] {
			truthUnneeded[strings.ToLower(a)] = true
		}
	}
	s.TruthUnneeded = len(truthUnneeded)
	var fps []string
	for _, a := range rep.Actions {
		if a.Status != gap.StatusUnused {
			continue
		}
		s.ReportedUnused++
		if truthUnneeded[strings.ToLower(a.Action)] {
			s.TruePositives++
		} else {
			fps = append(fps, a.Action)
		}
	}
	sort.Strings(fps)
	s.FalsePositives = strings.Join(fps, ", ")
	s.Precision = ratio(s.TruePositives, s.ReportedUnused)
	s.Recall = ratio(s.TruePositives, s.TruthUnneeded)
	return s
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return math.Round(10000*float64(a)/float64(b)) / 10000
}

func short(arn string) string {
	if i := strings.Index(arn, ":role/"); i >= 0 {
		return "role/" + arn[i+6:]
	}
	if i := strings.Index(arn, ":user/"); i >= 0 {
		return "user/" + arn[i+6:]
	}
	return arn
}

// Markdown renders the evaluation tables.
func (r *Result) Markdown(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Scenario `%s` (seed %d). Train window %s; held-out test window %s.\n\n", r.Scenario, r.Seed, r.Train, r.Test)
	b.WriteString("| Principal | Level | Stmts | Size | Held-out allow rate | Broken pairs | Excess actions (orig -> gen) | Decoys allowed (orig -> gen) | Needed actions granted |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---|---|---|\n")
	for _, row := range r.Rows {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %.1f%% (%d/%d) | %d | %d -> %d | %d -> %d of %d | %d/%d |\n",
			short(row.Principal), row.Level, row.Statements, row.Size, 100*row.HeldOutAllowRate, row.TestAllowed, row.TestCalls,
			row.BrokenPairs, row.ExcessOriginal, row.ExcessGenerated, row.DecoysOriginal, row.DecoysGenerated, row.DecoysTotal,
			row.NeededGranted, row.NeededActions)
	}
	b.WriteString("\nGap report (training window) vs. ground truth: \"unused\" should equal granted-but-unneeded.\n\n")
	b.WriteString("| Principal | Reported unused | Truly unneeded grants | Precision | Recall | False positives |\n|---|---:|---:|---:|---:|---|\n")
	for _, g := range r.Gap {
		fp := g.FalsePositives
		if fp == "" {
			fp = "-"
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %.3f | %.3f | %s |\n", short(g.Principal), g.ReportedUnused, g.TruthUnneeded, g.Precision, g.Recall, fp)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
