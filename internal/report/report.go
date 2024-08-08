// Package report renders analysis results as Markdown (for people) and JSON
// (for pipelines). Rendering is a pure function of its inputs so reports are
// deterministic and golden-testable.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/diff"
	"github.com/lutherleo/leastpriv/internal/gap"
	"github.com/lutherleo/leastpriv/internal/generator"
	"github.com/lutherleo/leastpriv/internal/verify"
)

// WriteJSON writes v as indented JSON.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// PrincipalRun bundles everything computed for one principal.
type PrincipalRun struct {
	Generation *generator.Result `json:"generation"`
	Verify     *verify.Report    `json:"verification,omitempty"`
	Diff       *diff.Result      `json:"diff,omitempty"`
}

// Run is the output of a generate run over several principals.
type Run struct {
	Level      generator.Level `json:"level"`
	Input      activity.Stats  `json:"input"`
	Principals []PrincipalRun  `json:"principals"`
}

func esc(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s)
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// GenerateMarkdown renders a generate run.
func GenerateMarkdown(w io.Writer, run *Run) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Least-privilege policy report\n\n")
	fmt.Fprintf(&b, "Level: `%s`. Input: %d CloudTrail records, %d observations, %d access-denied attempts, %d records from non-principal callers, window %s to %s.\n\n",
		run.Level, run.Input.Records, run.Input.Observations, run.Input.DeniedAttempts, run.Input.NonPrincipalRecords,
		day(run.Input.First), day(run.Input.Last))
	if len(run.Input.UnknownServices) > 0 {
		fmt.Fprintf(&b, "Events from services outside the catalog (ignored): %s.\n\n", counts(run.Input.UnknownServices))
	}
	b.WriteString("| Principal | Distinct calls | Granted | Statements | Size (chars) | Replay | Subset check |\n|---|---:|---:|---:|---:|---|---|\n")
	for _, pr := range run.Principals {
		g := pr.Generation
		stmts := 0
		if g.Policy != nil {
			stmts = len(g.Policy.Statement)
		}
		replay, subset := "n/a", "n/a"
		if v := pr.Verify; v != nil {
			replay = fmt.Sprintf("%d/%d allowed", v.ReplayAllowed, v.Replayed)
			subset = fmt.Sprintf("%d violations in %d requests", len(v.Violations), v.SubsetChecked)
		}
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %d | %s | %s |\n", g.Principal, g.ObservedCalls, g.GrantedCalls, stmts, g.Size, replay, subset)
	}
	b.WriteString("\n")
	for _, pr := range run.Principals {
		writePrincipal(&b, pr)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writePrincipal(b *strings.Builder, pr PrincipalRun) {
	g := pr.Generation
	fmt.Fprintf(b, "## `%s`\n\n", g.Principal)
	for _, wmsg := range g.Warnings {
		fmt.Fprintf(b, "> Warning: %s\n\n", wmsg)
	}
	if g.Policy == nil {
		b.WriteString("No policy generated.\n\n")
	}
	if d := pr.Diff; d != nil {
		fmt.Fprintf(b, "Effective change vs. original: %d removed, %d narrowed, %d widened, %d added, %d changed (statements %d -> %d, size %d -> %d chars).\n\n",
			d.Counts[diff.Removed], d.Counts[diff.Narrowed], d.Counts[diff.Widened], d.Counts[diff.Added], d.Counts[diff.Changed],
			d.StatementsBefore, d.StatementsAfter, d.SizeBefore, d.SizeAfter)
	}
	if v := pr.Verify; v != nil {
		status := "PASS"
		if !v.OK {
			status = "FAIL"
		}
		fmt.Fprintf(b, "Verification: **%s**. Replay: %d of %d observed calls the original allows are allowed (%d uncertain). Differential check: %d requests over %d actions x %d resources x %d contexts, %d allowed by the generated policy, %d violations",
			status, v.ReplayAllowed, v.Replayed, v.UncertainReplays, v.SubsetChecked, v.SubsetActions, v.SubsetResources, v.SubsetContexts, v.GeneratedAllows, len(v.Violations))
		if v.SubsetSampled {
			b.WriteString(" (stride-sampled)")
		}
		b.WriteString(".\n\n")
		for _, f := range v.Failures {
			fmt.Fprintf(b, "- replay failure: `%s` on `%s` (%s)\n", f.Action, f.Resource, f.Reason)
		}
		for _, x := range v.Violations {
			fmt.Fprintf(b, "- subset violation: `%s` on `%s` (original: %s, context %s)\n", x.Action, x.Resource, x.Original, x.Context)
		}
	}
	if len(g.Grants) > 0 {
		b.WriteString("| Sid | Actions | Resources | Condition | Derived from |\n|---|---|---|---|---|\n")
		for _, gr := range g.Grants {
			var src []string
			for _, s := range gr.Sources {
				label := fmt.Sprintf("%s#%d", s.Policy, s.Statement)
				if s.Sid != "" {
					label = s.Policy + "/" + s.Sid
				}
				src = append(src, label)
			}
			res := gr.Resources
			if len(gr.NotResource) > 0 {
				res = []string{"NOT " + strings.Join(gr.NotResource, ", ")}
			}
			cond := ""
			if len(gr.Condition) > 0 {
				cond = "`" + esc(gr.Condition.Key()) + "`"
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", gr.Sid, code(gr.Actions, 6), code(res, 4), cond, esc(strings.Join(src, ", ")))
		}
		if g.Denies > 0 {
			fmt.Fprintf(b, "\nOriginal Deny statements copied verbatim: %d.\n", g.Denies)
		}
		b.WriteString("\n")
	}
	if len(g.Collapses) > 0 {
		fmt.Fprintf(b, "Wildcards introduced (%s):\n\n", plural(len(g.Collapses), "collapse"))
		cs := append([]generator.Collapse(nil), g.Collapses...)
		sort.Slice(cs, func(i, j int) bool { return cs[i].Pattern+cs[i].Action < cs[j].Pattern+cs[j].Action })
		for i, c := range cs {
			if i == 10 {
				fmt.Fprintf(b, "- ... %d more\n", len(cs)-10)
				break
			}
			fmt.Fprintf(b, "- `%s` for `%s` replaces %d observed resources (%s)\n", c.Pattern, c.Action, c.Replaces, c.Kind)
		}
		b.WriteString("\n")
	}
	for _, e := range g.Expansions {
		fmt.Fprintf(b, "- action wildcard `%s` covers %d observed and %d unobserved catalog actions: %s\n", e.Pattern, len(e.Observed), len(e.Unobserved), code(e.Unobserved, 8))
	}
	if len(g.Expansions) > 0 {
		b.WriteString("\n")
	}
	if len(g.Ungranted) > 0 {
		b.WriteString("Observed calls the analysed policies do not allow (granted elsewhere, e.g. a resource policy; left out):\n\n")
		for _, u := range g.Ungranted {
			fmt.Fprintf(b, "- `%s` on `%s`: %s\n", u.Action, u.Resource, u.Reason)
		}
		b.WriteString("\n")
	}
	if len(g.Skipped) > 0 {
		b.WriteString("Skipped observations:\n\n")
		for _, s := range g.Skipped {
			fmt.Fprintf(b, "- `%s` on `%s` x%d: %s\n", s.Action, s.Resource, s.Count, s.Reason)
		}
		b.WriteString("\n")
	}
}

func code(items []string, limit int) string {
	if len(items) == 0 {
		return ""
	}
	var parts []string
	for i, it := range items {
		if i == limit {
			parts = append(parts, fmt.Sprintf("+%d more", len(items)-limit))
			break
		}
		parts = append(parts, "`"+esc(it)+"`")
	}
	return strings.Join(parts, ", ")
}

func day(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02")
}

func counts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// GapMarkdown renders permission-gap reports.
func GapMarkdown(w io.Writer, reps []*gap.Report) error {
	var b strings.Builder
	b.WriteString("# Permission gap report\n\n")
	b.WriteString("| Principal | Granted | Used | Stale | Unused | Unobservable | Unused % | High-risk unused |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range reps {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %d | %d | %.1f | %d |\n", r.Principal, r.Granted, r.Used, r.Stale, r.Unused, r.Unobservable, r.UnusedPercent, len(r.HighRiskUnused))
	}
	b.WriteString("\n")
	for _, r := range reps {
		fmt.Fprintf(&b, "## `%s`\n\n", r.Principal)
		fmt.Fprintf(&b, "Window %s to %s; ages measured at %s; stale after %d days.\n\n", day(r.WindowStart), day(r.WindowEnd), day(r.Now), r.StaleDays)
		for _, wmsg := range r.Warnings {
			fmt.Fprintf(&b, "> Warning: %s\n\n", wmsg)
		}
		if len(r.UncataloguedGrants) > 0 {
			fmt.Fprintf(&b, "Grants outside the bundled catalog (not itemised below): %s\n\n", code(r.UncataloguedGrants, 10))
		}
		if len(r.HighRiskUnused) > 0 {
			fmt.Fprintf(&b, "High-risk unused grants: %s\n\n", code(r.HighRiskUnused, 15))
		}
		if len(r.DeniedOnly) > 0 {
			fmt.Fprintf(&b, "Access-denied attempts on actions that are not granted: %s\n\n", code(r.DeniedOnly, 10))
		}
		if len(r.Services) > 0 {
			b.WriteString("| Service | Granted actions | Used | Unused | Last used |\n|---|---:|---:|---:|---|\n")
			for _, s := range r.Services {
				last := "never"
				if s.LastUsed != nil {
					last = s.LastUsed.Format("2006-01-02")
				}
				fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", s.Service, s.GrantedActions, s.UsedActions, s.UnusedActions, last)
			}
			b.WriteString("\n")
		}
		b.WriteString("| Action | Access | Status | Calls | Resources | Last used (age) | Risk | Notes |\n|---|---|---|---:|---:|---|---|---|\n")
		for _, a := range r.Actions {
			if a.Status == gap.StatusUnused && a.Risk == "low" {
				continue // listed in the summary count; low-risk unused rows are in the JSON
			}
			last := ""
			if a.LastUsed != nil && a.AgeDays != nil {
				last = fmt.Sprintf("%s (%dd)", a.LastUsed.Format("2006-01-02"), *a.AgeDays)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %d | %d | %s | %s | %s |\n", a.Action, a.Access, a.Status, a.Count, a.Resources, last, a.Risk, esc(strings.Join(a.Notes, "; ")))
		}
		b.WriteString("\nLow-risk unused actions are counted above and listed in the JSON report.\n\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// DiffMarkdown renders a policy diff.
func DiffMarkdown(w io.Writer, d *diff.Result) error {
	var b strings.Builder
	b.WriteString("# Policy diff\n\n")
	fmt.Fprintf(&b, "Statements %d -> %d; size %d -> %d characters.\n\n", d.StatementsBefore, d.StatementsAfter, d.SizeBefore, d.SizeAfter)
	fmt.Fprintf(&b, "| Removed | Narrowed | Widened | Added | Changed | Unchanged |\n|---:|---:|---:|---:|---:|---:|\n| %d | %d | %d | %d | %d | %d |\n\n",
		d.Counts[diff.Removed], d.Counts[diff.Narrowed], d.Counts[diff.Widened], d.Counts[diff.Added], d.Counts[diff.Changed], d.Counts[diff.Unchanged])
	changes := append([]diff.ActionChange(nil), d.Actions...)
	diff.SortChanges(changes)
	var removed []string
	shown, hidden := 0, 0
	for _, c := range changes {
		if c.Change == diff.Removed {
			removed = append(removed, c.Action)
			continue
		}
		if shown == 40 {
			hidden++
			continue
		}
		shown++
		fmt.Fprintf(&b, "- **%s** `%s`: %s -> %s\n", c.Change, c.Action, code(c.Before, 3), code(c.After, 3))
	}
	if hidden > 0 {
		fmt.Fprintf(&b, "- ... %d more changed actions in the JSON output\n", hidden)
	}
	if len(removed) > 0 {
		fmt.Fprintf(&b, "- **removed** (%d): %s\n", len(removed), code(removed, 40))
	}
	if d.Unified != "" {
		b.WriteString("\n```diff\n")
		b.WriteString(d.Unified)
		b.WriteString("```\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
