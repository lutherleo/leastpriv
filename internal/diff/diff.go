// Package diff compares two policy sets: an effective, per-action diff (what
// each catalog action is allowed on, before and after) and a textual unified
// diff of the canonical JSON.
//
// Effective diff cost: O(A * S) for A actions and S statements. The text
// diff is a longest-common-subsequence alignment over lines, O(N * M) time
// and memory for N and M lines; inputs whose product exceeds MaxLCSCells
// fall back to a whole-document replacement hunk.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/glob"
	"github.com/lutherleo/leastpriv/internal/policy"
)

// MaxLCSCells bounds the text-diff dynamic program.
const MaxLCSCells = 16_000_000

// Change classifies an action's difference.
type Change string

// Change kinds.
const (
	Removed   Change = "removed"
	Added     Change = "added"
	Narrowed  Change = "narrowed"
	Widened   Change = "widened"
	Changed   Change = "changed"
	Unchanged Change = "unchanged"
)

// ActionChange is the per-action effective difference.
type ActionChange struct {
	Action string   `json:"action"`
	Access string   `json:"access,omitempty"`
	Change Change   `json:"change"`
	Before []string `json:"before,omitempty"`
	After  []string `json:"after,omitempty"`
}

// Result is the full comparison.
type Result struct {
	StatementsBefore int            `json:"statementsBefore"`
	StatementsAfter  int            `json:"statementsAfter"`
	SizeBefore       int            `json:"sizeBefore"`
	SizeAfter        int            `json:"sizeAfter"`
	Counts           map[Change]int `json:"counts"`
	Actions          []ActionChange `json:"actions"`
	Unified          string         `json:"unified"`
}

// Compare diffs two policy sets (for example original vs generated).
func Compare(cat *catalog.Catalog, before, after []*policy.Document) (*Result, error) {
	res := &Result{Counts: map[Change]int{}}
	for _, d := range before {
		res.StatementsBefore += len(d.Statement)
		n, err := d.Size()
		if err != nil {
			return nil, err
		}
		res.SizeBefore += n
	}
	for _, d := range after {
		res.StatementsAfter += len(d.Statement)
		n, err := d.Size()
		if err != nil {
			return nil, err
		}
		res.SizeAfter += n
	}
	actions := map[string]string{}
	for _, a := range cat.Actions() {
		actions[a.FullName()] = a.Access
	}
	for _, d := range append(append([]*policy.Document{}, before...), after...) {
		for _, st := range d.Statement {
			for _, a := range st.Action {
				if !glob.HasWildcard(a) {
					if _, ok := actions[canonical(cat, a)]; !ok {
						actions[canonical(cat, a)] = ""
					}
				}
			}
		}
	}
	for _, name := range policy.SortedKeys(actions) {
		b := scopes(before, name)
		a := scopes(after, name)
		ch := classify(b, a)
		if ch == Unchanged && len(b) == 0 {
			continue
		}
		res.Counts[ch]++
		if ch == Unchanged {
			continue
		}
		res.Actions = append(res.Actions, ActionChange{Action: name, Access: actions[name], Change: ch, Before: b, After: a})
	}
	text, err := Unified(before, after, 3)
	if err != nil {
		return nil, err
	}
	res.Unified = text
	return res, nil
}

func canonical(cat *catalog.Catalog, a string) string {
	if act, ok := cat.Lookup(a); ok {
		return act.FullName()
	}
	return a
}

// scopes returns the resource scopes on which the documents allow action:
// Resource patterns of matching Allow statements, "NOT(...)" for
// NotResource, with " if <conditions>" appended for conditional grants. An
// unconditional Deny on "*" for the action empties the scope.
func scopes(docs []*policy.Document, action string) []string {
	set := map[string]bool{}
	for _, d := range docs {
		for i := range d.Statement {
			st := &d.Statement[i]
			if !matchesAction(st, action) {
				continue
			}
			if st.Effect == policy.Deny {
				if len(st.Condition) == 0 && !st.Has("NotResource") && contains(st.Resource, "*") {
					return nil
				}
				continue
			}
			suffix := ""
			if len(st.Condition) > 0 {
				suffix = " if " + st.Condition.Key()
			}
			if st.Has("NotResource") {
				set["NOT("+strings.Join(st.NotResource, ",")+")"+suffix] = true
				continue
			}
			for _, r := range st.Resource {
				set[r+suffix] = true
			}
		}
	}
	return policy.SortedKeys(set)
}

func matchesAction(st *policy.Statement, action string) bool {
	if st.Has("NotAction") {
		for _, p := range st.NotAction {
			if glob.MatchFold(p, action) {
				return false
			}
		}
		return true
	}
	for _, p := range st.Action {
		if glob.MatchFold(p, action) {
			return true
		}
	}
	return false
}

func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

// classify compares scope sets using pattern subsumption.
func classify(before, after []string) Change {
	switch {
	case len(before) == 0 && len(after) == 0:
		return Unchanged
	case len(after) == 0:
		return Removed
	case len(before) == 0:
		return Added
	case strings.Join(before, "\x00") == strings.Join(after, "\x00"):
		return Unchanged
	case coveredBy(after, before):
		return Narrowed
	case coveredBy(before, after):
		return Widened
	default:
		return Changed
	}
}

// coveredBy reports whether every scope in xs is subsumed by some scope in
// ys with the same condition suffix (NOT scopes compare by equality).
func coveredBy(xs, ys []string) bool {
	for _, x := range xs {
		xr, xc := splitScope(x)
		ok := false
		for _, y := range ys {
			yr, yc := splitScope(y)
			if yc != "" && yc != xc {
				continue
			}
			if strings.HasPrefix(xr, "NOT(") || strings.HasPrefix(yr, "NOT(") {
				if xr == yr {
					ok = true
				}
			} else if arn.Subsumes(yr, xr) {
				ok = true
			}
			if ok {
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func splitScope(s string) (resource, cond string) {
	r, c, _ := strings.Cut(s, " if ")
	return r, c
}

// Unified renders a unified diff of the canonical pretty JSON of both sets.
func Unified(before, after []*policy.Document, context int) (string, error) {
	a, err := lines(before)
	if err != nil {
		return "", err
	}
	b, err := lines(after)
	if err != nil {
		return "", err
	}
	ops := align(a, b)
	return render(ops, context), nil
}

func lines(docs []*policy.Document) ([]string, error) {
	var out []string
	for i, d := range docs {
		if len(docs) > 1 {
			out = append(out, fmt.Sprintf("// document %d", i+1))
		}
		b, err := d.Pretty()
		if err != nil {
			return nil, err
		}
		out = append(out, strings.Split(strings.TrimRight(string(b), "\n"), "\n")...)
	}
	return out, nil
}

type op struct {
	kind byte // ' ', '-', '+'
	text string
	a, b int // 1-based line numbers in each side (0 if absent)
}

func align(a, b []string) []op {
	n, m := len(a), len(b)
	if n*m > MaxLCSCells {
		var ops []op
		for i, s := range a {
			ops = append(ops, op{kind: '-', text: s, a: i + 1})
		}
		for j, s := range b {
			ops = append(ops, op{kind: '+', text: s, b: j + 1})
		}
		return ops
	}
	// lcs[i][j] = LCS length of a[i:], b[j:], stored row-major.
	lcs := make([]int32, (n+1)*(m+1))
	at := func(i, j int) int32 { return lcs[i*(m+1)+j] }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i*(m+1)+j] = at(i+1, j+1) + 1
			case at(i+1, j) >= at(i, j+1):
				lcs[i*(m+1)+j] = at(i+1, j)
			default:
				lcs[i*(m+1)+j] = at(i, j+1)
			}
		}
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{kind: ' ', text: a[i], a: i + 1, b: j + 1})
			i++
			j++
		case at(i+1, j) >= at(i, j+1):
			ops = append(ops, op{kind: '-', text: a[i], a: i + 1})
			i++
		default:
			ops = append(ops, op{kind: '+', text: b[j], b: j + 1})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{kind: '-', text: a[i], a: i + 1})
	}
	for ; j < m; j++ {
		ops = append(ops, op{kind: '+', text: b[j], b: j + 1})
	}
	return ops
}

// render groups edit operations into hunks with the given context lines.
func render(ops []op, context int) string {
	var changed []int
	for i, o := range ops {
		if o.kind != ' ' {
			changed = append(changed, i)
		}
	}
	if len(changed) == 0 {
		return ""
	}
	type span struct{ lo, hi int }
	var spans []span
	for _, c := range changed {
		lo, hi := max(0, c-context), min(len(ops)-1, c+context)
		if len(spans) > 0 && lo <= spans[len(spans)-1].hi+1 {
			spans[len(spans)-1].hi = max(spans[len(spans)-1].hi, hi)
			continue
		}
		spans = append(spans, span{lo, hi})
	}
	var b strings.Builder
	b.WriteString("--- before\n+++ after\n")
	for _, s := range spans {
		aStart, bStart, aLen, bLen := 0, 0, 0, 0
		for _, o := range ops[s.lo : s.hi+1] {
			if o.a > 0 {
				if aStart == 0 {
					aStart = o.a
				}
				aLen++
			}
			if o.b > 0 {
				if bStart == 0 {
					bStart = o.b
				}
				bLen++
			}
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", aStart, aLen, bStart, bLen)
		for _, o := range ops[s.lo : s.hi+1] {
			b.WriteByte(o.kind)
			b.WriteString(o.text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// SortChanges orders action changes by kind severity then name.
func SortChanges(cs []ActionChange) {
	rank := map[Change]int{Added: 0, Widened: 1, Changed: 2, Narrowed: 3, Removed: 4}
	sort.SliceStable(cs, func(i, j int) bool {
		if rank[cs[i].Change] != rank[cs[j].Change] {
			return rank[cs[i].Change] < rank[cs[j].Change]
		}
		return cs[i].Action < cs[j].Action
	})
}
