// Package generator builds least-privilege identity policies from observed
// activity.
//
// For each principal it (1) replays every distinct observed call through the
// original policies to find the Allow statement that granted it (the
// "source"), (2) groups calls by source statement and action, (3) collapses
// resources (and, in aggressive mode, read-only actions) into wildcards, and
// (4) assembles statements that inherit their source's Condition block. The
// original policies' Deny statements are copied verbatim.
//
// Two invariants hold by construction and are re-checked by package verify
// and by property tests:
//
//   - superset of observed: every call the original policies allowed is
//     allowed by the generated policy (same conditions, same denies);
//   - subset of original: every (action pattern, resource pattern) pair
//     emitted is proved covered by its source statement via sound pattern
//     subsumption, and conditions and denies are unchanged, so the generated
//     policy never allows a request the original denied.
//
// Complexity for E distinct observations, S original statements and N
// distinct resources per (source, action): attribution is O(E * S * m) where
// m is the per-statement match cost; collapsing is O(N * L) per group;
// assembly is O(G log G) for G generated statements.
package generator

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/glob"
	"github.com/lutherleo/leastpriv/internal/mapper"
	"github.com/lutherleo/leastpriv/internal/policy"
)

// Level selects how aggressively wildcards are introduced.
type Level string

// Aggressiveness levels.
const (
	// LevelExact lists every observed action and resource verbatim.
	LevelExact Level = "exact"
	// LevelModerate collapses uniform resource partitions bottom-up (a
	// folder with >= 3 children, each a leaf or itself collapsed) into
	// "parent/*"; actions are never wildcarded.
	LevelModerate Level = "moderate"
	// LevelAggressive collapses resource subtrees and name prefixes (>= 2
	// siblings by default) and folds read-only actions sharing a verb into
	// "service:Verb*" when every catalog action it matches is List/Read.
	LevelAggressive Level = "aggressive"
)

// ParseLevel validates a level name.
func ParseLevel(s string) (Level, error) {
	switch Level(s) {
	case LevelExact, LevelModerate, LevelAggressive:
		return Level(s), nil
	}
	return "", fmt.Errorf("unknown level %q (want exact, moderate or aggressive)", s)
}

// Options configures generation.
type Options struct {
	Level Level
	// MinSiblings overrides the level's resource-collapse threshold when > 0.
	MinSiblings int
	// MinActions is the aggressive action-collapse threshold (default 3).
	MinActions int
	// MaxSize splits the output into several documents when > 0 and the
	// policy is larger than this many characters (whitespace excluded).
	MaxSize int
}

func (o Options) collapser(cat *catalog.Catalog) *collapser {
	c := &collapser{cat: cat}
	switch o.Level {
	case LevelModerate:
		c.minSiblings, c.bottomUp = 3, true
	case LevelAggressive:
		c.minSiblings, c.namePrefix = 2, true
	default:
		return nil
	}
	if o.MinSiblings > 0 {
		c.minSiblings = o.MinSiblings
	}
	return c
}

// Input is one principal's original policies and activity.
type Input struct {
	Principal    *authz.Principal
	Observations []activity.Observation
}

// SourceRef identifies the original statement a generated grant derives from.
type SourceRef struct {
	Policy    string `json:"policy"`
	Statement int    `json:"statement"`
	Sid       string `json:"sid,omitempty"`
}

// Ungranted is an observed successful call the original policies do not
// allow (it must have been granted by something outside the analysed
// policies, such as a resource-based policy).
type Ungranted struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Count    int    `json:"count"`
}

// Skipped is an observation left out of the generated policy (or, in
// Result.Fallbacks, one that could not be narrowed).
type Skipped struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Reason   string `json:"reason"`
	Count    int    `json:"count"`
}

// Expansion records actions an aggressive action wildcard grants beyond those observed.
type Expansion struct {
	Pattern    string   `json:"pattern"`
	Observed   []string `json:"observed"`
	Unobserved []string `json:"unobserved"`
}

// Grant is one generated (actions, resources, condition) statement with provenance.
type Grant struct {
	Sid       string   `json:"sid"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources,omitempty"`
	// NotResource is set (instead of Resources) only when the source
	// statement's NotResource uses policy variables and is copied verbatim.
	NotResource []string         `json:"notResource,omitempty"`
	Condition   policy.Condition `json:"condition,omitempty"`
	Sources     []SourceRef      `json:"sources"`
}

// Result is the generator output for one principal.
type Result struct {
	Principal string             `json:"principal"`
	Level     Level              `json:"level"`
	Policy    *policy.Document   `json:"policy,omitempty"`
	Parts     []*policy.Document `json:"parts,omitempty"`
	Size      int                `json:"size"`
	// ObservedCalls counts distinct (action, resource, relevant-context)
	// observations; GrantedCalls those the original policies allowed.
	ObservedCalls int         `json:"observedCalls"`
	GrantedCalls  int         `json:"grantedCalls"`
	Grants        []Grant     `json:"grants"`
	Denies        int         `json:"copiedDenies"`
	Ungranted     []Ungranted `json:"ungranted,omitempty"`
	Skipped       []Skipped   `json:"skipped,omitempty"`
	// Fallbacks lists observations whose resource could not be scoped
	// provably, so the action kept its source statement's resource element.
	Fallbacks  []Skipped    `json:"fallbacks,omitempty"`
	Collapses  []Collapse   `json:"collapses,omitempty"`
	Expansions []Expansion  `json:"expansions,omitempty"`
	Warnings   []string     `json:"warnings,omitempty"`
	Attributed []Attributed `json:"-"`
}

// Attributed is a granted observation with the source statement that granted
// it; verification replays these.
type Attributed struct {
	Observation activity.Observation
	Source      SourceRef
	Uncertain   bool
}

type sourceKey struct {
	policy int
	stmt   int
}

type actionGroup struct {
	resources map[string]bool
}

// Generate builds the least-privilege policy for one principal.
func Generate(cat *catalog.Catalog, in Input, opts Options) (*Result, error) {
	if opts.Level == "" {
		opts.Level = LevelModerate
	}
	if _, err := ParseLevel(string(opts.Level)); err != nil {
		return nil, err
	}
	if opts.MinActions <= 0 {
		opts.MinActions = 3
	}
	p := in.Principal
	set, err := p.PolicySet()
	if err != nil {
		return nil, err
	}
	res := &Result{Principal: p.ARN, Level: opts.Level}
	res.Warnings = append(res.Warnings, p.Warnings...)

	refKeys := map[string]bool{}
	for _, cp := range set.Identity {
		for _, k := range cp.ReferencedKeys() {
			refKeys[k] = true
		}
	}
	if set.Boundary != nil {
		for _, k := range set.Boundary.ReferencedKeys() {
			refKeys[k] = true
		}
	}
	keys := policy.SortedKeys(refKeys)

	ungranted := map[string]*Ungranted{}
	skipped := map[string]*Skipped{}
	fallbacks := map[string]*Skipped{}
	groups := map[sourceKey]map[string]*actionGroup{}
	seen := map[string]bool{}
	for _, o := range in.Observations {
		if o.Denied {
			continue
		}
		if o.NoAuth {
			addSkip(skipped, o, "action requires no IAM permission")
			continue
		}
		sig := o.Action + "\x00" + o.Resource + "\x00" + contextSignature(o.Context, keys)
		if seen[sig] {
			continue
		}
		seen[sig] = true
		res.ObservedCalls++
		ev := set.Evaluate(o.Request())
		if !ev.Allowed() {
			k := o.Action + "\x00" + o.Resource + "\x00" + ev.Decision.String()
			if u, ok := ungranted[k]; ok {
				u.Count++
			} else {
				ungranted[k] = &Ungranted{Action: o.Action, Resource: o.Resource, Decision: ev.Decision.String(), Reason: ev.Reason, Count: 1}
			}
			continue
		}
		src, ok := pickSource(p, ev)
		if !ok {
			return nil, fmt.Errorf("internal error: allowed call %s on %s has no identity Allow statement", o.Action, o.Resource)
		}
		res.GrantedCalls++
		ref := SourceRef{Policy: p.Policies[src.policy].Name, Statement: src.stmt, Sid: p.Policies[src.policy].Doc.Statement[src.stmt].Sid}
		res.Attributed = append(res.Attributed, Attributed{Observation: o, Source: ref, Uncertain: ev.Uncertain})
		action := canonicalAction(cat, o.Action)
		if groups[src] == nil {
			groups[src] = map[string]*actionGroup{}
		}
		ag := groups[src][action]
		if ag == nil {
			ag = &actionGroup{resources: map[string]bool{}}
			groups[src][action] = ag
		}
		ag.resources[internalResource(o)] = true
	}

	col := opts.collapser(cat)
	var grants []Grant
	expansions := map[string]*Expansion{}
	srcKeys := make([]sourceKey, 0, len(groups))
	for k := range groups {
		srcKeys = append(srcKeys, k)
	}
	sort.Slice(srcKeys, func(i, j int) bool {
		if srcKeys[i].policy != srcKeys[j].policy {
			return srcKeys[i].policy < srcKeys[j].policy
		}
		return srcKeys[i].stmt < srcKeys[j].stmt
	})
	for _, sk := range srcKeys {
		doc := p.Policies[sk.policy].Doc
		st := doc.Statement[sk.stmt]
		ref := SourceRef{Policy: p.Policies[sk.policy].Name, Statement: sk.stmt, Sid: st.Sid}
		cond := adaptCondition(st.Condition, doc.EffectiveVersion())
		cov := coverage{st: &st, version: doc.EffectiveVersion()}
		byResources := map[string]*Grant{}
		var order []string
		for _, action := range sortedActionKeys(groups[sk]) {
			ag := groups[sk][action]
			resources, notResources := cov.resourcesFor(policy.SortedKeys(ag.resources))
			if !cov.variableResources() {
				if col != nil {
					var evs []Collapse
					resources, evs = col.collapse(action, policy.ServiceOf(action), resources, cov.resourceCovered)
					for i := range evs {
						evs[i].Pattern = iamLiteral(evs[i].Pattern)
					}
					res.Collapses = append(res.Collapses, evs...)
				}
				uncovered := false
				for _, r := range resources {
					if !cov.resourceCovered(r) {
						uncovered = true
						addSkipKey(fallbacks, action, iamLiteral(r), "resource only partially known (pattern) and not provably inside the source statement; kept the source statement's resource scope for this action")
					}
				}
				if uncovered {
					// Fall back to the source's own resource element: still a
					// subset of the original, and it allows the observed call.
					resources, notResources = cov.sourceResources()
				} else {
					resources = iamLiterals(resources)
				}
			}
			if len(resources) == 0 && len(notResources) == 0 {
				continue
			}
			rk := strings.Join(resources, "\x00") + "\x01" + strings.Join(notResources, "\x00")
			g, ok := byResources[rk]
			if !ok {
				g = &Grant{Resources: resources, NotResource: notResources, Condition: cond, Sources: []SourceRef{ref}}
				byResources[rk] = g
				order = append(order, rk)
			}
			g.Actions = append(g.Actions, action)
		}
		for _, rk := range order {
			g := byResources[rk]
			if opts.Level == LevelAggressive && !cov.st.Has("NotAction") {
				g.Actions = collapseActions(cat, g.Actions, opts.MinActions, cov.actionCovered, expansions)
			}
			grants = append(grants, *g)
		}
	}
	grants = mergeGrants(grants)
	res.Grants = grants
	for _, e := range expansions {
		res.Expansions = append(res.Expansions, *e)
	}
	sort.Slice(res.Expansions, func(i, j int) bool { return res.Expansions[i].Pattern < res.Expansions[j].Pattern })
	res.Ungranted = sortedUngranted(ungranted)
	res.Skipped = sortedSkipped(skipped)
	res.Fallbacks = sortedSkipped(fallbacks)

	doc, denies := assemble(p, grants)
	res.Denies = denies
	if doc == nil {
		res.Warnings = append(res.Warnings, "no granted activity observed: no Allow statements generated; consider detaching this principal's policies after confirming the observation window is representative")
		return res, nil
	}
	res.Policy = doc
	size, err := doc.Size()
	if err != nil {
		return nil, err
	}
	res.Size = size
	if issues := engine.Validate(doc); policy.HasErrors(issues) {
		return nil, fmt.Errorf("internal error: generated policy is invalid: %v", issues)
	}
	if opts.MaxSize > 0 && size > opts.MaxSize {
		parts, err := Split(doc, opts.MaxSize)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		} else {
			res.Parts = parts
		}
	}
	return res, nil
}

// contextSignature renders only the context keys the policies reference, so
// observations that differ only in irrelevant context (timestamps) dedupe.
func contextSignature(ctx map[string][]string, keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strings.Join(ctx[k], ","))
		b.WriteByte(';')
	}
	return b.String()
}

// pickSource chooses the identity Allow statement to attribute a call to:
// certain matches first, then statements with conditions (narrower), then
// policy and statement order.
func pickSource(p *authz.Principal, ev engine.Result) (sourceKey, bool) {
	best := sourceKey{-1, -1}
	bestCertain, bestCond := false, false
	for _, m := range ev.Matched {
		if m.Effect != policy.Allow || m.Boundary {
			continue
		}
		pi, ok := p.PolicyIndex(m.Policy)
		if !ok {
			continue
		}
		hasCond := len(p.Policies[pi].Doc.Statement[m.Index].Condition) > 0
		cand := sourceKey{pi, m.Index}
		better := false
		switch {
		case best.policy < 0:
			better = true
		case m.Certain != bestCertain:
			better = m.Certain
		case hasCond != bestCond:
			better = hasCond
		case cand.policy != best.policy:
			better = cand.policy < best.policy
		default:
			better = cand.stmt < best.stmt
		}
		if better {
			best, bestCertain, bestCond = cand, m.Certain, hasCond
		}
	}
	return best, best.policy >= 0
}

func canonicalAction(cat *catalog.Catalog, action string) string {
	if a, ok := cat.Lookup(action); ok {
		return a.FullName()
	}
	return action
}

func sortedActionKeys(m map[string]*actionGroup) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// coverage answers "is this pattern provably inside the source statement?".
type coverage struct {
	st      *policy.Statement
	version string
}

func (c coverage) variableResources() bool {
	if c.version == policy.Version2008 {
		return false
	}
	for _, r := range c.st.Resource {
		if strings.Contains(r, "${") {
			return true
		}
	}
	for _, r := range c.st.NotResource {
		if strings.Contains(r, "${") {
			return true
		}
	}
	return false
}

// resourcesFor returns the resource list to start from: the observed
// resources, or the source's own Resource/NotResource patterns verbatim when
// they use policy variables (concretising them could widen the grant for
// sessions where the variable has a different value).
func (c coverage) resourcesFor(observed []string) (resources, notResources []string) {
	if !c.variableResources() {
		return observed, nil
	}
	return c.sourceResources()
}

// sourceResources copies the source statement's Resource or NotResource
// element for use in the 2012-10-17 output. Text from a 2008-10-17 source is
// literal there, so its '${' is escaped; copied verbatim it would become a
// live policy variable and widen the grant.
func (c coverage) sourceResources() (resources, notResources []string) {
	src := c.st.Resource
	if c.st.Has("NotResource") {
		src = c.st.NotResource
	}
	out := make([]string, len(src))
	for i, r := range src {
		if c.version == policy.Version2008 {
			r = literalize(r)
		}
		out[i] = r
	}
	if c.st.Has("NotResource") {
		return nil, out
	}
	return out, nil
}

func (c coverage) resourceCovered(r string) bool {
	if c.st.Has("NotResource") {
		if arn.IsPattern(r) {
			return false
		}
		for _, nr := range c.st.NotResource {
			if arn.Match(nr, r) {
				return false
			}
		}
		return true
	}
	for _, sr := range c.st.Resource {
		if arn.Subsumes(sr, r) {
			return true
		}
	}
	return false
}

func (c coverage) actionCovered(a string) bool {
	if c.st.Has("NotAction") {
		if glob.HasWildcard(a) {
			return false
		}
		for _, na := range c.st.NotAction {
			if glob.MatchFold(na, a) {
				return false
			}
		}
		return true
	}
	for _, sa := range c.st.Action {
		if glob.SubsumesFold(sa, a) {
			return true
		}
	}
	return false
}

// collapseActions folds same-verb actions into "svc:Verb*" when at least
// minActions share the verb, the wildcard is covered by the source, and every
// catalog action it matches is List or Read.
func collapseActions(cat *catalog.Catalog, actions []string, minActions int, covered func(string) bool, exp map[string]*Expansion) []string {
	byVerb := map[string][]string{}
	var keys []string
	for _, a := range actions {
		svc, name, ok := strings.Cut(a, ":")
		if !ok {
			continue
		}
		k := svc + ":" + catalog.Verb(name)
		if _, seen := byVerb[k]; !seen {
			keys = append(keys, k)
		}
		byVerb[k] = append(byVerb[k], a)
	}
	var out []string
	for _, k := range keys {
		members := byVerb[k]
		pattern := k + "*"
		if len(members) < minActions || !covered(pattern) || !readOnlyExpansion(cat, pattern) {
			out = append(out, members...)
			continue
		}
		out = append(out, pattern)
		observed := map[string]bool{}
		for _, m := range members {
			observed[strings.ToLower(m)] = true
		}
		e := exp[pattern]
		if e == nil {
			e = &Expansion{Pattern: pattern}
			exp[pattern] = e
		}
		e.Observed = mergeSorted(e.Observed, members)
		var unobserved []string
		for _, a := range cat.Expand(pattern) {
			if !observed[strings.ToLower(a.FullName())] {
				unobserved = append(unobserved, a.FullName())
			}
		}
		e.Unobserved = mergeSorted(e.Unobserved, unobserved)
	}
	sort.Strings(out)
	return out
}

func readOnlyExpansion(cat *catalog.Catalog, pattern string) bool {
	matched := cat.Expand(pattern)
	if len(matched) == 0 {
		return false
	}
	for _, a := range matched {
		if a.Access != catalog.AccessList && a.Access != catalog.AccessRead {
			return false
		}
	}
	return true
}

func mergeSorted(a, b []string) []string {
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		m[s] = true
	}
	return policy.SortedKeys(m)
}

// mergeGrants merges grants with equal conditions and equal resource sets
// (union of actions), then equal conditions and equal action sets (union of
// resources). Both merges preserve the set of allowed (action, resource)
// pairs exactly.
func mergeGrants(gs []Grant) []Grant {
	for _, g := range gs {
		sort.Strings(g.Actions)
	}
	pass := func(gs []Grant, key func(Grant) string, merge func(dst *Grant, src Grant)) []Grant {
		idx := map[string]int{}
		var out []Grant
		for _, g := range gs {
			k := g.Condition.Key() + "\x01" + key(g)
			if i, ok := idx[k]; ok {
				merge(&out[i], g)
				continue
			}
			idx[k] = len(out)
			out = append(out, g)
		}
		return out
	}
	gs = pass(gs, func(g Grant) string {
		return strings.Join(g.Resources, "\x00") + "\x01" + strings.Join(g.NotResource, "\x00")
	}, func(dst *Grant, src Grant) {
		dst.Actions = mergeSorted(dst.Actions, src.Actions)
		dst.Sources = appendSources(dst.Sources, src.Sources)
	})
	gs = pass(gs, func(g Grant) string {
		if len(g.NotResource) > 0 {
			// NotResource lists cannot be unioned; keep such grants apart.
			return "\x02" + strings.Join(g.Actions, "\x00") + "\x01" + strings.Join(g.NotResource, "\x00")
		}
		return strings.Join(g.Actions, "\x00")
	}, func(dst *Grant, src Grant) {
		dst.Resources = mergeSorted(dst.Resources, src.Resources)
		dst.Sources = appendSources(dst.Sources, src.Sources)
	})
	sort.SliceStable(gs, func(i, j int) bool {
		si, sj := grantService(gs[i]), grantService(gs[j])
		if si != sj {
			return si < sj
		}
		return strings.Join(gs[i].Actions, ",") < strings.Join(gs[j].Actions, ",")
	})
	return gs
}

func appendSources(a, b []SourceRef) []SourceRef {
	seen := map[SourceRef]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			a = append(a, s)
			seen[s] = true
		}
	}
	return a
}

func grantService(g Grant) string {
	svcs := map[string]bool{}
	for _, a := range g.Actions {
		svcs[policy.ServiceOf(a)] = true
	}
	keys := policy.SortedKeys(svcs)
	if len(keys) == 1 {
		return keys[0]
	}
	return "~multi"
}

// assemble renders grants as Allow statements, appends the original Deny
// statements, and assigns Sids.
func assemble(p *authz.Principal, grants []Grant) (*policy.Document, int) {
	if len(grants) == 0 {
		return nil, 0
	}
	doc := &policy.Document{Version: policy.Version2012}
	used := map[string]int{}
	sids := map[string]bool{}
	for i := range grants {
		g := &grants[i]
		name := "Multi"
		if svc := grantService(*g); svc != "~multi" {
			name = alnumTitle(svc)
		}
		used[name]++
		sid := "Allow" + name
		if used[name] > 1 {
			sid = fmt.Sprintf("Allow%sN%d", name, used[name])
		}
		g.Sid = sid
		sids[sid] = true
		st := policy.Statement{Sid: sid, Effect: policy.Allow, Action: policy.Values(g.Actions), Condition: g.Condition}
		if len(g.NotResource) > 0 {
			st.NotResource = policy.Values(g.NotResource)
		} else {
			st.Resource = policy.Values(g.Resources)
		}
		doc.Statement = append(doc.Statement, st)
	}
	denies := 0
	seenDeny := map[string]bool{}
	for _, nd := range p.Policies {
		for _, st := range nd.Doc.Statement {
			if st.Effect != policy.Deny {
				continue
			}
			c := adaptStatement(st.Clone(), nd.Doc.EffectiveVersion())
			key, err := json.Marshal(policy.Statement{Effect: c.Effect, Action: c.Action, NotAction: c.NotAction, Resource: c.Resource, NotResource: c.NotResource, Condition: c.Condition})
			if err != nil || seenDeny[string(key)] {
				continue
			}
			seenDeny[string(key)] = true
			if c.Sid == "" || sids[c.Sid] {
				c.Sid = fmt.Sprintf("Deny%d", denies+1)
				for sids[c.Sid] {
					c.Sid += "x"
				}
			}
			sids[c.Sid] = true
			doc.Statement = append(doc.Statement, c)
			denies++
		}
	}
	return doc, denies
}

func alnumTitle(s string) string {
	var b strings.Builder
	up := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			if up {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			up = false
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			up = false
		default:
			up = true
		}
	}
	return b.String()
}

// internalResource returns the observed resource in the generator's internal
// pattern form. Exactly mapped resources are literal strings, so any '*' or
// '?' they contain (object keys may hold both) is escaped to glob's literal
// runes; partially mapped resources keep their '*' placeholders, which stand
// for unknown ARN parts.
func internalResource(o activity.Observation) string {
	if o.Confidence == mapper.ConfidencePartial || o.Resource == "*" {
		return o.Resource
	}
	return glob.Escape(o.Resource)
}

// iamLiteralReplacer renders internal patterns as 2012-10-17 policy text:
// literal '*' and '?' become ${*} and ${?}, and a literal "${" becomes
// "${$}{" so it is not read as a policy variable.
var iamLiteralReplacer = strings.NewReplacer(
	"${", "${$}{",
	string(glob.LiteralStar), "${*}",
	string(glob.LiteralQuestion), "${?}",
)

func iamLiteral(s string) string { return iamLiteralReplacer.Replace(s) }

func iamLiterals(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = iamLiteral(s)
	}
	return out
}

// literalize protects text that a 2008-10-17 policy treated literally from
// being read as a policy variable in the 2012-10-17 output.
func literalize(s string) string { return strings.ReplaceAll(s, "${", "${$}{") }

func adaptCondition(c policy.Condition, version string) policy.Condition {
	c = c.Clone()
	if version != policy.Version2008 {
		return c
	}
	for _, kv := range c {
		for k, vals := range kv {
			for i := range vals {
				vals[i] = literalize(vals[i])
			}
			kv[k] = vals
		}
	}
	return c
}

func adaptStatement(st policy.Statement, version string) policy.Statement {
	if version != policy.Version2008 {
		return st
	}
	for i := range st.Resource {
		st.Resource[i] = literalize(st.Resource[i])
	}
	for i := range st.NotResource {
		st.NotResource[i] = literalize(st.NotResource[i])
	}
	st.Condition = adaptCondition(st.Condition, version)
	return st
}

func addSkip(m map[string]*Skipped, o activity.Observation, reason string) {
	addSkipKey(m, o.Action, o.Resource, reason)
}

func addSkipKey(m map[string]*Skipped, action, resource, reason string) {
	k := action + "\x00" + resource + "\x00" + reason
	if s, ok := m[k]; ok {
		s.Count++
		return
	}
	m[k] = &Skipped{Action: action, Resource: resource, Reason: reason, Count: 1}
}

func sortedUngranted(m map[string]*Ungranted) []Ungranted {
	out := make([]Ungranted, 0, len(m))
	for _, u := range m {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

func sortedSkipped(m map[string]*Skipped) []Skipped {
	out := make([]Skipped, 0, len(m))
	for _, s := range m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}
