// Package verify checks a generated policy against the original policies
// and the observed activity:
//
//   - Replay (superset of observed): every observed successful call that the
//     original policies allow must be allowed by the generated policy under
//     the same reconstructed request context.
//   - Differential subset check (subset of original): over a request universe
//     built from catalog actions, observed resources, and probe resources
//     instantiated from every pattern in either policy, no request may be
//     allowed by the generated policy but denied by the original. Each
//     request is evaluated with all context keys unknown (optimistic
//     semantics, identical for both policy sets) and with up to MaxContexts
//     observed contexts.
//
// Replay costs O(E * S) evaluations for E observations; the subset check
// evaluates at most MaxPairs requests twice per context.
package verify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/policy"
)

// Options bounds the differential check.
type Options struct {
	// MaxPairs caps the (action, resource) pairs checked per context
	// (default 250000). Pairs beyond the cap are skipped deterministically
	// by stride sampling and the report says so.
	MaxPairs int
	// MaxContexts caps how many distinct observed contexts are used in
	// addition to the all-unknown context (default 3).
	MaxContexts int
}

// Failure is an observed call the generated policy does not allow.
type Failure struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	EventID  string `json:"eventId"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// Violation is a request the generated policy allows but the original does not.
type Violation struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Context  string `json:"context"`
	Original string `json:"original"`
}

// Report is the verification outcome for one principal.
type Report struct {
	Principal        string      `json:"principal"`
	Replayed         int         `json:"replayed"`
	ReplayAllowed    int         `json:"replayAllowed"`
	ReplaySkipped    int         `json:"replaySkippedNotGrantedByOriginal"`
	UncertainReplays int         `json:"uncertainReplays"`
	Failures         []Failure   `json:"failures,omitempty"`
	SubsetActions    int         `json:"subsetActions"`
	SubsetResources  int         `json:"subsetResources"`
	SubsetContexts   int         `json:"subsetContexts"`
	SubsetChecked    int         `json:"subsetChecked"`
	SubsetSampled    bool        `json:"subsetSampled"`
	GeneratedAllows  int         `json:"generatedAllows"`
	Violations       []Violation `json:"violations,omitempty"`
	OK               bool        `json:"ok"`
}

// Verify checks generated documents (all parts, if split) for principal p.
func Verify(cat *catalog.Catalog, p *authz.Principal, generated []*policy.Document, obs []activity.Observation, opts Options) (*Report, error) {
	if opts.MaxPairs <= 0 {
		opts.MaxPairs = 250000
	}
	if opts.MaxContexts < 0 {
		opts.MaxContexts = 0
	} else if opts.MaxContexts == 0 {
		opts.MaxContexts = 3
	}
	orig, err := p.PolicySet()
	if err != nil {
		return nil, err
	}
	gen := &engine.Set{Boundary: orig.Boundary}
	for i, d := range generated {
		c, err := engine.Compile(fmt.Sprintf("generated%d", i+1), d)
		if err != nil {
			return nil, fmt.Errorf("compile generated policy: %w", err)
		}
		gen.Identity = append(gen.Identity, c)
	}
	rep := &Report{Principal: p.ARN}

	// Replay.
	seen := map[string]bool{}
	var contexts []map[string][]string
	ctxSeen := map[string]bool{}
	for _, o := range obs {
		if o.Denied || o.NoAuth {
			continue
		}
		req := o.Request()
		oe := orig.Evaluate(req)
		if !oe.Allowed() {
			rep.ReplaySkipped++
			continue
		}
		rep.Replayed++
		ge := gen.Evaluate(req)
		if ge.Allowed() {
			rep.ReplayAllowed++
			if ge.Uncertain {
				rep.UncertainReplays++
			}
		} else {
			k := o.Action + "\x00" + o.Resource
			if !seen[k] {
				seen[k] = true
				rep.Failures = append(rep.Failures, Failure{Action: o.Action, Resource: o.Resource, EventID: o.EventID, Decision: ge.Decision.String(), Reason: ge.Reason})
			}
		}
		if len(contexts) < opts.MaxContexts {
			sig := ctxSig(o.Context)
			if !ctxSeen[sig] {
				ctxSeen[sig] = true
				contexts = append(contexts, o.Context)
			}
		}
	}

	// Differential subset check.
	actions := actionUniverse(cat, p, generated, obs)
	resources := resourceUniverse(cat, p, generated, obs)
	rep.SubsetActions, rep.SubsetResources = len(actions), len(resources)
	total := len(actions) * len(resources)
	stride := 1
	if total > opts.MaxPairs {
		stride = (total + opts.MaxPairs - 1) / opts.MaxPairs
		rep.SubsetSampled = true
	}
	reqs := []engine.Request{{Unknown: engine.AllUnknown}}
	for _, c := range contexts {
		reqs = append(reqs, engine.Request{Context: c, Unknown: activity.UnknownFunc(false)})
	}
	rep.SubsetContexts = len(reqs)
	vioSeen := map[string]bool{}
	for ci, base := range reqs {
		for i := 0; i < total; i += stride {
			req := base
			req.Action = actions[i/len(resources)]
			req.Resource = resources[i%len(resources)]
			rep.SubsetChecked++
			if !gen.Evaluate(req).Allowed() {
				continue
			}
			rep.GeneratedAllows++
			oe := orig.Evaluate(req)
			if oe.Allowed() {
				continue
			}
			k := req.Action + "\x00" + req.Resource
			if vioSeen[k] || len(rep.Violations) >= 50 {
				continue
			}
			vioSeen[k] = true
			label := "all-unknown"
			if ci > 0 {
				label = fmt.Sprintf("observed#%d", ci)
			}
			rep.Violations = append(rep.Violations, Violation{Action: req.Action, Resource: req.Resource, Context: label, Original: oe.Decision.String()})
		}
	}
	rep.OK = len(rep.Failures) == 0 && len(rep.Violations) == 0
	return rep, nil
}

func ctxSig(ctx map[string][]string) string {
	keys := policy.SortedKeys(ctx)
	var b strings.Builder
	for _, k := range keys {
		if k == "aws:currenttime" || k == "aws:epochtime" {
			continue
		}
		fmt.Fprintf(&b, "%s=%s;", k, strings.Join(ctx[k], ","))
	}
	return b.String()
}

// actionUniverse returns catalog actions of every service mentioned by either
// policy set or the activity, plus literal actions named anywhere.
func actionUniverse(cat *catalog.Catalog, p *authz.Principal, gen []*policy.Document, obs []activity.Observation) []string {
	services := map[string]bool{}
	set := map[string]bool{}
	all := false
	addPattern := func(a string) {
		svc := policy.ServiceOf(a)
		if a == "*" || strings.ContainsAny(svc, "*?") {
			all = true
			return
		}
		services[svc] = true
		if !strings.ContainsAny(a, "*?") {
			set[a] = true
		}
	}
	for _, d := range allDocs(p, gen) {
		for _, st := range d.Statement {
			for _, a := range st.Action {
				addPattern(a)
			}
			if len(st.NotAction) > 0 {
				all = true // NotAction grants or denies every other action
			}
		}
	}
	for _, o := range obs {
		addPattern(o.Action)
	}
	for _, a := range cat.Actions() {
		if all || services[a.Service()] {
			set[a.FullName()] = true
		}
	}
	return policy.SortedKeys(set)
}

func allDocs(p *authz.Principal, gen []*policy.Document) []*policy.Document {
	var out []*policy.Document
	for _, nd := range p.Policies {
		out = append(out, nd.Doc)
	}
	if p.Boundary != nil {
		out = append(out, p.Boundary.Doc)
	}
	return append(out, gen...)
}

// resourceUniverse builds probe resources: "*", every observed resource,
// several instantiations of every resource pattern in either policy set, and
// a fresh resource of every catalog type in each observed account/region.
func resourceUniverse(cat *catalog.Catalog, p *authz.Principal, gen []*policy.Document, obs []activity.Observation) []string {
	set := map[string]bool{"*": true}
	envs := map[[2]string]bool{}
	account := ""
	if a, err := arn.Parse(p.ARN); err == nil {
		account = a.Account
	}
	envs[[2]string{"us-east-1", account}] = true
	for _, o := range obs {
		set[o.Resource] = true
		if a, err := arn.Parse(o.Resource); err == nil && a.Region != "" && a.Account != "" {
			envs[[2]string{a.Region, a.Account}] = true
		}
	}
	for _, d := range allDocs(p, gen) {
		for _, st := range d.Statement {
			for _, r := range append(append([]string{}, st.Resource...), st.NotResource...) {
				for _, probe := range instantiate(r) {
					set[probe] = true
				}
			}
		}
	}
	for env := range envs {
		for _, s := range cat.Services {
			for i := range s.ResourceTypes {
				tmpl := s.ResourceTypes[i].Template(arn.PartitionForRegion(env[0]), env[0], env[1])
				for _, probe := range instantiate(tmpl) {
					set[probe] = true
				}
			}
		}
	}
	out := policy.SortedKeys(set)
	sort.Strings(out)
	return out
}

// instantiate returns concrete members of a resource pattern: wildcards
// replaced by probe text, by the empty string, and by a path-crossing value,
// with policy variables replaced by a probe token.
func instantiate(pattern string) []string {
	if pattern == "*" {
		return nil
	}
	p := pattern
	for {
		i := strings.Index(p, "${")
		if i < 0 {
			break
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			break
		}
		p = p[:i] + "lpvar" + p[i+j+1:]
	}
	if !strings.ContainsAny(p, "*?") {
		return []string{p}
	}
	repl := func(star, q string) string {
		return strings.NewReplacer("*", star, "?", q).Replace(p)
	}
	return []string{repl("lpprobe", "x"), repl("", "y"), repl("lp/deep/probe", "z")}
}
