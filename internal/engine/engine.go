// Package engine evaluates IAM identity-based policies (optionally
// intersected with a permissions boundary) against authorization requests.
//
// It mirrors AWS's documented evaluation logic for this scope:
//
//  1. By default every request is implicitly denied.
//  2. An explicit Deny in any identity policy or the permissions boundary
//     overrides any Allow.
//  3. Otherwise the request is allowed when an identity policy allows it
//     and, if a permissions boundary is set, the boundary also allows it.
//
// A statement applies when its Action (or NotAction), Resource (or
// NotResource) and every Condition operator match. Actions match
// case-insensitively; resources match case-sensitively; '*' and '?' are
// wildcards. Resource-based policies, SCPs/RCPs and session policies are out
// of scope (see docs/ARCHITECTURE.md).
//
// Evaluating one request costs O(S * (A + R + C)) where S is the number of
// statements and A, R, C are the pattern-matching costs of the action,
// resource and condition elements.
package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/glob"
	"github.com/lutherleo/leastpriv/internal/policy"
)

// Decision is the outcome of an evaluation.
type Decision uint8

// Decisions.
const (
	ImplicitDeny Decision = iota
	Allow
	ExplicitDeny
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allowed"
	case ExplicitDeny:
		return "explicitDeny"
	default:
		return "implicitDeny"
	}
}

// MarshalText renders the decision as its String form.
func (d Decision) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

type compiledStmt struct {
	index       int
	sid         string
	effect      policy.Effect
	notAction   bool
	actions     []string // lower-cased patterns
	notResource bool
	resources   []string
	conds       []condition
}

// Policy is a compiled policy document ready for repeated evaluation.
type Policy struct {
	Name    string
	Doc     *policy.Document
	version string
	stmts   []compiledStmt
}

// Compile prepares a policy document for evaluation. It rejects documents
// the engine cannot evaluate faithfully (unknown condition operators,
// malformed literal values, statements without Action/Resource elements).
func Compile(name string, doc *policy.Document) (*Policy, error) {
	p := &Policy{Name: name, Doc: doc, version: doc.EffectiveVersion()}
	for i := range doc.Statement {
		st := &doc.Statement[i]
		if st.Effect != policy.Allow && st.Effect != policy.Deny {
			return nil, fmt.Errorf("policy %s statement %d: invalid Effect %q", name, i, st.Effect)
		}
		cs := compiledStmt{index: i, sid: st.Sid, effect: st.Effect}
		switch {
		case st.Has("Action") && !st.Has("NotAction"):
			cs.actions = lowerAll(st.Action)
		case st.Has("NotAction") && !st.Has("Action"):
			cs.notAction, cs.actions = true, lowerAll(st.NotAction)
		default:
			return nil, fmt.Errorf("policy %s statement %d: exactly one of Action/NotAction is required", name, i)
		}
		switch {
		case st.Has("Resource") && !st.Has("NotResource"):
			cs.resources = st.Resource
		case st.Has("NotResource") && !st.Has("Resource"):
			cs.notResource, cs.resources = true, st.NotResource
		default:
			return nil, fmt.Errorf("policy %s statement %d: exactly one of Resource/NotResource is required", name, i)
		}
		for _, op := range policy.SortedKeys(st.Condition) {
			for _, key := range policy.SortedKeys(st.Condition[op]) {
				c, err := newCondition(op, key, st.Condition[op][key], p.version)
				if err != nil {
					return nil, fmt.Errorf("policy %s statement %d: %w", name, i, err)
				}
				cs.conds = append(cs.conds, c)
			}
		}
		p.stmts = append(p.stmts, cs)
	}
	return p, nil
}

// MustCompile is Compile that panics on error; for tests and fixtures.
func MustCompile(name string, doc *policy.Document) *Policy {
	p, err := Compile(name, doc)
	if err != nil {
		panic(err)
	}
	return p
}

func lowerAll(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = strings.ToLower(s)
	}
	return out
}

// ReferencedKeys returns the lower-cased context keys any statement depends
// on, through conditions or policy variables.
func (p *Policy) ReferencedKeys() []string {
	seen := map[string]bool{}
	for _, st := range p.stmts {
		for _, c := range st.conds {
			seen[c.key] = true
			for _, v := range c.values {
				for _, k := range variableKeys(v) {
					seen[k] = true
				}
			}
		}
		for _, r := range st.resources {
			for _, k := range variableKeys(r) {
				seen[k] = true
			}
		}
	}
	return policy.SortedKeys(seen)
}

func (st *compiledStmt) matchAction(action string) bool {
	hit := false
	for _, a := range st.actions {
		if glob.MatchFold(a, action) {
			hit = true
			break
		}
	}
	return hit != st.notAction
}

func (p *Policy) matchResource(st *compiledStmt, req *Request, unk unknownSet) Tri {
	hit := No
	for _, r := range st.resources {
		pat, state := r, Yes
		if p.version != policy.Version2008 {
			pat, state = substitute(r, req, unk)
		}
		if state == No {
			continue
		}
		if arn.Match(pat, req.Resource) {
			hit = or(hit, state)
			if hit == Yes {
				break
			}
		}
	}
	if st.notResource {
		return not(hit)
	}
	return hit
}

// MatchStatement reports whether statement i of the policy applies to the request.
func (p *Policy) MatchStatement(i int, req Request) Tri {
	return p.matchStmt(&p.stmts[i], &req, nil)
}

func (p *Policy) matchStmt(st *compiledStmt, req *Request, unk unknownSet) Tri {
	if !st.matchAction(req.Action) {
		return No
	}
	res := p.matchResource(st, req, unk)
	if res == No {
		return No
	}
	for i := range st.conds {
		res = and(res, st.conds[i].eval(req, unk))
		if res == No {
			return No
		}
	}
	return res
}

// StatementRef identifies a statement that matched a request.
type StatementRef struct {
	Policy  string        `json:"policy"`
	Index   int           `json:"index"`
	Sid     string        `json:"sid,omitempty"`
	Effect  policy.Effect `json:"effect"`
	Certain bool          `json:"certain"`
	// Boundary is true when the statement belongs to the permissions boundary.
	Boundary bool `json:"boundary,omitempty"`
}

// Result is the outcome of evaluating one request.
type Result struct {
	Decision Decision `json:"decision"`
	// Uncertain is true when the outcome depends on unknown context keys.
	// An uncertain Allow means "allowed if the unknown values satisfy the
	// matching statement's conditions" and no explicit Deny certainly applies.
	Uncertain   bool           `json:"uncertain"`
	Matched     []StatementRef `json:"matched,omitempty"`
	UnknownKeys []string       `json:"unknownKeys,omitempty"`
	Reason      string         `json:"reason"`
}

// Allowed reports whether the decision is Allow (possibly uncertain).
func (r Result) Allowed() bool { return r.Decision == Allow }

// Set is the collection of policies that apply to one principal.
type Set struct {
	Identity []*Policy
	Boundary *Policy
}

type groupOutcome struct {
	allow, deny Tri
}

func evalGroup(ps []*Policy, req *Request, unk unknownSet, boundary bool, matched *[]StatementRef) groupOutcome {
	out := groupOutcome{}
	for _, p := range ps {
		for i := range p.stmts {
			st := &p.stmts[i]
			t := p.matchStmt(st, req, unk)
			if t == No {
				continue
			}
			*matched = append(*matched, StatementRef{
				Policy: p.Name, Index: st.index, Sid: st.sid, Effect: st.effect,
				Certain: t == Yes, Boundary: boundary,
			})
			if st.effect == policy.Deny {
				out.deny = or(out.deny, t)
			} else {
				out.allow = or(out.allow, t)
			}
		}
	}
	return out
}

// Evaluate decides the request against the policy set.
func (s *Set) Evaluate(req Request) Result {
	unk := unknownSet{}
	var res Result
	id := evalGroup(s.Identity, &req, unk, false, &res.Matched)
	allow, deny := id.allow, id.deny
	if s.Boundary != nil {
		b := evalGroup([]*Policy{s.Boundary}, &req, unk, true, &res.Matched)
		allow = and(allow, b.allow)
		deny = or(deny, b.deny)
		if b.allow == No && id.allow != No && deny != Yes {
			res.Decision = ImplicitDeny
			res.Reason = "allowed by an identity policy but not by the permissions boundary"
			res.UnknownKeys = unk.sorted()
			return res
		}
	}
	res.UnknownKeys = unk.sorted()
	switch {
	case deny == Yes:
		res.Decision = ExplicitDeny
		res.Reason = "an explicit Deny statement applies"
	case allow == No:
		res.Decision = ImplicitDeny
		res.Reason = "no statement allows the request (implicit deny)"
	default:
		res.Decision = Allow
		res.Uncertain = allow == Maybe || deny == Maybe
		res.Reason = "an Allow statement applies and no Deny applies"
		if res.Uncertain {
			res.Reason = "allowed if unknown context values satisfy the matching conditions"
		}
	}
	return res
}

// Allows is a convenience wrapper returning whether the request is allowed.
func (s *Set) Allows(req Request) bool { return s.Evaluate(req).Allowed() }

// Validate checks a document with the IAM grammar plus the engine's operator list.
func Validate(doc *policy.Document) []policy.Issue {
	return policy.Validate(doc, KnownOperator)
}

// SortRefs orders statement references deterministically.
func SortRefs(refs []StatementRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Policy != refs[j].Policy {
			return refs[i].Policy < refs[j].Policy
		}
		return refs[i].Index < refs[j].Index
	})
}
