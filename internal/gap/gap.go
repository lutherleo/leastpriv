// Package gap produces the permission-gap report for a principal: which
// actions its policies grant, which it actually used during the observation
// window (with last-used age), and which grants are unused, stale or
// unobservable.
//
// "Granted" is computed per catalog action as: some identity Allow statement
// matches the action, the action is not denied by an unconditional Deny on
// all resources, and (when set) the permissions boundary also allows it.
// Conditions are assumed satisfiable, so this is an upper bound on what the
// principal can do. Cost: O(A * S) for A catalog actions and S statements,
// plus O(E) over observations.
package gap

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/glob"
	"github.com/lutherleo/leastpriv/internal/policy"
)

// Status classifies one action for a principal.
type Status string

// Statuses.
const (
	StatusUsed         Status = "used"
	StatusStale        Status = "stale"
	StatusUnused       Status = "unused"
	StatusUnobservable Status = "unobservable"
	StatusNoAuth       Status = "no-auth"
	StatusUngranted    Status = "used-but-not-granted"
)

// Options configures the analysis.
type Options struct {
	// Now is the reference time for ages; zero means the end of the window.
	Now time.Time
	// StaleDays marks used actions whose last use is older than this (default 30).
	StaleDays int
	// WindowStart/WindowEnd describe the observation window (for reporting).
	WindowStart, WindowEnd time.Time
}

// ActionUsage is one row of the report.
type ActionUsage struct {
	Action         string     `json:"action"`
	Service        string     `json:"service"`
	Access         string     `json:"access"`
	Granted        bool       `json:"granted"`
	Scope          string     `json:"scope,omitempty"` // "*", "scoped", "not-resource"
	Conditional    bool       `json:"conditional,omitempty"`
	Count          int        `json:"count"`
	Resources      int        `json:"distinctResources"`
	FirstUsed      *time.Time `json:"firstUsed,omitempty"`
	LastUsed       *time.Time `json:"lastUsed,omitempty"`
	AgeDays        *int       `json:"lastUsedAgeDays,omitempty"`
	DeniedAttempts int        `json:"deniedAttempts,omitempty"`
	Status         Status     `json:"status"`
	Risk           string     `json:"risk,omitempty"`
	Notes          []string   `json:"notes,omitempty"`
}

// ServiceUsage rolls actions up per service, like IAM access advisor.
type ServiceUsage struct {
	Service        string     `json:"service"`
	GrantedActions int        `json:"grantedActions"`
	UsedActions    int        `json:"usedActions"`
	UnusedActions  int        `json:"unusedActions"`
	LastUsed       *time.Time `json:"lastUsed,omitempty"`
}

// Report is the permission-gap report for one principal.
type Report struct {
	Principal          string         `json:"principal"`
	WindowStart        time.Time      `json:"windowStart"`
	WindowEnd          time.Time      `json:"windowEnd"`
	Now                time.Time      `json:"now"`
	StaleDays          int            `json:"staleDays"`
	Granted            int            `json:"granted"`
	Used               int            `json:"used"`
	Stale              int            `json:"stale"`
	Unused             int            `json:"unused"`
	Unobservable       int            `json:"unobservable"`
	UnusedPercent      float64        `json:"unusedPercent"`
	HighRiskUnused     []string       `json:"highRiskUnused,omitempty"`
	UncataloguedGrants []string       `json:"uncataloguedGrants,omitempty"`
	DeniedOnly         []string       `json:"deniedAttemptsOnUngranted,omitempty"`
	Services           []ServiceUsage `json:"services"`
	Actions            []ActionUsage  `json:"actions"`
	Warnings           []string       `json:"warnings,omitempty"`
}

type usage struct {
	count     int
	denied    int
	first     time.Time
	last      time.Time
	resources map[string]bool
	granted   bool // at least one successful use allowed by the policies
}

// Analyze builds the gap report.
func Analyze(cat *catalog.Catalog, p *authz.Principal, obs []activity.Observation, opts Options) (*Report, error) {
	if opts.StaleDays <= 0 {
		opts.StaleDays = 30
	}
	set, err := p.PolicySet()
	if err != nil {
		return nil, err
	}
	rep := &Report{Principal: p.ARN, StaleDays: opts.StaleDays, WindowStart: opts.WindowStart, WindowEnd: opts.WindowEnd}
	rep.Warnings = append(rep.Warnings, p.Warnings...)
	now := opts.Now
	if now.IsZero() {
		now = opts.WindowEnd
	}
	uses := map[string]*usage{}
	var latest time.Time
	for _, o := range obs {
		key := strings.ToLower(o.Action)
		u := uses[key]
		if u == nil {
			u = &usage{resources: map[string]bool{}}
			uses[key] = u
		}
		if o.Denied {
			u.denied++
			continue
		}
		u.count++
		u.resources[o.Resource] = true
		if u.first.IsZero() || o.Time.Before(u.first) {
			u.first = o.Time
		}
		if o.Time.After(u.last) {
			u.last = o.Time
		}
		if !u.granted && set.Allows(o.Request()) {
			u.granted = true
		}
		if o.Time.After(latest) {
			latest = o.Time
		}
	}
	if now.IsZero() {
		now = latest
	}
	rep.Now = now

	docs := identityDocs(p)
	var boundary *policy.Document
	if p.Boundary != nil {
		boundary = p.Boundary.Doc
	}
	seen := map[string]bool{}
	for _, a := range cat.Actions() {
		name := a.FullName()
		key := strings.ToLower(name)
		seen[key] = true
		g := grantFor(docs, boundary, name)
		u := uses[key]
		if !g.granted && (u == nil || u.count == 0) {
			if u != nil && u.denied > 0 {
				rep.DeniedOnly = append(rep.DeniedOnly, fmt.Sprintf("%s (%d attempts)", name, u.denied))
			}
			continue
		}
		row := ActionUsage{Action: name, Service: a.Service(), Access: a.Access, Granted: g.granted, Scope: g.scope, Conditional: g.conditional}
		fill(&row, u, now)
		switch {
		case a.NoAuth:
			row.Status = StatusNoAuth
		case row.Count > 0 && !g.granted:
			row.Status = StatusUngranted
		case row.Count > 0 && row.AgeDays != nil && *row.AgeDays > opts.StaleDays:
			row.Status = StatusStale
		case row.Count > 0:
			row.Status = StatusUsed
		case a.NotLogged:
			row.Status = StatusUnobservable
			row.Notes = append(row.Notes, "CloudTrail does not record this action; usage cannot be observed")
		default:
			row.Status = StatusUnused
		}
		if a.DataEvent && row.Count == 0 && !a.NotLogged {
			row.Notes = append(row.Notes, "recorded only as a CloudTrail data event; confirm data events were enabled")
		}
		if row.Status == StatusUnused || row.Status == StatusStale {
			row.Risk = risk(a.Access, g.scope)
		}
		rep.Actions = append(rep.Actions, row)
	}
	// Used actions outside the catalog.
	for key, u := range uses {
		if seen[key] || u.count == 0 {
			continue
		}
		name := originalCase(obs, key)
		row := ActionUsage{Action: name, Service: policy.ServiceOf(name), Access: "unknown", Granted: u.granted}
		fill(&row, u, now)
		row.Status = StatusUsed
		if !u.granted {
			row.Status = StatusUngranted
		}
		row.Notes = append(row.Notes, "action not in the bundled catalog")
		rep.Actions = append(rep.Actions, row)
	}
	sort.Slice(rep.Actions, func(i, j int) bool { return rep.Actions[i].Action < rep.Actions[j].Action })
	rep.UncataloguedGrants = uncataloguedGrants(cat, docs)
	summarize(rep)
	return rep, nil
}

func identityDocs(p *authz.Principal) []*policy.Document {
	out := make([]*policy.Document, 0, len(p.Policies))
	for _, nd := range p.Policies {
		out = append(out, nd.Doc)
	}
	return out
}

func fill(row *ActionUsage, u *usage, now time.Time) {
	if u == nil {
		return
	}
	row.DeniedAttempts = u.denied
	if u.count == 0 {
		return
	}
	row.Count = u.count
	row.Resources = len(u.resources)
	first, last := u.first, u.last
	row.FirstUsed, row.LastUsed = &first, &last
	age := int(math.Floor(now.Sub(last).Hours() / 24))
	if age < 0 {
		age = 0
	}
	row.AgeDays = &age
}

func originalCase(obs []activity.Observation, key string) string {
	for _, o := range obs {
		if strings.ToLower(o.Action) == key {
			return o.Action
		}
	}
	return key
}

type grant struct {
	granted     bool
	scope       string
	conditional bool
}

func actionMatches(st *policy.Statement, action string) bool {
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

func coversAllResources(st *policy.Statement) bool {
	if st.Has("NotResource") {
		return false
	}
	for _, r := range st.Resource {
		if r == "*" {
			return true
		}
	}
	return false
}

// grantFor decides whether action is granted on at least one resource.
func grantFor(docs []*policy.Document, boundary *policy.Document, action string) grant {
	var g grant
	allConditional := true
	for _, d := range docs {
		for i := range d.Statement {
			st := &d.Statement[i]
			if st.Effect != policy.Deny || !actionMatches(st, action) {
				continue
			}
			if len(st.Condition) == 0 && coversAllResources(st) {
				return grant{}
			}
		}
	}
	for _, d := range docs {
		for i := range d.Statement {
			st := &d.Statement[i]
			if st.Effect != policy.Allow || !actionMatches(st, action) {
				continue
			}
			g.granted = true
			if len(st.Condition) == 0 {
				allConditional = false
			}
			switch {
			case st.Has("NotResource"):
				if g.scope != "*" {
					g.scope = "not-resource"
				}
			case coversAllResources(st):
				g.scope = "*"
			default:
				if g.scope == "" {
					g.scope = "scoped"
				}
			}
		}
	}
	if !g.granted {
		return grant{}
	}
	g.conditional = allConditional
	if boundary != nil {
		b := grantFor([]*policy.Document{boundary}, nil, action)
		if !b.granted {
			return grant{}
		}
	}
	return g
}

// risk rates an unused grant: permission-management and unscoped writes are
// high risk; scoped writes and tagging medium; reads and lists low.
func risk(access, scope string) string {
	switch access {
	case catalog.AccessPermissions:
		return "high"
	case catalog.AccessWrite:
		if scope == "*" || scope == "not-resource" {
			return "high"
		}
		return "medium"
	case catalog.AccessTagging:
		return "medium"
	default:
		return "low"
	}
}

// uncataloguedGrants lists Allow action patterns that match no catalog
// action (whole services the catalog does not model, such as "rds:*").
func uncataloguedGrants(cat *catalog.Catalog, docs []*policy.Document) []string {
	set := map[string]bool{}
	for _, d := range docs {
		for _, st := range d.Statement {
			if st.Effect != policy.Allow {
				continue
			}
			for _, a := range st.Action {
				if a == "*" {
					set["* (every action of every service, including services outside the catalog)"] = true
					continue
				}
				if len(cat.Expand(a)) == 0 {
					set[a] = true
				}
			}
			if st.Has("NotAction") {
				set["NotAction "+strings.Join(st.NotAction, ",")+" (every other action, including services outside the catalog)"] = true
			}
		}
	}
	return policy.SortedKeys(set)
}

func summarize(rep *Report) {
	svc := map[string]*ServiceUsage{}
	for _, r := range rep.Actions {
		if r.Status == StatusNoAuth {
			continue
		}
		s := svc[r.Service]
		if s == nil {
			s = &ServiceUsage{Service: r.Service}
			svc[r.Service] = s
		}
		if r.Granted {
			rep.Granted++
			s.GrantedActions++
		}
		switch r.Status {
		case StatusUsed:
			rep.Used++
		case StatusStale:
			rep.Stale++
		case StatusUnused:
			rep.Unused++
			s.UnusedActions++
			if r.Risk == "high" {
				rep.HighRiskUnused = append(rep.HighRiskUnused, r.Action)
			}
		case StatusUnobservable:
			rep.Unobservable++
		}
		if r.Count > 0 {
			s.UsedActions++
			if r.LastUsed != nil && (s.LastUsed == nil || r.LastUsed.After(*s.LastUsed)) {
				t := *r.LastUsed
				s.LastUsed = &t
			}
		}
	}
	if rep.Granted > 0 {
		rep.UnusedPercent = math.Round(1000*float64(rep.Unused)/float64(rep.Granted)) / 10
	}
	for _, k := range policy.SortedKeys(svc) {
		rep.Services = append(rep.Services, *svc[k])
	}
}

// Granted returns the catalog actions the principal's policies grant (the
// same notion of "granted" the report uses), sorted.
func Granted(cat *catalog.Catalog, p *authz.Principal) []string {
	var boundary *policy.Document
	if p.Boundary != nil {
		boundary = p.Boundary.Doc
	}
	return GrantedByDocs(cat, identityDocs(p), boundary)
}

// GrantedByDocs is Granted for an arbitrary policy set (e.g. a generated
// policy evaluated under the principal's boundary).
func GrantedByDocs(cat *catalog.Catalog, docs []*policy.Document, boundary *policy.Document) []string {
	var out []string
	for _, a := range cat.Actions() {
		if a.NoAuth {
			continue
		}
		if grantFor(docs, boundary, a.FullName()).granted {
			out = append(out, a.FullName())
		}
	}
	return out
}
