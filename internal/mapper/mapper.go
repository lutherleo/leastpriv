// Package mapper turns CloudTrail records into the IAM (action, resource)
// pairs that the request needed to be authorized for, using the catalog's
// event-name mappings and ARN templates.
//
// Resource resolution order for each mapped action and resource type:
//  1. the record's resources[] entries of the matching CloudTrail type;
//  2. request parameters that already hold a full ARN of that type;
//  3. the type's ARN template filled from request parameters.
//
// When parameters are missing, unresolved placeholders become '*' and the
// call is marked ConfidencePartial; the generator then still scopes the
// grant to the resource type rather than widening it to "*".
//
// Mapping one record costs O(P * V) for P parameter paths and V fanned-out
// values (usually both tiny).
package mapper

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/arn"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/cloudtrail"
)

// Confidence describes how precisely a call's resource was determined.
type Confidence string

// Confidence levels.
const (
	// ConfidenceExact: the resource ARN was fully determined.
	ConfidenceExact Confidence = "exact"
	// ConfidencePartial: some ARN parts were unknown and became '*'.
	ConfidencePartial Confidence = "partial"
	// ConfidenceUncatalogued: the event's service is known but the event
	// name is not in the catalog; the action is assumed to equal the event
	// name and the resource is "*".
	ConfidenceUncatalogued Confidence = "uncatalogued"
)

// Call is one IAM authorization a CloudTrail record implies.
type Call struct {
	Action     string     `json:"action"`
	Resource   string     `json:"resource"`
	Confidence Confidence `json:"confidence"`
	// NoAuth marks actions that need no IAM permission (sts:GetCallerIdentity).
	NoAuth bool `json:"noAuth,omitempty"`
}

// Mapper maps records using a catalog.
type Mapper struct {
	cat *catalog.Catalog
}

// New returns a mapper over the catalog.
func New(cat *catalog.Catalog) *Mapper { return &Mapper{cat: cat} }

// ErrUnknownService is wrapped by Map when the event source is not in the catalog.
var ErrUnknownService = fmt.Errorf("service not in catalog")

// Map returns the calls implied by a record.
func (m *Mapper) Map(rec *cloudtrail.Record) ([]Call, error) {
	svc, ok := m.cat.ServiceBySource(rec.EventSource)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownService, rec.EventSource)
	}
	mappings := m.cat.EventMappings(rec.EventSource, rec.EventName)
	if len(mappings) == 0 {
		name := svc.NormalizeEventName(rec.EventName)
		return []Call{{Action: svc.Prefix + ":" + name, Resource: "*", Confidence: ConfidenceUncatalogued}}, nil
	}
	env := templateEnv{
		partition: arn.PartitionForRegion(rec.AWSRegion),
		region:    rec.AWSRegion,
		account:   rec.Account(),
	}
	var out []Call
	for _, em := range mappings {
		act := em.Action
		if !act.HasResources() {
			out = append(out, Call{Action: act.FullName(), Resource: "*", Confidence: ConfidenceExact, NoAuth: act.NoAuth})
			continue
		}
		resources, conf := m.resolve(act, em.Params, rec, env)
		for _, r := range resources {
			out = append(out, Call{Action: act.FullName(), Resource: r, Confidence: conf, NoAuth: act.NoAuth})
		}
	}
	return out, nil
}

type templateEnv struct{ partition, region, account string }

func (m *Mapper) resolve(act *catalog.Action, override map[string][]string, rec *cloudtrail.Record, env templateEnv) ([]string, Confidence) {
	type partial struct {
		arns     []string
		resolved int
	}
	var all []string
	var best *partial
	for _, typeName := range act.Resources {
		rt, ok := m.cat.ResourceType(act.Service(), typeName)
		if !ok {
			continue
		}
		arns, resolved, complete := m.resolveType(rt, override, rec, env)
		if complete {
			if act.ResourceMode != "all" {
				return arns, ConfidenceExact
			}
			all = append(all, arns...)
			continue
		}
		if best == nil || resolved > best.resolved {
			best = &partial{arns: arns, resolved: resolved}
		}
	}
	if len(all) > 0 {
		return dedupe(all), ConfidenceExact
	}
	if best == nil {
		return []string{"*"}, ConfidencePartial
	}
	return best.arns, ConfidencePartial
}

var placeholderRe = regexp.MustCompile(`\$\{([A-Za-z]+)\}`)

// resolveType returns the ARNs of one resource type for the record, how many
// non-environment placeholders were resolved, and whether all were.
func (m *Mapper) resolveType(rt *catalog.ResourceType, override map[string][]string, rec *cloudtrail.Record, env templateEnv) ([]string, int, bool) {
	if override == nil {
		var fromResources []string
		if rt.CloudTrailType != "" {
			for _, r := range rec.Resources {
				if r.Type == rt.CloudTrailType && r.ARN != "" {
					fromResources = append(fromResources, r.ARN)
				}
			}
		}
		if len(fromResources) > 0 {
			return dedupe(fromResources), 1, true
		}
		for _, p := range rt.ARNParams {
			var found []string
			for _, v := range lookupPath(rec.RequestParameters, p) {
				if strings.HasPrefix(v, "arn:") && rt.VariableSpan(v) >= 0 {
					found = append(found, v)
				}
			}
			if len(found) > 0 {
				return dedupe(found), 1, true
			}
		}
	}
	params := rt.Params
	if override != nil {
		params = override
	}
	values := map[string][]string{}
	resolved, complete := 0, true
	for _, m := range placeholderRe.FindAllStringSubmatch(rt.ARN, -1) {
		name := m[1]
		switch name {
		case "Partition", "Region", "Account":
			continue
		}
		for _, spec := range params[name] {
			if vs := evalSpec(rec.RequestParameters, spec); len(vs) > 0 {
				values[name] = vs
				break
			}
		}
		if len(values[name]) == 0 {
			complete = false
			values[name] = []string{"*"}
		} else {
			resolved++
		}
	}
	return expandTemplate(rt.ARN, env, values), resolved, complete
}

// expandTemplate fills the template, taking the cartesian product of
// multi-valued placeholders.
func expandTemplate(tmpl string, env templateEnv, values map[string][]string) []string {
	results := []string{""}
	pos := 0
	for _, loc := range placeholderRe.FindAllStringSubmatchIndex(tmpl, -1) {
		lit := tmpl[pos:loc[0]]
		name := tmpl[loc[2]:loc[3]]
		var opts []string
		switch name {
		case "Partition":
			opts = []string{env.partition}
		case "Region":
			opts = []string{env.region}
		case "Account":
			opts = []string{env.account}
		default:
			opts = values[name]
		}
		next := make([]string, 0, len(results)*len(opts))
		for _, r := range results {
			for _, o := range opts {
				next = append(next, r+lit+o)
			}
		}
		results = next
		pos = loc[1]
	}
	for i := range results {
		results[i] += tmpl[pos:]
	}
	return dedupe(results)
}

// evalSpec evaluates "path|transform[:arg]" against request parameters.
func evalSpec(params map[string]any, spec string) []string {
	path, transform, _ := strings.Cut(spec, "|")
	raw := lookupPath(params, path)
	if transform == "" {
		return raw
	}
	var out []string
	for _, v := range raw {
		if t := applyTransform(transform, v); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// lookupPath walks a dotted path; "x[]" fans out over an array and "{}"
// fans out over an object's keys. Scalars are rendered as strings.
func lookupPath(params map[string]any, path string) []string {
	if params == nil || path == "" {
		return nil
	}
	cur := []any{params}
	for _, seg := range strings.Split(path, ".") {
		var next []any
		for _, node := range cur {
			obj, ok := node.(map[string]any)
			if !ok {
				continue
			}
			switch {
			case seg == "{}":
				keys := make([]string, 0, len(obj))
				for k := range obj {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					next = append(next, k)
				}
			case strings.HasSuffix(seg, "[]"):
				if arr, ok := obj[strings.TrimSuffix(seg, "[]")].([]any); ok {
					next = append(next, arr...)
				}
			default:
				if v, ok := obj[seg]; ok {
					next = append(next, v)
				}
			}
		}
		cur = next
	}
	var out []string
	for _, v := range cur {
		switch t := v.(type) {
		case string:
			if t != "" {
				out = append(out, t)
			}
		case float64, bool:
			out = append(out, fmt.Sprint(t))
		}
	}
	return out
}

func applyTransform(name, v string) string {
	fn, arg, _ := strings.Cut(name, ":")
	switch fn {
	case "lastPathSegment":
		v = strings.TrimRight(v, "/")
		if i := strings.LastIndexByte(v, '/'); i >= 0 {
			return v[i+1:]
		}
		return v
	case "copySourceBucket", "copySourceKey":
		src := v
		if dec, err := url.PathUnescape(src); err == nil {
			src = dec
		}
		src, _, _ = strings.Cut(src, "?versionId=")
		src = strings.TrimPrefix(src, "/")
		bucket, key, ok := strings.Cut(src, "/")
		if !ok {
			return ""
		}
		if fn == "copySourceBucket" {
			return bucket
		}
		return key
	case "lambdaName":
		if strings.HasPrefix(v, "arn:") {
			parts := strings.Split(v, ":")
			if len(parts) >= 7 {
				return parts[6]
			}
			return ""
		}
		if _, after, ok := strings.Cut(v, ":function:"); ok {
			v = after
		}
		name, _, _ := strings.Cut(v, ":")
		return name
	case "stripLeadingSlash":
		return strings.TrimPrefix(v, "/")
	case "secretPattern":
		if strings.HasPrefix(v, "arn:") {
			return ""
		}
		// Secret ARNs end in a random 6-character suffix; AWS recommends
		// matching names with "-??????".
		return v + "-??????"
	case "kmsKeyId":
		if strings.HasPrefix(v, "alias/") || strings.HasPrefix(v, "arn:") {
			return ""
		}
		return strings.TrimPrefix(v, "key/")
	case "kmsAlias":
		if after, ok := strings.CutPrefix(v, "alias/"); ok {
			return after
		}
		return ""
	case "requirePrefix":
		if strings.HasPrefix(v, arg) {
			return v
		}
		return ""
	}
	return ""
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
