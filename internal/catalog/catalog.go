// Package catalog holds the bundled subset of IAM actions, their access
// levels and resource types, and the CloudTrail event names they produce.
//
// The data is a hand-curated subset of the AWS Service Authorization
// Reference (see DATA.md); it is embedded at build time so the tool works
// offline. Lookups are O(1) map accesses after an O(actions) index build.
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/lutherleo/leastpriv/internal/glob"
)

//go:embed data/catalog.json
var embedded []byte

// Access levels, as named by the Service Authorization Reference.
const (
	AccessList        = "List"
	AccessRead        = "Read"
	AccessWrite       = "Write"
	AccessPermissions = "Permissions management"
	AccessTagging     = "Tagging"
)

// ResourceType describes one resource type of a service and how to build its
// ARN from CloudTrail request parameters.
type ResourceType struct {
	Name           string              `json:"name"`
	ARN            string              `json:"arn"`
	CloudTrailType string              `json:"cloudTrailType,omitempty"`
	ARNParams      []string            `json:"arnParams,omitempty"`
	Params         map[string][]string `json:"params"`

	service  string
	matcher  *regexp.Regexp
	varStart int // capture group index of the last placeholder
}

// Action is one IAM action.
type Action struct {
	Name      string   `json:"name"`
	Access    string   `json:"access"`
	Resources []string `json:"resources"`
	// Events lists CloudTrail event names that exercise this action. A nil
	// slice means the event name equals the action name.
	Events       []string `json:"events,omitempty"`
	ResourceMode string   `json:"resourceMode,omitempty"` // "first" (default) or "all"
	DataEvent    bool     `json:"dataEvent,omitempty"`
	NotLogged    bool     `json:"notLogged,omitempty"`
	NoAuth       bool     `json:"noAuth,omitempty"`

	service string
}

// ExtraEvent maps an event to an additional action with its own parameter
// paths (for example CopyObject also needs s3:GetObject on the source).
type ExtraEvent struct {
	Event  string              `json:"event"`
	Action string              `json:"action"`
	Params map[string][]string `json:"params"`
}

// Service is one AWS service in the catalog.
type Service struct {
	Prefix           string         `json:"prefix"`
	Name             string         `json:"name"`
	EventSource      string         `json:"eventSource"`
	StripEventSuffix bool           `json:"stripEventSuffix,omitempty"`
	ResourceTypes    []ResourceType `json:"resourceTypes"`
	Actions          []Action       `json:"actions"`
	ExtraEvents      []ExtraEvent   `json:"extraEvents,omitempty"`
}

// EventMapping is one action exercised by a CloudTrail event.
type EventMapping struct {
	Action *Action
	// Params overrides resource-type parameter paths (nil: use the type's own).
	Params map[string][]string
}

// Catalog is the indexed action catalog.
type Catalog struct {
	Services []*Service

	bySource  map[string]*Service
	byPrefix  map[string]*Service
	byAction  map[string]*Action // lower-case "svc:action"
	byEvent   map[string][]EventMapping
	resByName map[string]*ResourceType // "svc/type"
}

// Default returns the embedded catalog. It panics only if the embedded data
// is corrupt, which the test suite guards against.
func Default() *Catalog {
	c, err := Parse(embedded)
	if err != nil {
		panic(fmt.Sprintf("embedded catalog: %v", err))
	}
	return c
}

// Parse loads and indexes a catalog from JSON.
func Parse(data []byte) (*Catalog, error) {
	var raw struct {
		SchemaVersion int        `json:"schemaVersion"`
		Services      []*Service `json:"services"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	if raw.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported catalog schemaVersion %d", raw.SchemaVersion)
	}
	c := &Catalog{
		Services:  raw.Services,
		bySource:  map[string]*Service{},
		byPrefix:  map[string]*Service{},
		byAction:  map[string]*Action{},
		byEvent:   map[string][]EventMapping{},
		resByName: map[string]*ResourceType{},
	}
	for _, s := range c.Services {
		if s.Prefix == "" || s.EventSource == "" {
			return nil, fmt.Errorf("service %q: prefix and eventSource are required", s.Name)
		}
		c.bySource[s.EventSource] = s
		c.byPrefix[s.Prefix] = s
		for i := range s.ResourceTypes {
			rt := &s.ResourceTypes[i]
			rt.service = s.Prefix
			if err := rt.compile(); err != nil {
				return nil, fmt.Errorf("service %s resource %s: %w", s.Prefix, rt.Name, err)
			}
			c.resByName[s.Prefix+"/"+rt.Name] = rt
		}
		for i := range s.Actions {
			act := &s.Actions[i]
			act.service = s.Prefix
			key := strings.ToLower(s.Prefix + ":" + act.Name)
			if _, dup := c.byAction[key]; dup {
				return nil, fmt.Errorf("duplicate action %s", key)
			}
			c.byAction[key] = act
			for _, r := range act.Resources {
				if _, ok := c.resByName[s.Prefix+"/"+r]; !ok {
					return nil, fmt.Errorf("action %s references unknown resource type %q", key, r)
				}
			}
			events := act.Events
			if events == nil {
				events = []string{act.Name}
			}
			for _, e := range events {
				ek := s.EventSource + "/" + e
				c.byEvent[ek] = append(c.byEvent[ek], EventMapping{Action: act})
			}
		}
		for _, x := range s.ExtraEvents {
			act, ok := c.byAction[strings.ToLower(s.Prefix+":"+x.Action)]
			if !ok {
				return nil, fmt.Errorf("extra event %s references unknown action %s", x.Event, x.Action)
			}
			ek := s.EventSource + "/" + x.Event
			c.byEvent[ek] = append(c.byEvent[ek], EventMapping{Action: act, Params: x.Params})
		}
	}
	return c, nil
}

var placeholderRe = regexp.MustCompile(`\$\{([A-Za-z]+)\}`)

// compile builds a regexp that recognises concrete ARNs of this type and
// records which capture group holds the last (most specific) placeholder.
func (rt *ResourceType) compile() error {
	locs := placeholderRe.FindAllStringSubmatchIndex(rt.ARN, -1)
	if len(locs) == 0 {
		return fmt.Errorf("ARN template %q has no placeholders", rt.ARN)
	}
	var b strings.Builder
	b.WriteString("^")
	prev := 0
	for i, loc := range locs {
		b.WriteString(regexp.QuoteMeta(rt.ARN[prev:loc[0]]))
		name := rt.ARN[loc[2]:loc[3]]
		switch {
		case name == "Partition" || name == "Region" || name == "Account":
			b.WriteString("([^:]*)")
		case i == len(locs)-1:
			b.WriteString("(.+)")
		default:
			b.WriteString("([^/:]+)")
		}
		prev = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(rt.ARN[prev:]))
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return err
	}
	rt.matcher = re
	rt.varStart = len(locs)
	return nil
}

// Service returns the service prefix that owns the resource type.
func (rt *ResourceType) Service() string { return rt.service }

// NamedPlaceholders returns how many placeholders other than partition,
// region and account the ARN template has. A type with two or more (an S3
// object inside a bucket, an index inside a table) has a container whose
// whole contents may be wildcarded; a type with one has a flat namespace.
func (rt *ResourceType) NamedPlaceholders() int {
	n := 0
	for _, m := range placeholderRe.FindAllStringSubmatch(rt.ARN, -1) {
		switch m[1] {
		case "Partition", "Region", "Account":
		default:
			n++
		}
	}
	return n
}

// VariableSpan returns the byte offset in a concrete ARN of this type where
// its last placeholder begins (the part the generator may wildcard), or -1
// if the ARN is not of this type.
func (rt *ResourceType) VariableSpan(resource string) int {
	m := rt.matcher.FindStringSubmatchIndex(resource)
	if m == nil {
		return -1
	}
	return m[2*rt.varStart]
}

// Template returns the ARN template with partition, region and account
// filled in and every other placeholder replaced by '*'.
func (rt *ResourceType) Template(partition, region, account string) string {
	return placeholderRe.ReplaceAllStringFunc(rt.ARN, func(m string) string {
		switch m {
		case "${Partition}":
			return partition
		case "${Region}":
			return region
		case "${Account}":
			return account
		}
		return "*"
	})
}

// Service returns the service prefix of the action.
func (a *Action) Service() string { return a.service }

// FullName returns "prefix:Name".
func (a *Action) FullName() string { return a.service + ":" + a.Name }

// HasResources reports whether the action supports resource-level permissions.
func (a *Action) HasResources() bool { return len(a.Resources) > 0 }

// Lookup finds an action by "svc:Name" (case-insensitive).
func (c *Catalog) Lookup(action string) (*Action, bool) {
	a, ok := c.byAction[strings.ToLower(action)]
	return a, ok
}

// ServiceByPrefix returns a service by its IAM prefix.
func (c *Catalog) ServiceByPrefix(prefix string) (*Service, bool) {
	s, ok := c.byPrefix[strings.ToLower(prefix)]
	return s, ok
}

// ServiceBySource returns a service by its CloudTrail eventSource.
func (c *Catalog) ServiceBySource(source string) (*Service, bool) {
	s, ok := c.bySource[source]
	return s, ok
}

// ResourceType returns a service's resource type by name.
func (c *Catalog) ResourceType(service, name string) (*ResourceType, bool) {
	rt, ok := c.resByName[service+"/"+name]
	return rt, ok
}

var eventSuffixRe = regexp.MustCompile(`^(.+?)(\d{8})(v\d+)?$`)

// NormalizeEventName strips version suffixes such as Lambda's
// "GetFunction20150331v2" when the service declares them.
func (s *Service) NormalizeEventName(name string) string {
	if !s.StripEventSuffix {
		return name
	}
	if m := eventSuffixRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return name
}

// EventMappings returns the actions an event exercises.
func (c *Catalog) EventMappings(source, eventName string) []EventMapping {
	s, ok := c.bySource[source]
	if !ok {
		return nil
	}
	return c.byEvent[source+"/"+s.NormalizeEventName(eventName)]
}

// Actions returns every action in the catalog, sorted by full name.
func (c *Catalog) Actions() []*Action {
	out := make([]*Action, 0, len(c.byAction))
	for _, a := range c.byAction {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

// Expand returns the catalog actions matched by an IAM action pattern such
// as "s3:Get*" (case-insensitive), sorted.
func (c *Catalog) Expand(pattern string) []*Action {
	var out []*Action
	for _, a := range c.Actions() {
		if glob.MatchFold(pattern, a.FullName()) {
			out = append(out, a)
		}
	}
	return out
}

// TypeOf returns the resource type of a concrete ARN within a service, or
// nil. When several templates match (an S3 bucket template also matches
// object ARNs), the one with the most placeholders wins, then the longest.
func (c *Catalog) TypeOf(service, resource string) *ResourceType {
	s, ok := c.byPrefix[service]
	if !ok {
		return nil
	}
	var best *ResourceType
	for i := range s.ResourceTypes {
		rt := &s.ResourceTypes[i]
		if !rt.matcher.MatchString(resource) {
			continue
		}
		if best == nil || rt.varStart > best.varStart ||
			(rt.varStart == best.varStart && len(rt.ARN) > len(best.ARN)) {
			best = rt
		}
	}
	return best
}

// Verb returns the leading CamelCase word of an action name ("Get" for
// "GetObject"), used for action wildcard collapsing.
func Verb(actionName string) string {
	for i := 1; i < len(actionName); i++ {
		if actionName[i] >= 'A' && actionName[i] <= 'Z' {
			return actionName[:i]
		}
	}
	return actionName
}
