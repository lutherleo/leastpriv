package engine

import (
	"sort"
	"strings"
)

// Request is the authorization request context the engine evaluates: an
// action, a resource ARN (or "*" for actions without resource-level
// permissions) and condition context keys.
type Request struct {
	Action   string
	Resource string
	// Context maps lower-cased condition keys to their values. A key with
	// several values is multivalued (for example aws:TagKeys).
	Context map[string][]string
	// Unknown reports whether a key that is absent from Context has an
	// unknown value (it may or may not exist in the real request) rather than
	// being authoritatively absent. A nil Unknown means every absent key is
	// authoritatively absent, which is how IAM itself evaluates.
	Unknown func(key string) bool
}

// NewRequest returns a request with an empty, authoritative context.
func NewRequest(action, resource string) Request {
	return Request{Action: action, Resource: resource, Context: map[string][]string{}}
}

// Set assigns values to a context key (case-insensitive).
func (r *Request) Set(key string, values ...string) {
	if r.Context == nil {
		r.Context = map[string][]string{}
	}
	r.Context[strings.ToLower(key)] = values
}

// AllUnknown is an Unknown function that treats every absent key as unknown.
// It is used to ask "is this action/resource granted under some context?".
func AllUnknown(string) bool { return true }

type keyState uint8

const (
	keyPresent keyState = iota
	keyAbsent
	keyUnknown
)

func (r *Request) lookup(key string) ([]string, keyState) {
	vals, ok := r.Context[strings.ToLower(key)]
	if ok && len(vals) > 0 {
		return vals, keyPresent
	}
	if r.Unknown != nil && r.Unknown(strings.ToLower(key)) {
		return nil, keyUnknown
	}
	return nil, keyAbsent
}

// unknownSet collects the context keys whose unknown values influenced a result.
type unknownSet map[string]bool

func (u unknownSet) add(key string) {
	if u != nil {
		u[strings.ToLower(key)] = true
	}
}

func (u unknownSet) sorted() []string {
	if len(u) == 0 {
		return nil
	}
	out := make([]string, 0, len(u))
	for k := range u {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
