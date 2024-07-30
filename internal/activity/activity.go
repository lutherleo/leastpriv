// Package activity joins CloudTrail records, the action catalog and the
// principal inventory into per-principal observations: "principal P was
// authorized for action A on resource R at time T under context C".
package activity

import (
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/cloudtrail"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/mapper"
)

// Observation is one authorization implied by a CloudTrail record.
type Observation struct {
	Principal  string              `json:"principal"`
	Action     string              `json:"action"`
	Resource   string              `json:"resource"`
	Confidence mapper.Confidence   `json:"confidence"`
	NoAuth     bool                `json:"noAuth,omitempty"`
	Time       time.Time           `json:"time"`
	EventID    string              `json:"eventId"`
	EventName  string              `json:"eventName"`
	Context    map[string][]string `json:"context,omitempty"`
	// Denied marks an access-denied attempt (the call was not authorized).
	Denied bool `json:"denied,omitempty"`
	// ErrorCode is set for failed calls; non-authorization errors still
	// prove the authorization check passed.
	ErrorCode string `json:"errorCode,omitempty"`

	tlsKnown bool
}

// Request builds the engine request for the observation. Context keys that
// CloudTrail cannot carry are marked unknown.
func (o Observation) Request() engine.Request {
	return engine.Request{
		Action:   o.Action,
		Resource: o.Resource,
		Context:  o.Context,
		Unknown:  UnknownFunc(o.tlsKnown),
	}
}

// UnknownFunc returns the engine.Request.Unknown predicate for contexts
// derived from CloudTrail: keys CloudTrail cannot carry are unknown, and
// aws:SecureTransport is unknown unless the record could express it.
func UnknownFunc(tlsKnown bool) func(string) bool {
	return func(key string) bool {
		if key == "aws:securetransport" {
			return !tlsKnown
		}
		return !cloudtrail.DerivableKeys[key]
	}
}

// WithTLSKnown marks whether the observation's record could express
// aws:SecureTransport (used when building observations outside Load).
func (o *Observation) WithTLSKnown(known bool) { o.tlsKnown = known }

// Stats summarises what was read.
type Stats struct {
	Records             int            `json:"records"`
	Observations        int            `json:"observations"`
	DeniedAttempts      int            `json:"deniedAttempts"`
	NonPrincipalRecords int            `json:"nonPrincipalRecords"`
	OutOfScopeRecords   int            `json:"outOfScopeRecords"`
	UnknownServices     map[string]int `json:"unknownServices,omitempty"`
	UncataloguedEvents  map[string]int `json:"uncataloguedEvents,omitempty"`
	First               time.Time      `json:"first"`
	Last                time.Time      `json:"last"`
}

// Dataset holds observations grouped by principal key (see authz.Key).
type Dataset struct {
	ByPrincipal map[string][]Observation
	Stats       Stats
}

// Options controls loading.
type Options struct {
	// Inventory restricts observations to known principals when non-nil.
	Inventory *authz.Inventory
	// From/To bound event times (zero means unbounded); To is exclusive.
	From, To time.Time
	Logger   *slog.Logger
}

// Load reads CloudTrail logs under path and maps them to observations.
func Load(path string, cat *catalog.Catalog, opts Options) (*Dataset, error) {
	ds := &Dataset{ByPrincipal: map[string][]Observation{}}
	ds.Stats.UnknownServices = map[string]int{}
	ds.Stats.UncataloguedEvents = map[string]int{}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := mapper.New(cat)
	err := cloudtrail.ReadPath(path, func(rec cloudtrail.Record) error {
		ds.Stats.Records++
		t, err := rec.Time()
		if err != nil {
			return err
		}
		if (!opts.From.IsZero() && t.Before(opts.From)) || (!opts.To.IsZero() && !t.Before(opts.To)) {
			ds.Stats.OutOfScopeRecords++
			return nil
		}
		principal, ok, reason := rec.PrincipalARN()
		if !ok {
			ds.Stats.NonPrincipalRecords++
			log.Debug("skipping record", "event", rec.EventID, "reason", reason)
			return nil
		}
		key, ok := authz.Key(principal)
		if !ok {
			ds.Stats.NonPrincipalRecords++
			return nil
		}
		if opts.Inventory != nil {
			if _, known := opts.Inventory.Find(principal); !known {
				ds.Stats.OutOfScopeRecords++
				return nil
			}
		}
		calls, err := m.Map(&rec)
		if errors.Is(err, mapper.ErrUnknownService) {
			ds.Stats.UnknownServices[rec.EventSource]++
			return nil
		}
		if err != nil {
			return err
		}
		ctx := rec.Context(principal)
		tlsKnown := !rec.IsUnknownKey("aws:securetransport")
		denied := rec.Denied()
		if denied {
			ds.Stats.DeniedAttempts++
		}
		if ds.Stats.First.IsZero() || t.Before(ds.Stats.First) {
			ds.Stats.First = t
		}
		if t.After(ds.Stats.Last) {
			ds.Stats.Last = t
		}
		for _, c := range calls {
			if c.Confidence == mapper.ConfidenceUncatalogued {
				ds.Stats.UncataloguedEvents[c.Action]++
			}
			ds.ByPrincipal[key] = append(ds.ByPrincipal[key], Observation{
				Principal: principal, Action: c.Action, Resource: c.Resource,
				Confidence: c.Confidence, NoAuth: c.NoAuth, Time: t,
				EventID: rec.EventID, EventName: rec.EventName, Context: ctx,
				Denied: denied, ErrorCode: rec.ErrorCode, tlsKnown: tlsKnown,
			})
			ds.Stats.Observations++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for k := range ds.ByPrincipal {
		obs := ds.ByPrincipal[k]
		sort.SliceStable(obs, func(i, j int) bool { return obs[i].Time.Before(obs[j].Time) })
	}
	return ds, nil
}

// Principals returns the principal keys in sorted order.
func (ds *Dataset) Principals() []string {
	out := make([]string, 0, len(ds.ByPrincipal))
	for k := range ds.ByPrincipal {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Successful returns the observations that were authorized.
func Successful(obs []Observation) []Observation {
	out := make([]Observation, 0, len(obs))
	for _, o := range obs {
		if !o.Denied {
			out = append(out, o)
		}
	}
	return out
}
