package generator

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/mapper"
	"github.com/lutherleo/leastpriv/internal/policy"
)

// The property under test, for every aggressiveness level:
//
//	observed ⊆ generated ⊆ original
//
// (1) every observed call the original policies allow is allowed by the
//     generated policy under the same request context, and
// (2) no request in a dense universe of actions x resources x contexts is
//     allowed by the generated policy but denied by the original.
//
// Policies, observations and contexts are drawn at random from pools that
// exercise wildcards, NotAction/NotResource, conditions (including keys
// CloudTrail cannot carry), policy variables, 2008-version documents,
// explicit denies and permissions boundaries.

var (
	propActions = []string{
		"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetObjectTagging", "s3:GetObjectAcl",
		"sqs:SendMessage", "sqs:ReceiveMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ListQueueTags",
		"dynamodb:GetItem", "dynamodb:Query", "dynamodb:DescribeTable", "dynamodb:Scan", "dynamodb:DescribeTimeToLive",
	}
	propActionPatterns = append([]string{"s3:*", "s3:Get*", "s3:*Object", "sqs:*", "sqs:Get*", "dynamodb:*", "dynamodb:Describe*", "*", "S3:GETOBJECT"}, propActions...)
	propResources      = func() []string {
		var out []string
		for _, b := range []string{"b1", "b2"} {
			out = append(out, "arn:aws:s3:::"+b)
			for _, dir := range []string{"a", "b", "alice", "bob"} {
				for _, k := range []string{"x1", "x2", "x3", "y-1", "y-2"} {
					out = append(out, "arn:aws:s3:::"+b+"/"+dir+"/"+k)
				}
			}
		}
		for _, q := range []string{"jobs-a", "jobs-b", "jobs-c", "events"} {
			out = append(out, "arn:aws:sqs:us-east-1:1:"+q)
		}
		for _, t := range []string{"t1", "t2"} {
			out = append(out, "arn:aws:dynamodb:us-east-1:1:table/"+t)
			for _, i := range []string{"i1", "i2", "i3"} {
				out = append(out, "arn:aws:dynamodb:us-east-1:1:table/"+t+"/index/"+i)
			}
		}
		// "*" (resource-less), a partial-mapping pattern, and object keys
		// holding characters that are wildcards or variables in policy text.
		return append(out, "*", "arn:aws:s3:::b1/*", "arn:aws:s3:::b1/a/x*1", "arn:aws:s3:::b2/b/q?", "arn:aws:s3:::b2/alice/${aws:username}")
	}()
	propResourcePatterns = []string{
		"*", "arn:aws:s3:::b1/*", "arn:aws:s3:::b1/a/*", "arn:aws:s3:::*", "arn:aws:s3:::b?/*", "arn:aws:s3:::b1/a/x?",
		"arn:aws:s3:::b1", "arn:aws:s3:::b2/b/y-*", "arn:aws:sqs:*:1:jobs-*", "arn:aws:sqs:us-east-1:1:*",
		"arn:aws:dynamodb:us-east-1:1:table/t1*", "arn:aws:dynamodb:*:*:table/*", "arn:aws:dynamodb:us-east-1:1:table/t2",
		"arn:aws:s3:::b1/${aws:username}/*", "arn:aws:s3:::b2/${aws:username, 'a'}/x?",
		// Matches the partial observation "arn:aws:s3:::b1/*" without
		// subsuming it, which forces the generator's fallback to the source's
		// own resource element (and, from a 2008 document, its literal '${').
		"arn:aws:s3:::b1/?",
	}
	propConditions = []string{
		``,
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}`,
		`"Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
		`"Condition":{"Bool":{"aws:SecureTransport":"true"}}`,
		`"Condition":{"StringLike":{"aws:ResourceTag/env":"prod*"}}`,
		`"Condition":{"StringNotEquals":{"aws:username":"bob"}}`,
		`"Condition":{"Null":{"aws:username":"false"}}`,
	}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func pickN(r *rand.Rand, xs []string, max int) []string {
	n := 1 + r.IntN(max)
	out := make([]string, n)
	for i := range out {
		out[i] = pick(r, xs)
	}
	return out
}

func quoteList(xs []string) string {
	b, _ := json.Marshal(xs)
	return string(b)
}

func randomStatement(r *rand.Rand, allowBias float64) string {
	effect := "Allow"
	if r.Float64() > allowBias {
		effect = "Deny"
	}
	parts := []string{`"Effect":"` + effect + `"`}
	if r.IntN(10) == 0 {
		parts = append(parts, `"NotAction":`+quoteList(pickN(r, propActionPatterns, 2)))
	} else {
		parts = append(parts, `"Action":`+quoteList(pickN(r, propActionPatterns, 4)))
	}
	if r.IntN(10) == 0 {
		parts = append(parts, `"NotResource":`+quoteList(pickN(r, propResourcePatterns, 2)))
	} else {
		parts = append(parts, `"Resource":`+quoteList(pickN(r, propResourcePatterns, 3)))
	}
	if c := pick(r, propConditions); c != "" && r.IntN(3) == 0 {
		parts = append(parts, c)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func randomDoc(r *rand.Rand, allowBias float64) string {
	n := 1 + r.IntN(5)
	sts := make([]string, n)
	for i := range sts {
		sts[i] = randomStatement(r, allowBias)
	}
	version := "2012-10-17"
	if r.IntN(10) == 0 {
		version = "2008-10-17"
	}
	return `{"Version":"` + version + `","Statement":[` + strings.Join(sts, ",") + `]}`
}

func randomContext(r *rand.Rand) map[string][]string {
	ctx := map[string][]string{
		"aws:requestedregion": {pick(r, []string{"us-east-1", "eu-west-1"})},
		"aws:sourceip":        {pick(r, []string{"10.1.2.3", "203.0.113.9"})},
		"aws:securetransport": {pick(r, []string{"true", "false"})},
	}
	if r.IntN(3) > 0 {
		ctx["aws:username"] = []string{pick(r, []string{"alice", "bob", "a"})}
	}
	return ctx
}

func randomPrincipal(t *testing.T, r *rand.Rand) *authz.Principal {
	nDocs := 1 + r.IntN(2)
	var docs []string
	for i := 0; i < nDocs; i++ {
		docs = append(docs, randomDoc(r, 0.8))
	}
	boundary := ""
	if r.IntN(5) == 0 {
		boundary = randomDoc(r, 0.9)
	}
	return principal(t, boundary, docs...)
}

func randomObservations(r *rand.Rand) []activity.Observation {
	var observations []activity.Observation
	for i := 0; i < 5+r.IntN(40); i++ {
		o := obs(pick(r, propActions), pick(r, propResources))
		if strings.HasSuffix(o.Resource, "/*") {
			o.Confidence = mapper.ConfidencePartial
		}
		o.Context = randomContext(r)
		observations = append(observations, o)
	}
	return observations
}

// propertyBudget returns the iteration count and seed, overridable by
// LP_PROPERTY_ITER / LP_PROPERTY_SEED for longer soak runs.
func propertyBudget(iterations, short int) (int, uint64) {
	seed := uint64(2026)
	if testing.Short() {
		iterations = short
	}
	if v, err := strconv.Atoi(os.Getenv("LP_PROPERTY_ITER")); err == nil && v > 0 {
		iterations = v
	}
	if v, err := strconv.ParseUint(os.Getenv("LP_PROPERTY_SEED"), 10, 64); err == nil {
		seed = v
	}
	return iterations, seed
}

type propertyStats struct{ replay, subset, generatedAllows, fallbacks int }

func TestPropertyObservedSubsetGeneratedSubsetOriginal(t *testing.T) {
	iterations, seed := propertyBudget(400, 60)
	r := rand.New(rand.NewPCG(8, seed))
	var stats propertyStats
	for it := 0; it < iterations; it++ {
		checkProperty(t, r, it, randomPrincipal(t, r), randomObservations(r), &stats)
	}
	t.Logf("replay checks: %d, subset checks: %d (%d allowed by generated)", stats.replay, stats.subset, stats.generatedAllows)
	// The strength floor scales with the budget (2.5 checks per iteration,
	// i.e. 1000 at the default 400) so that -short and LP_PROPERTY_ITER runs
	// are held to the same per-iteration standard as the full run.
	minChecks := iterations * 5 / 2
	if stats.replay < minChecks || stats.generatedAllows < minChecks {
		t.Fatalf("property exercised too weakly: replay=%d generatedAllows=%d (want >= %d each for %d iterations)", stats.replay, stats.generatedAllows, minChecks, iterations)
	}
}

// The resource fallback (an observed partial resource that cannot be proved
// inside its source statement) is rare under the general pools, and from a
// 2008-10-17 document it must keep the source's '${' literal. This property
// draws only 2008 documents whose Allow statements match the partial
// observation "arn:aws:s3:::b1/*" through "arn:aws:s3:::b1/?" without
// subsuming it, alongside patterns holding '${', so the fallback runs on
// almost every iteration.
func TestPropertyFallbackFrom2008Source(t *testing.T) {
	iterations, seed := propertyBudget(200, 40)
	r := rand.New(rand.NewPCG(9, seed))
	varPatterns := []string{"arn:aws:s3:::b1/${aws:username}/*", "arn:aws:s3:::b2/${aws:username, 'a'}/x?", "arn:aws:s3:::b2/alice/${aws:username}", "arn:aws:s3:::b2/*/${aws:username}"}
	narrow := []string{"arn:aws:s3:::b1/a/*", "arn:aws:s3:::b2/b/y-*", "arn:aws:s3:::b1/a/x?", "arn:aws:s3:::b1"}
	statement := func() string {
		res := []string{"arn:aws:s3:::b1/?", pick(r, varPatterns)}
		if r.IntN(2) == 0 {
			res = append(res, pick(r, narrow))
		}
		field := "Resource"
		if r.IntN(4) == 0 {
			field, res = "NotResource", []string{pick(r, varPatterns)}
		}
		parts := []string{`"Effect":"Allow"`, `"Action":` + quoteList(pickN(r, []string{"s3:GetObject", "s3:Get*", "s3:*Object", "s3:PutObject", "s3:*"}, 2)), `"` + field + `":` + quoteList(res)}
		if c := pick(r, propConditions); c != "" && r.IntN(4) == 0 {
			parts = append(parts, c)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	var stats propertyStats
	for it := 0; it < iterations; it++ {
		sts := []string{statement()}
		if r.IntN(3) == 0 {
			sts = append(sts, statement())
		}
		if r.IntN(4) == 0 {
			sts = append(sts, randomStatement(r, 0))
		}
		p := principal(t, "", `{"Version":"2008-10-17","Statement":[`+strings.Join(sts, ",")+`]}`)
		observations := randomObservations(r)
		for _, a := range []string{"s3:GetObject", "s3:PutObject"} {
			o := obs(a, "arn:aws:s3:::b1/*")
			o.Confidence = mapper.ConfidencePartial
			o.Context = randomContext(r)
			observations = append(observations, o)
		}
		checkProperty(t, r, it, p, observations, &stats)
	}
	t.Logf("fallbacks: %d, replay checks: %d, subset checks: %d (%d allowed by generated)", stats.fallbacks, stats.replay, stats.subset, stats.generatedAllows)
	if stats.fallbacks < iterations {
		t.Fatalf("fallback path exercised too weakly: %d fallbacks in %d iterations", stats.fallbacks, iterations)
	}
}

// checkProperty generates at every level and asserts
// observed ⊆ generated ⊆ original over the dense request universe.
func checkProperty(t *testing.T, r *rand.Rand, it int, p *authz.Principal, observations []activity.Observation, stats *propertyStats) {
	t.Helper()
	orig, err := p.PolicySet()
	if err != nil {
		t.Fatal(err)
	}
	{
		contexts := []engine.Request{{Unknown: engine.AllUnknown}, {Context: randomContext(r)}, {Context: randomContext(r), Unknown: activity.UnknownFunc(false)}}
		for _, level := range []Level{LevelExact, LevelModerate, LevelAggressive} {
			res, err := Generate(cat, Input{Principal: p, Observations: observations}, Options{Level: level, MinActions: 2})
			if err != nil {
				t.Fatalf("iteration %d %s: %v", it, level, err)
			}
			stats.fallbacks += len(res.Fallbacks)
			gen := &engine.Set{Boundary: orig.Boundary}
			if res.Policy != nil {
				if issues := engine.Validate(res.Policy); policy.HasErrors(issues) {
					t.Fatalf("invalid generated policy: %v", issues)
				}
				gen.Identity = []*engine.Policy{engine.MustCompile("generated", res.Policy)}
			}
			describe := func() string {
				var docs []string
				for _, nd := range p.Policies {
					b, _ := json.Marshal(nd.Doc)
					docs = append(docs, string(b))
				}
				if p.Boundary != nil {
					b, _ := json.Marshal(p.Boundary.Doc)
					docs = append(docs, "boundary: "+string(b))
				}
				g, _ := json.Marshal(res.Policy)
				return fmt.Sprintf("iteration %d level %s\noriginal:\n%s\ngenerated:\n%s", it, level, strings.Join(docs, "\n"), g)
			}
			// (1) observed ⊆ generated.
			for _, o := range observations {
				req := o.Request()
				if orig.Allows(req) {
					stats.replay++
					if !gen.Allows(req) {
						t.Fatalf("observed call %s on %s (ctx %v) allowed by original but not generated\n%s", o.Action, o.Resource, o.Context, describe())
					}
				}
			}
			// (2) generated ⊆ original.
			for _, base := range append(contexts, engine.Request{Context: observations[0].Context}) {
				for _, a := range propActions {
					for _, res := range propResources {
						req := base
						req.Action, req.Resource = a, res
						stats.subset++
						if !gen.Allows(req) {
							continue
						}
						stats.generatedAllows++
						if !orig.Allows(req) {
							t.Fatalf("generated allows %s on %s (ctx %v) but original does not\n%s", a, res, req.Context, describe())
						}
					}
				}
			}
		}
	}
}
