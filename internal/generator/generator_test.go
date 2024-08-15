package generator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/engine"
	"github.com/lutherleo/leastpriv/internal/mapper"
	"github.com/lutherleo/leastpriv/internal/policy"
)

var cat = catalog.Default()

func principal(t testing.TB, boundary string, docs ...string) *authz.Principal {
	t.Helper()
	var ps []string
	for _, d := range docs {
		ps = append(ps, `{"document":`+d+`}`)
	}
	js := `{"principals":[{"arn":"arn:aws:iam::111122223333:role/app","policies":[` + strings.Join(ps, ",") + `]`
	if boundary != "" {
		js += `,"permissionsBoundary":{"name":"b","document":` + boundary + `}`
	}
	js += `}]}`
	inv, err := authz.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return inv.Principals[0]
}

func obs(action, resource string, ctx ...string) activity.Observation {
	o := activity.Observation{Action: action, Resource: resource, Confidence: mapper.ConfidenceExact,
		Time: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Context: map[string][]string{}}
	for i := 0; i+1 < len(ctx); i += 2 {
		o.Context[strings.ToLower(ctx[i])] = []string{ctx[i+1]}
	}
	return o
}

func gen(t testing.TB, p *authz.Principal, level Level, o ...activity.Observation) *Result {
	t.Helper()
	res, err := Generate(cat, Input{Principal: p, Observations: o}, Options{Level: level})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func doc(stmts string) string { return `{"Version":"2012-10-17","Statement":[` + stmts + `]}` }

func resourcesOf(res *Result, action string) []string {
	if res.Policy == nil {
		return nil
	}
	for _, st := range res.Policy.Statement {
		if st.Effect != policy.Allow {
			continue
		}
		for _, a := range st.Action {
			if a == action {
				return st.Resource
			}
		}
	}
	return nil
}

func objects(bucket string, keys ...string) []activity.Observation {
	var out []activity.Observation
	for _, k := range keys {
		out = append(out, obs("s3:GetObject", "arn:aws:s3:::"+bucket+"/"+k))
	}
	return out
}

func TestLevels(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`))
	o := objects("b", "logs/2026/07/01/a", "logs/2026/07/01/b", "logs/2026/07/01/c",
		"logs/2026/07/02/a", "logs/2026/07/02/b", "logs/2026/07/02/c",
		"logs/2026/07/03/a", "logs/2026/07/03/b", "logs/2026/07/03/c", "other/x")
	exact := gen(t, p, LevelExact, o...)
	if got := resourcesOf(exact, "s3:GetObject"); len(got) != 10 {
		t.Fatalf("exact: %v", got)
	}
	mod := gen(t, p, LevelModerate, o...)
	if got := strings.Join(resourcesOf(mod, "s3:GetObject"), ","); got != "arn:aws:s3:::b/logs/2026/07/*,arn:aws:s3:::b/other/x" {
		t.Fatalf("moderate: %s", got)
	}
	agg := gen(t, p, LevelAggressive, o...)
	if got := strings.Join(resourcesOf(agg, "s3:GetObject"), ","); got != "arn:aws:s3:::b/*" {
		t.Fatalf("aggressive: %s", got)
	}
	if len(mod.Collapses) != 1 || mod.Collapses[0].Replaces != 9 {
		t.Fatalf("collapse records %+v", mod.Collapses)
	}
}

func TestModerateKeepsSmallAndChains(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`))
	// Two siblings: below the threshold of three.
	r := gen(t, p, LevelModerate, objects("b", "x/1", "x/2")...)
	if len(resourcesOf(r, "s3:GetObject")) != 2 {
		t.Fatal("two siblings must stay exact")
	}
	// Build folders that each hold one file are unbranched chains.
	r = gen(t, p, LevelModerate, objects("b", "builds/1/m.json", "builds/2/m.json", "builds/3/m.json")...)
	if got := resourcesOf(r, "s3:GetObject"); len(got) != 1 || got[0] != "arn:aws:s3:::b/builds/*" {
		t.Fatalf("chains: %v", got)
	}
	// A terminal resource that is also a folder keeps its own entry.
	r = gen(t, p, LevelModerate, objects("b", "d", "d/1", "d/2", "d/3")...)
	if got := strings.Join(resourcesOf(r, "s3:GetObject"), ","); got != "arn:aws:s3:::b/d,arn:aws:s3:::b/d/*" {
		t.Fatalf("terminal folder: %s", got)
	}
}

func TestFlatNamespacesNeverBecomeStar(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":"sqs:*","Resource":"*"}`))
	var o []activity.Observation
	for _, q := range []string{"jobs-a", "jobs-b", "jobs-c", "events"} {
		o = append(o, obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:111122223333:"+q))
	}
	mod := gen(t, p, LevelModerate, o...)
	if len(resourcesOf(mod, "sqs:SendMessage")) != 4 {
		t.Fatal("moderate must not wildcard queue names")
	}
	agg := gen(t, p, LevelAggressive, o...)
	got := strings.Join(resourcesOf(agg, "sqs:SendMessage"), ",")
	if got != "arn:aws:sqs:us-east-1:111122223333:events,arn:aws:sqs:us-east-1:111122223333:jobs-*" {
		t.Fatalf("aggressive name prefix: %s", got)
	}
}

func TestCollapseRespectsSource(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/up/a*"}`))
	r := gen(t, p, LevelAggressive, objects("b", "up/a1", "up/a2", "up/a3")...)
	if got := resourcesOf(r, "s3:GetObject"); len(got) != 3 {
		t.Fatalf("uncovered wildcard must not be emitted: %v", got)
	}
	// Name-prefix candidate not covered either.
	p2 := principal(t, "", doc(`{"Effect":"Allow","Action":"sqs:SendMessage","Resource":["arn:aws:sqs:us-east-1:1:jobs-a","arn:aws:sqs:us-east-1:1:jobs-b"]}`))
	r = gen(t, p2, LevelAggressive, obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:1:jobs-a"), obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:1:jobs-b"))
	if got := resourcesOf(r, "sqs:SendMessage"); len(got) != 2 {
		t.Fatalf("name prefix not covered: %v", got)
	}
}

func TestActionCollapse(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":["sqs:*"],"Resource":"*"}`))
	q := "arn:aws:sqs:us-east-1:1:jobs"
	o := []activity.Observation{obs("sqs:GetQueueAttributes", q), obs("sqs:GetQueueUrl", q), obs("sqs:ListQueueTags", q),
		obs("sqs:SendMessage", q), obs("sqs:SetQueueAttributes", q)}
	r, err := Generate(cat, Input{Principal: p, Observations: o}, Options{Level: LevelAggressive, MinActions: 2})
	if err != nil {
		t.Fatal(err)
	}
	acts := strings.Join(r.Policy.Statement[0].Action, ",")
	if acts != "sqs:Get*,sqs:ListQueueTags,sqs:SendMessage,sqs:SetQueueAttributes" {
		t.Fatalf("actions: %s", acts)
	}
	if len(r.Expansions) != 1 || r.Expansions[0].Pattern != "sqs:Get*" || len(r.Expansions[0].Unobserved) != 0 {
		t.Fatalf("expansions %+v", r.Expansions)
	}
	// Write verbs are never wildcarded, and the source must cover the pattern.
	p2 := principal(t, "", doc(`{"Effect":"Allow","Action":["sqs:GetQueueAttributes","sqs:GetQueueUrl"],"Resource":"*"}`))
	r, _ = Generate(cat, Input{Principal: p2, Observations: o[:2]}, Options{Level: LevelAggressive, MinActions: 2})
	if strings.Contains(strings.Join(r.Policy.Statement[0].Action, ","), "*") {
		t.Fatal("collapse beyond source")
	}
	// ec2 Describe* expands to unobserved catalog actions and records them.
	p3 := principal(t, "", doc(`{"Effect":"Allow","Action":"ec2:*","Resource":"*"}`))
	r = gen(t, p3, LevelAggressive, obs("ec2:DescribeInstances", "*"), obs("ec2:DescribeVolumes", "*"), obs("ec2:DescribeVpcs", "*"))
	if len(r.Expansions) != 1 || len(r.Expansions[0].Unobserved) == 0 {
		t.Fatalf("describe expansion %+v", r.Expansions)
	}
}

func TestNotActionAndNotResourceSources(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","NotAction":"iam:*","NotResource":"arn:aws:s3:::secret/*"}`))
	partial := obs("s3:GetObject", "arn:aws:s3:::b/*")
	partial.Confidence = mapper.ConfidencePartial
	o := append(objects("b", "x/1", "x/2", "x/3"), partial)
	r := gen(t, p, LevelAggressive, o...)
	if len(r.Grants) != 1 || strings.Join(r.Grants[0].NotResource, ",") != "arn:aws:s3:::secret/*" {
		t.Fatalf("pattern resource under NotResource must fall back to the source scope: %+v", r.Grants)
	}
	if len(r.Fallbacks) != 1 || !strings.Contains(r.Fallbacks[0].Reason, "pattern") {
		t.Fatalf("fallback must be reported: %+v", r.Fallbacks)
	}
	r = gen(t, p, LevelAggressive, objects("b", "x/1", "x/2", "x/3")...)
	if got := resourcesOf(r, "s3:GetObject"); len(got) != 3 {
		t.Fatalf("NotResource source keeps concrete resources: %v", got)
	}
}

func TestVariableResourcesCopiedVerbatim(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username}/*"}`))
	r := gen(t, p, LevelModerate, obs("s3:GetObject", "arn:aws:s3:::home/alice/a", "aws:username", "alice"))
	if got := resourcesOf(r, "s3:GetObject"); len(got) != 1 || got[0] != "arn:aws:s3:::home/${aws:username}/*" {
		t.Fatalf("variable resource: %v", got)
	}
	p2 := principal(t, "", doc(`{"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::home/${aws:username}/private/*"}`))
	r = gen(t, p2, LevelModerate, obs("s3:GetObject", "arn:aws:s3:::home/alice/a", "aws:username", "alice"))
	if len(r.Grants) != 1 || len(r.Grants[0].NotResource) != 1 || r.Policy.Statement[0].NotResource == nil {
		t.Fatalf("NotResource with variables: %+v", r.Grants)
	}
}

func TestConditionsDeniesAndAttribution(t *testing.T) {
	p := principal(t, "",
		doc(`{"Sid":"Broad","Effect":"Allow","Action":"s3:*","Resource":"*"},`+
			`{"Sid":"Narrow","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},`+
			`{"Sid":"NoDelete","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}`),
		doc(`{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"},{"Sid":"Broad","Effect":"Deny","Action":"iam:*","Resource":"*"}`))
	o := obs("s3:GetObject", "arn:aws:s3:::b/k", "aws:SecureTransport", "true")
	r := gen(t, p, LevelExact, o)
	st := r.Policy.Statement[0]
	if st.Condition == nil || st.Condition["Bool"]["aws:SecureTransport"][0] != "true" {
		t.Fatalf("conditional source must be preferred: %+v", st)
	}
	if r.Grants[0].Sources[0].Sid != "Narrow" {
		t.Fatalf("provenance %+v", r.Grants[0].Sources)
	}
	if r.Denies != 2 {
		t.Fatalf("duplicate denies must collapse: %d", r.Denies)
	}
	sids := map[string]bool{}
	for _, s := range r.Policy.Statement {
		if sids[s.Sid] {
			t.Fatalf("duplicate Sid %s", s.Sid)
		}
		sids[s.Sid] = true
	}
}

func TestUngrantedSkippedDenied(t *testing.T) {
	p := principal(t, doc(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`),
		doc(`{"Effect":"Allow","Action":["s3:GetObject","dynamodb:GetItem"],"Resource":"*"}`))
	denied := obs("s3:PutObject", "arn:aws:s3:::b/k")
	denied.Denied = true
	noauth := obs("sts:GetCallerIdentity", "*")
	noauth.NoAuth = true
	r := gen(t, p, LevelModerate,
		obs("s3:GetObject", "arn:aws:s3:::b/k"),
		obs("s3:GetObject", "arn:aws:s3:::b/k"), // duplicate
		obs("dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:1:table/t"),
		obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:1:q"),
		denied, noauth)
	if r.ObservedCalls != 3 || r.GrantedCalls != 1 {
		t.Fatalf("counts %d %d", r.ObservedCalls, r.GrantedCalls)
	}
	if len(r.Ungranted) != 2 || !strings.Contains(r.Ungranted[0].Reason, "boundary") {
		t.Fatalf("ungranted %+v", r.Ungranted)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Action != "sts:GetCallerIdentity" {
		t.Fatalf("skipped %+v", r.Skipped)
	}
	empty := gen(t, p, LevelModerate)
	if empty.Policy != nil || len(empty.Warnings) == 0 {
		t.Fatal("no activity must yield no policy and a warning")
	}
}

func TestVersion2008Literalized(t *testing.T) {
	p := principal(t, "", `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringLike":{"s3:prefix":"${literal}*"}}},`+
		`{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/${aws:username}/*"}]}`)
	r := gen(t, p, LevelModerate, obs("s3:ListBucket", "arn:aws:s3:::b", "s3:prefix", "${literal}x"))
	b, _ := json.Marshal(r.Policy)
	if !strings.Contains(string(b), `${$}{literal}*`) || !strings.Contains(string(b), `b/${$}{aws:username}/*`) {
		t.Fatalf("2008 text must stay literal in 2012 output: %s", b)
	}
	set := &engine.Set{Identity: []*engine.Policy{engine.MustCompile("g", r.Policy)}}
	req := obs("s3:ListBucket", "arn:aws:s3:::b", "s3:prefix", "${literal}x").Request()
	if !set.Allows(req) {
		t.Fatal("literalized condition must still match the literal text")
	}
}

func TestSplitAndOptions(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}`))
	var o []activity.Observation
	for i := 0; i < 40; i++ {
		o = append(o, obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:111122223333:queue-number-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26))))
		o = append(o, obs("dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:111122223333:table/t"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	r, err := Generate(cat, Input{Principal: p, Observations: o}, Options{Level: LevelExact, MaxSize: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Parts) < 2 {
		t.Fatalf("expected split, size %d parts %d", r.Size, len(r.Parts))
	}
	total := 0
	for _, part := range r.Parts {
		n, _ := part.Size()
		if n > 3000 {
			t.Fatalf("part too large: %d", n)
		}
		total += len(part.Statement)
	}
	if total != len(r.Policy.Statement) {
		t.Fatal("split lost statements")
	}
	if _, err := Split(r.Policy, 50); err == nil {
		t.Fatal("impossible split must fail")
	}
	r, _ = Generate(cat, Input{Principal: p, Observations: o}, Options{Level: LevelExact, MaxSize: 10})
	if len(r.Warnings) == 0 || r.Parts != nil {
		t.Fatal("unsplittable policy must warn")
	}
	if _, err := ParseLevel("loose"); err == nil {
		t.Fatal("ParseLevel")
	}
	if _, err := Generate(cat, Input{Principal: p}, Options{Level: "loose"}); err == nil {
		t.Fatal("bad level accepted")
	}
	def, _ := Generate(cat, Input{Principal: p, Observations: o[:1]}, Options{})
	if def.Level != LevelModerate {
		t.Fatal("default level")
	}
}

func TestBadPolicyFails(t *testing.T) {
	inv, err := authz.Parse([]byte(`{"principals":[{"arn":"arn:aws:iam::1:role/a","policies":[{"document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Nope":{"k":"v"}}}]}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(cat, Input{Principal: inv.Principals[0]}, Options{}); err == nil {
		t.Fatal("uncompilable policy must fail")
	}
}

func TestHelpers(t *testing.T) {
	if alnumTitle("secretsmanager") != "Secretsmanager" || alnumTitle("a-b_c") != "ABC" || alnumTitle("x9") != "X9" {
		t.Fatal("alnumTitle")
	}
	if contextSignature(map[string][]string{"a": {"1"}}, nil) != "" {
		t.Fatal("empty signature")
	}
	if got := dedupeSorted([]string{"b", "a", "b"}); strings.Join(got, ",") != "a,b" {
		t.Fatal("dedupe")
	}
}

// Object keys may legally contain '*', '?' and "${". Emitted verbatim they
// would act as wildcards or policy variables in the generated policy, so the
// generator writes them with IAM's literal escapes ${*}, ${?} and ${$}.
func TestLiteralWildcardCharactersInObservedResources(t *testing.T) {
	p := principal(t, "", doc(`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b1/*"}`))
	keys := []string{"a/x*y", "a/q?.csv", "a/${aws:username}.txt"}
	for _, level := range []Level{LevelExact, LevelModerate, LevelAggressive} {
		res := gen(t, p, level, objects("b1", keys...)...)
		set := &engine.Set{Identity: []*engine.Policy{engine.MustCompile("gen", res.Policy)}}
		for _, k := range keys {
			r := "arn:aws:s3:::b1/" + k
			if ev := set.Evaluate(engine.NewRequest("s3:GetObject", r)); !ev.Allowed() {
				t.Errorf("%s: observed %s not allowed: %s", level, r, ev.Reason)
			}
		}
		for _, r := range []string{"arn:aws:s3:::b1/a/x-anything-y", "arn:aws:s3:::b1/a/qZ.csv", "arn:aws:s3:::b1/a/alice.txt"} {
			req := engine.NewRequest("s3:GetObject", r)
			req.Set("aws:username", "alice")
			if ev := set.Evaluate(req); ev.Allowed() && level == LevelExact {
				t.Errorf("%s: literal characters acted as wildcards/variables: %s allowed", level, r)
			}
		}
		if level == LevelExact {
			want := []string{"arn:aws:s3:::b1/a/q${?}.csv", "arn:aws:s3:::b1/a/x${*}y", "arn:aws:s3:::b1/a/${$}{aws:username}.txt"}
			got := strings.Join(resourcesOf(res, "s3:GetObject"), " ")
			for _, w := range want {
				if !strings.Contains(got, w) {
					t.Errorf("exact resources %q missing %q", got, w)
				}
			}
		}
	}
}

// A 2008-version source's Resource text is literal. When the generator falls
// back to the source's own resource scope (an observed partial resource it
// cannot prove inside the statement), the copied text must be escaped for the
// 2012-10-17 output, or '${aws:username}' would turn into a live variable and
// widen the grant.
func TestFallbackFrom2008SourceStaysLiteral(t *testing.T) {
	for _, field := range []string{"Resource", "NotResource"} {
		var src string
		if field == "Resource" {
			src = `{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::b1/?","arn:aws:s3:::b2/${aws:username}"]}`
		} else {
			src = `{"Effect":"Allow","Action":"s3:GetObject","NotResource":["arn:aws:s3:::b2/${aws:username}"]}`
		}
		p := principal(t, "", `{"Version":"2008-10-17","Statement":[`+src+`]}`)
		orig, err := p.PolicySet()
		if err != nil {
			t.Fatal(err)
		}
		o := obs("s3:GetObject", "arn:aws:s3:::b1/*")
		o.Confidence = mapper.ConfidencePartial
		for _, level := range []Level{LevelExact, LevelModerate, LevelAggressive} {
			res := gen(t, p, level, o)
			if res.Policy == nil {
				t.Fatalf("%s %s: no policy generated", field, level)
			}
			if len(res.Fallbacks) == 0 && field == "Resource" {
				t.Fatalf("%s %s: expected the fallback path to run", field, level)
			}
			b, _ := json.Marshal(res.Policy)
			if !strings.Contains(string(b), `b2/${$}{aws:username}`) {
				t.Errorf("%s %s: 2008 text not literalized in fallback: %s", field, level, b)
			}
			set := &engine.Set{Identity: []*engine.Policy{engine.MustCompile("gen", res.Policy)}}
			if !set.Allows(o.Request()) {
				t.Errorf("%s %s: observed call no longer allowed", field, level)
			}
			for _, user := range []string{"alice", "${aws:username}"} {
				for _, r := range []string{"arn:aws:s3:::b2/alice", "arn:aws:s3:::b2/${aws:username}", "arn:aws:s3:::b1/x"} {
					req := engine.NewRequest("s3:GetObject", r)
					req.Set("aws:username", user)
					if set.Allows(req) && !orig.Allows(req) {
						t.Errorf("%s %s: generated allows %s (aws:username=%s) but original does not: %s", field, level, r, user, b)
					}
				}
			}
		}
	}
}
