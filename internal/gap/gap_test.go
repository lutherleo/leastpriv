package gap

import (
	"strings"
	"testing"
	"time"

	"github.com/lutherleo/leastpriv/internal/activity"
	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/policy"
)

var cat = catalog.Default()

func principal(t *testing.T, boundary string, docs ...string) *authz.Principal {
	t.Helper()
	var ps []string
	for _, d := range docs {
		ps = append(ps, `{"document":`+d+`}`)
	}
	js := `{"principals":[{"arn":"arn:aws:iam::111122223333:role/app","policies":[` + strings.Join(ps, ",") + `]`
	if boundary != "" {
		js += `,"permissionsBoundary":{"name":"b","document":` + boundary + `}`
	}
	inv, err := authz.Parse([]byte(js + `}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return inv.Principals[0]
}

var t0 = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

func obs(action, resource string, day int) activity.Observation {
	return activity.Observation{Action: action, Resource: resource, Time: t0.AddDate(0, 0, day), Context: map[string][]string{}}
}

func row(r *Report, action string) *ActionUsage {
	for i := range r.Actions {
		if r.Actions[i].Action == action {
			return &r.Actions[i]
		}
	}
	return nil
}

func TestAnalyze(t *testing.T) {
	p := principal(t, "", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["sqs:*","logs:PutLogEvents","sts:GetCallerIdentity","rds:*"],"Resource":"*"},
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
		{"Effect":"Allow","NotAction":"iam:*","NotResource":"arn:aws:s3:::secret/*"},
		{"Effect":"Deny","Action":"sqs:DeleteQueue","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:PurgeQueue","Resource":"arn:aws:sqs:us-east-1:1:prod"}]}`)
	denied := obs("iam:CreateUser", "arn:aws:iam::1:user/x", 3)
	denied.Denied = true
	o := []activity.Observation{
		obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:1:q", 1),
		obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:1:q2", 80),
		obs("sqs:ReceiveMessage", "arn:aws:sqs:us-east-1:1:q", 10),
		obs("iam:CustomThing", "*", 5),
		denied, denied,
	}
	rep, err := Analyze(cat, p, o, Options{StaleDays: 30, WindowStart: t0, WindowEnd: t0.AddDate(0, 0, 90)})
	if err != nil {
		t.Fatal(err)
	}
	send := row(rep, "sqs:SendMessage")
	if send.Status != StatusUsed || send.Count != 2 || send.Resources != 2 || *send.AgeDays != 10 || send.Scope != "*" {
		t.Fatalf("send %+v", send)
	}
	if recv := row(rep, "sqs:ReceiveMessage"); recv.Status != StatusStale || *recv.AgeDays != 80 || recv.Risk != "low" {
		t.Fatalf("recv %+v", recv)
	}
	if row(rep, "sqs:DeleteQueue") != nil {
		t.Fatal("unconditionally denied action must not be granted")
	}
	if pq := row(rep, "sqs:PurgeQueue"); pq == nil || pq.Status != StatusUnused || pq.Risk != "high" {
		t.Fatalf("resource-scoped deny leaves the grant: %+v", pq)
	}
	if aq := row(rep, "sqs:AddPermission"); aq.Risk != "high" {
		t.Fatal("permissions management is high risk")
	}
	if tg := row(rep, "sqs:TagQueue"); tg.Risk != "medium" {
		t.Fatal("tagging is medium risk")
	}
	if ple := row(rep, "logs:PutLogEvents"); ple.Status != StatusUnobservable || len(ple.Notes) == 0 {
		t.Fatalf("unobservable %+v", ple)
	}
	if gci := row(rep, "sts:GetCallerIdentity"); gci.Status != StatusNoAuth {
		t.Fatalf("no-auth %+v", gci)
	}
	get := row(rep, "s3:GetObject")
	if get.Scope != "not-resource" || get.Conditional {
		t.Fatalf("NotResource statement also grants GetObject: %+v", get)
	}
	if put := row(rep, "s3:PutObject"); put.Scope != "not-resource" || put.Risk != "high" {
		t.Fatalf("NotResource write: %+v", put)
	}
	if row(rep, "iam:CreateUser") != nil || len(rep.DeniedOnly) != 1 || !strings.Contains(rep.DeniedOnly[0], "2 attempts") {
		t.Fatalf("denied-only %+v", rep.DeniedOnly)
	}
	if c := row(rep, "iam:CustomThing"); c == nil || c.Status != StatusUngranted || c.Access != "unknown" {
		t.Fatalf("uncatalogued used action %+v", c)
	}
	if !strings.Contains(strings.Join(rep.UncataloguedGrants, ";"), "rds:*") || !strings.Contains(strings.Join(rep.UncataloguedGrants, ";"), "NotAction iam:*") {
		t.Fatalf("uncatalogued grants %v", rep.UncataloguedGrants)
	}
	if rep.Used != 1 || rep.Stale != 1 || rep.Granted == 0 || rep.UnusedPercent <= 0 || len(rep.HighRiskUnused) == 0 {
		t.Fatalf("summary %+v", rep)
	}
	if !rep.Now.Equal(t0.AddDate(0, 0, 90)) {
		t.Fatalf("now defaults to window end: %v", rep.Now)
	}
	var sqsSvc *ServiceUsage
	for i := range rep.Services {
		if rep.Services[i].Service == "sqs" {
			sqsSvc = &rep.Services[i]
		}
	}
	if sqsSvc == nil || sqsSvc.UsedActions != 2 || sqsSvc.LastUsed == nil {
		t.Fatalf("service rollup %+v", sqsSvc)
	}
}

func TestBoundaryAndConditional(t *testing.T) {
	p := principal(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:*"],"Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`)
	rep, err := Analyze(cat, p, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if row(rep, "iam:CreateUser") != nil {
		t.Fatal("boundary must remove iam grants")
	}
	g := row(rep, "s3:GetObject")
	if g == nil || !g.Conditional || g.Scope != "scoped" || g.Status != StatusUnused {
		t.Fatalf("%+v", g)
	}
	if !rep.Now.IsZero() {
		t.Fatal("no activity and no window: zero now")
	}
	granted := Granted(cat, p)
	if len(granted) != 1 || granted[0] != "s3:GetObject" {
		t.Fatalf("Granted %v", granted)
	}
	explicit := Options{Now: t0}
	rep, _ = Analyze(cat, p, []activity.Observation{obs("s3:GetObject", "arn:aws:s3:::b/k", 5)}, explicit)
	if a := row(rep, "s3:GetObject"); *a.AgeDays != 0 || rep.StaleDays != 30 {
		t.Fatalf("future use clamps age at 0: %+v", a)
	}
	d, _ := policy.Parse([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	if got := GrantedByDocs(cat, []*policy.Document{d}, nil); len(got) != len(cat.Actions())-1 {
		t.Fatalf("admin grants every catalog action except no-auth ones: %d", len(got))
	}
	bad := principal(t, "", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Nope":{"k":"v"}}}]}`)
	if _, err := Analyze(cat, bad, nil, Options{}); err == nil {
		t.Fatal("bad policy must error")
	}
}
