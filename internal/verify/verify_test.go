package verify

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

func mustDoc(t *testing.T, js string) *policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func obs(action, resource string) activity.Observation {
	return activity.Observation{Action: action, Resource: resource, Time: time.Unix(0, 0), EventID: "e-" + action,
		Context: map[string][]string{"aws:requestedregion": {"us-east-1"}}}
}

const original = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::b/*"},{"Effect":"Deny","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/locked/*"}]}`

func TestVerifyPass(t *testing.T) {
	p := principal(t, "", original)
	gen := mustDoc(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/data/*"}]}`)
	denied := obs("s3:PutObject", "arn:aws:s3:::b/x")
	denied.Denied = true
	o := []activity.Observation{obs("s3:GetObject", "arn:aws:s3:::b/data/1"), obs("s3:GetObject", "arn:aws:s3:::b/data/2"),
		obs("sqs:SendMessage", "arn:aws:sqs:us-east-1:1:q"), denied}
	rep, err := Verify(cat, p, []*policy.Document{gen}, o, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Replayed != 2 || rep.ReplayAllowed != 2 || rep.ReplaySkipped != 1 || rep.GeneratedAllows == 0 || rep.SubsetContexts != 2 {
		t.Fatalf("%+v", rep)
	}
}

func TestVerifyDetectsReplayFailure(t *testing.T) {
	p := principal(t, "", original)
	gen := mustDoc(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/data/*"}]}`)
	rep, err := Verify(cat, p, []*policy.Document{gen}, []activity.Observation{obs("s3:GetObject", "arn:aws:s3:::b/other/1")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || len(rep.Failures) != 1 || rep.Failures[0].Decision != "implicitDeny" {
		t.Fatalf("%+v", rep)
	}
}

func TestVerifyDetectsSubsetViolation(t *testing.T) {
	p := principal(t, "", original)
	// Drops the original's Deny on b/locked/*.
	gen := mustDoc(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]}`)
	rep, err := Verify(cat, p, []*policy.Document{gen}, []activity.Observation{obs("s3:GetObject", "arn:aws:s3:::b/data/1")}, Options{MaxContexts: -1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || len(rep.Violations) == 0 || rep.SubsetContexts != 1 {
		t.Fatalf("%+v", rep)
	}
	found := false
	for _, v := range rep.Violations {
		if v.Action == "s3:PutObject" && strings.HasPrefix(v.Resource, "arn:aws:s3:::b/locked/") && v.Original == "explicitDeny" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the dropped deny to surface: %+v", rep.Violations)
	}
}

func TestVerifySampling(t *testing.T) {
	p := principal(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, original)
	gen := mustDoc(t, original)
	rep, err := Verify(cat, p, []*policy.Document{gen}, []activity.Observation{obs("s3:GetObject", "arn:aws:s3:::b/data/1")}, Options{MaxPairs: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.SubsetSampled || !rep.OK || rep.SubsetChecked > 100*rep.SubsetContexts+rep.SubsetContexts {
		t.Fatalf("%+v", rep)
	}
	bad := mustDoc(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bogus":{"k":"v"}}}]}`)
	if _, err := Verify(cat, p, []*policy.Document{bad}, nil, Options{}); err == nil {
		t.Fatal("uncompilable generated policy must error")
	}
}

func TestUniverse(t *testing.T) {
	if got := instantiate("arn:aws:s3:::home/${aws:username}/*"); len(got) != 3 || !strings.Contains(got[0], "lpvar") {
		t.Fatalf("instantiate %v", got)
	}
	if instantiate("*") != nil || len(instantiate("arn:aws:s3:::b")) != 1 {
		t.Fatal("instantiate trivial")
	}
	if instantiate("arn:aws:s3:::b/${broken")[0] != "arn:aws:s3:::b/${broken" {
		t.Fatal("unterminated variable")
	}
	p := principal(t, "", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`)
	acts := actionUniverse(cat, p, nil, nil)
	if len(acts) != len(cat.Actions()) {
		t.Fatalf("NotAction must widen the universe to all actions, got %d", len(acts))
	}
	p2 := principal(t, "", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}`)
	acts = actionUniverse(cat, p2, nil, []activity.Observation{obs("custom:Thing", "*")})
	joined := strings.Join(acts, ",")
	if !strings.Contains(joined, "sqs:PurgeQueue") || !strings.Contains(joined, "custom:Thing") || strings.Contains(joined, "s3:GetObject") {
		t.Fatalf("universe %v", acts)
	}
	if ctxSig(map[string][]string{"aws:currenttime": {"x"}, "a": {"1"}}) != "a=1;" {
		t.Fatal("ctxSig")
	}
}
