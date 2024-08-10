package diff

import (
	"strings"
	"testing"

	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/policy"
)

var cat = catalog.Default()

func docs(t *testing.T, js ...string) []*policy.Document {
	t.Helper()
	var out []*policy.Document
	for _, j := range js {
		d, err := policy.Parse([]byte(j))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func find(r *Result, action string) *ActionChange {
	for i := range r.Actions {
		if r.Actions[i].Action == action {
			return &r.Actions[i]
		}
	}
	return nil
}

func TestCompare(t *testing.T) {
	before := docs(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["s3:*","sqs:SendMessage","custom:Op"],"Resource":"*"},
		{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:us-east-1:1:table/a"},
		{"Effect":"Allow","Action":"kms:Decrypt","NotResource":"arn:aws:kms:us-east-1:1:key/x"},
		{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}`)
	after := docs(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::b/*"},
		{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
		{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:us-east-1:1:table/*"},
		{"Effect":"Allow","Action":"dynamodb:PutItem","Resource":"*"},
		{"Effect":"Allow","Action":"kms:Decrypt","NotResource":"arn:aws:kms:us-east-1:1:key/x"},
		{"Effect":"Allow","Action":"lambda:GetFunction","Resource":"arn:aws:lambda:us-east-1:1:function:a"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:GetFunction","Resource":"arn:aws:lambda:us-east-1:1:function:b"}]}`)
	r, err := Compare(cat, before, after)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]Change{
		"s3:GetObject":       Narrowed,
		"s3:PutObject":       Removed,
		"sqs:SendMessage":    Narrowed,
		"dynamodb:GetItem":   Widened,
		"dynamodb:PutItem":   Added,
		"custom:Op":          Removed,
		"lambda:GetFunction": Added,
	}
	for a, want := range checks {
		c := find(r, a)
		if c == nil || c.Change != want {
			t.Errorf("%s: got %+v want %s", a, c, want)
		}
	}
	if find(r, "kms:Decrypt") != nil || r.Counts[Unchanged] != 1 {
		t.Fatalf("unchanged kms grant must be counted, not listed: %v", r.Counts)
	}
	if find(r, "s3:DeleteBucket") != nil {
		t.Fatal("denied before and absent after is unchanged-empty")
	}
	if r.StatementsBefore != 4 || r.StatementsAfter != 7 || r.SizeBefore == 0 {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Unified, "--- before\n+++ after\n@@ -1,") || !strings.Contains(r.Unified, "+// document 2") || !strings.Contains(r.Unified, "-        \"s3:*\",") {
		t.Fatalf("unified diff:\n%s", r.Unified)
	}
	SortChanges(r.Actions)
	if r.Actions[0].Change != Added {
		t.Fatalf("sort order %v", r.Actions[0])
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		b, a []string
		want Change
	}{
		{nil, nil, Unchanged},
		{[]string{"*"}, []string{"*"}, Unchanged},
		{[]string{"arn:aws:s3:::b/*"}, []string{"arn:aws:s3:::c/*"}, Changed},
		{[]string{"NOT(x)"}, []string{"NOT(y)"}, Changed},
		{[]string{"NOT(x)"}, []string{"NOT(x) if {}"}, Narrowed},
		{[]string{"* if {\"a\":1}"}, []string{"*"}, Widened},
	}
	for _, c := range cases {
		if got := classify(c.b, c.a); got != c.want {
			t.Errorf("classify(%v,%v)=%s want %s", c.b, c.a, got, c.want)
		}
	}
}

func TestUnifiedEdgeCases(t *testing.T) {
	a := docs(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	same, err := Unified(a, a, 3)
	if err != nil || same != "" {
		t.Fatalf("identical inputs: %q %v", same, err)
	}
	ops := align(make([]string, 5000), append(make([]string, 4000), "x"))
	if len(ops) == 0 {
		t.Fatal("align")
	}
	big := make([]string, 5000)
	for i := range big {
		big[i] = strings.Repeat("y", i%7)
	}
	ops = align(big, append(append([]string{}, big...), "z"))
	plus := 0
	for _, o := range ops {
		if o.kind == '+' {
			plus++
		}
	}
	if plus != 5001 {
		t.Fatalf("over the LCS budget the diff must fall back to replace-all, got %d additions", plus)
	}
}
