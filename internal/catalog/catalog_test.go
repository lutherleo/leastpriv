package catalog

import (
	"strings"
	"testing"
)

func TestDefaultCatalog(t *testing.T) {
	c := Default()
	if len(c.Services) < 10 || len(c.Actions()) < 150 {
		t.Fatalf("catalog too small: %d services %d actions", len(c.Services), len(c.Actions()))
	}
	a, ok := c.Lookup("S3:getobject")
	if !ok || a.FullName() != "s3:GetObject" || a.Access != AccessRead || !a.DataEvent || !a.HasResources() || a.Service() != "s3" {
		t.Fatalf("lookup: %+v", a)
	}
	if _, ok := c.Lookup("s3:Nope"); ok {
		t.Fatal("unexpected action")
	}
	pr, _ := c.Lookup("iam:PassRole")
	if !pr.NotLogged {
		t.Fatal("PassRole must be marked not logged")
	}
	gci, _ := c.Lookup("sts:GetCallerIdentity")
	if !gci.NoAuth || gci.HasResources() {
		t.Fatal("GetCallerIdentity flags")
	}
	for _, a := range c.Actions() {
		switch a.Access {
		case AccessList, AccessRead, AccessWrite, AccessPermissions, AccessTagging:
		default:
			t.Errorf("%s has unknown access level %q", a.FullName(), a.Access)
		}
	}
	if s, ok := c.ServiceByPrefix("S3"); !ok || s.EventSource != "s3.amazonaws.com" {
		t.Fatal("service by prefix")
	}
	if _, ok := c.ServiceBySource("nope.amazonaws.com"); ok {
		t.Fatal("unexpected service")
	}
}

func TestEventMappings(t *testing.T) {
	c := Default()
	cases := map[string][]string{
		"s3.amazonaws.com/HeadObject":                 {"s3:GetObject"},
		"s3.amazonaws.com/CopyObject":                 {"s3:PutObject", "s3:GetObject"},
		"s3.amazonaws.com/ListBuckets":                {"s3:ListAllMyBuckets"},
		"lambda.amazonaws.com/GetFunction20150331v2":  {"lambda:GetFunction"},
		"lambda.amazonaws.com/Invoke":                 {"lambda:InvokeFunction"},
		"lambda.amazonaws.com/CreateFunction20150331": {"lambda:CreateFunction"},
		"kms.amazonaws.com/ReEncrypt":                 {"kms:ReEncryptFrom", "kms:ReEncryptTo"},
		"sqs.amazonaws.com/SendMessageBatch":          {"sqs:SendMessage"},
		"s3.amazonaws.com/GetObjectVersion":           nil,
		"other.amazonaws.com/Anything":                nil,
	}
	for k, want := range cases {
		src, name, _ := strings.Cut(k, "/")
		var got []string
		for _, m := range c.EventMappings(src, name) {
			got = append(got, m.Action.FullName())
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %v want %v", k, got, want)
		}
	}
	s, _ := c.ServiceByPrefix("s3")
	if s.NormalizeEventName("GetObject20150331") != "GetObject20150331" {
		t.Fatal("s3 must not strip suffixes")
	}
}

func TestResourceTypes(t *testing.T) {
	c := Default()
	obj := c.TypeOf("s3", "arn:aws:s3:::bucket/a/b.txt")
	if obj == nil || obj.Name != "object" || obj.Service() != "s3" {
		t.Fatalf("object type: %+v", obj)
	}
	if span := obj.VariableSpan("arn:aws:s3:::bucket/a/b.txt"); span != len("arn:aws:s3:::bucket/") {
		t.Fatalf("span %d", span)
	}
	if b := c.TypeOf("s3", "arn:aws:s3:::bucket"); b == nil || b.Name != "bucket" {
		t.Fatal("bucket type")
	}
	idx := c.TypeOf("dynamodb", "arn:aws:dynamodb:us-east-1:1:table/orders/index/by-day")
	if idx == nil || idx.Name != "index" || idx.NamedPlaceholders() != 2 {
		t.Fatalf("index type %+v", idx)
	}
	q := c.TypeOf("sqs", "arn:aws:sqs:us-east-1:1:jobs")
	if q == nil || q.NamedPlaceholders() != 1 {
		t.Fatal("queue type")
	}
	if c.TypeOf("nope", "x") != nil || c.TypeOf("s3", "arn:aws:sqs:us-east-1:1:jobs") != nil {
		t.Fatal("unexpected type")
	}
	if obj.VariableSpan("arn:aws:sqs:us-east-1:1:jobs") != -1 {
		t.Fatal("span on foreign ARN")
	}
	if got := obj.Template("aws", "us-east-1", "1"); got != "arn:aws:s3:::*/*" {
		t.Fatalf("template %s", got)
	}
	tbl, _ := c.ResourceType("dynamodb", "table")
	if tbl.Template("aws", "eu-west-1", "123") != "arn:aws:dynamodb:eu-west-1:123:table/*" {
		t.Fatal("table template")
	}
	if _, ok := c.ResourceType("dynamodb", "nope"); ok {
		t.Fatal("unexpected resource type")
	}
}

func TestExpandAndVerb(t *testing.T) {
	c := Default()
	got := c.Expand("sqs:Get*")
	if len(got) != 2 || got[0].FullName() != "sqs:GetQueueAttributes" {
		t.Fatalf("expand: %v", got)
	}
	if len(c.Expand("nosuch:*")) != 0 {
		t.Fatal("expand unknown")
	}
	for in, want := range map[string]string{"GetObject": "Get", "List": "List", "DescribeDBInstances": "Describe", "X": "X"} {
		if Verb(in) != want {
			t.Errorf("Verb(%s)=%s", in, Verb(in))
		}
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`{`,
		`{"schemaVersion":2,"services":[]}`,
		`{"schemaVersion":1,"services":[{"prefix":"","eventSource":"x"}]}`,
		`{"schemaVersion":1,"services":[{"prefix":"x","eventSource":"x","resourceTypes":[{"name":"r","arn":"arn:aws:x:::fixed"}]}]}`,
		`{"schemaVersion":1,"services":[{"prefix":"x","eventSource":"x","actions":[{"name":"A","resources":["missing"]}]}]}`,
		`{"schemaVersion":1,"services":[{"prefix":"x","eventSource":"x","actions":[{"name":"A"},{"name":"a"}]}]}`,
		`{"schemaVersion":1,"services":[{"prefix":"x","eventSource":"x","actions":[{"name":"A"}],"extraEvents":[{"event":"E","action":"B"}]}]}`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("expected error for %s", b)
		}
	}
}
