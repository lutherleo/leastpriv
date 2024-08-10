package activity

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lutherleo/leastpriv/internal/authz"
	"github.com/lutherleo/leastpriv/internal/catalog"
)

const logFile = `{"Records":[
{"eventVersion":"1.09","eventTime":"2026-07-02T00:00:00Z","eventSource":"sqs.amazonaws.com","eventName":"SendMessage","awsRegion":"us-east-1","recipientAccountId":"1",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/app/s","accountId":"1"},"requestParameters":{"queueUrl":"https://sqs.us-east-1.amazonaws.com/1/q"},"tlsDetails":{}},
{"eventVersion":"1.09","eventTime":"2026-07-01T00:00:00Z","eventSource":"sqs.amazonaws.com","eventName":"PurgeQueue","awsRegion":"us-east-1","errorCode":"AccessDenied",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/app/s","accountId":"1"},"requestParameters":{"queueUrl":"https://sqs.us-east-1.amazonaws.com/1/q"}},
{"eventVersion":"1.09","eventTime":"2026-07-03T00:00:00Z","eventSource":"rds.amazonaws.com","eventName":"DescribeDBInstances","awsRegion":"us-east-1",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/app/s","accountId":"1"}},
{"eventVersion":"1.09","eventTime":"2026-07-03T00:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetBucketWebsite","awsRegion":"us-east-1",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/app/s","accountId":"1"}},
{"eventVersion":"1.09","eventTime":"2026-07-03T00:00:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"us-east-1",
 "userIdentity":{"type":"AWSService","invokedBy":"lambda.amazonaws.com"}},
{"eventVersion":"1.09","eventTime":"2026-07-03T00:00:00Z","eventSource":"sqs.amazonaws.com","eventName":"SendMessage","awsRegion":"us-east-1",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/other/s","accountId":"1"}},
{"eventVersion":"1.09","eventTime":"2026-07-03T00:00:00Z","eventSource":"sqs.amazonaws.com","eventName":"SendMessage","awsRegion":"us-east-1",
 "userIdentity":{"type":"Root","arn":"arn:aws:iam::1:root","accountId":"1"}},
{"eventVersion":"1.09","eventTime":"2026-07-03T00:00:00Z","eventSource":"sqs.amazonaws.com","eventName":"SendMessage","awsRegion":"us-east-1",
 "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:group/odd","accountId":"1"}},
{"eventVersion":"1.09","eventTime":"2026-09-01T00:00:00Z","eventSource":"sqs.amazonaws.com","eventName":"SendMessage","awsRegion":"us-east-1",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/app/s","accountId":"1"}}
]}`

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(logFile), 0o600); err != nil {
		t.Fatal(err)
	}
	cat := catalog.Default()
	ds, err := Load(dir, cat, Options{To: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	s := ds.Stats
	if s.Records != 9 || s.DeniedAttempts != 1 || s.NonPrincipalRecords != 2 || s.OutOfScopeRecords != 1 || s.UnknownServices["rds.amazonaws.com"] != 1 || s.UncataloguedEvents["s3:GetBucketWebsite"] != 1 {
		t.Fatalf("stats %+v", s)
	}
	keys := ds.Principals()
	if len(keys) != 3 || keys[0] != "1/role/app" {
		t.Fatalf("principals %v", keys)
	}
	app := ds.ByPrincipal["1/role/app"]
	if len(app) != 3 || !app[0].Time.Before(app[1].Time) || !app[0].Denied {
		t.Fatalf("app observations not sorted/flagged: %+v", app)
	}
	if got := Successful(app); len(got) != 2 {
		t.Fatalf("successful %d", len(got))
	}
	req := app[1].Request()
	if req.Unknown("aws:securetransport") || !req.Unknown("aws:resourcetag/x") || req.Unknown("aws:sourceip") {
		t.Fatal("unknown-key predicate")
	}
	o := Observation{}
	o.WithTLSKnown(true)
	if o.Request().Unknown("aws:securetransport") {
		t.Fatal("WithTLSKnown")
	}
	inv, err := authz.Parse([]byte(`{"principals":[{"arn":"arn:aws:iam::1:role/x/app","policies":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	ds, err = Load(dir, cat, Options{Inventory: inv, From: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Principals()) != 1 || ds.Stats.OutOfScopeRecords != 3 {
		t.Fatalf("inventory filter: %v %+v", ds.Principals(), ds.Stats)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"Records":[{"eventTime":"bad"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, cat, Options{}); err == nil {
		t.Fatal("bad eventTime must error")
	}
}
