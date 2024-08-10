package arn

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	a, err := Parse("arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/fn:*")
	if err != nil {
		t.Fatal(err)
	}
	if a.Service != "logs" || a.Region != "us-east-1" || a.Account != "111122223333" || a.Resource != "log-group:/aws/lambda/fn:*" {
		t.Fatalf("bad parse %+v", a)
	}
	if a.String() != "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/fn:*" {
		t.Fatal("round trip")
	}
	if _, err := Parse("s3:::bucket"); !errors.Is(err, ErrNotARN) {
		t.Fatalf("want ErrNotARN, got %v", err)
	}
}

func TestPartition(t *testing.T) {
	for region, want := range map[string]string{"us-east-1": "aws", "cn-north-1": "aws-cn", "us-gov-west-1": "aws-us-gov"} {
		if got := PartitionForRegion(region); got != want {
			t.Errorf("%s: %s want %s", region, got, want)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		p, r string
		want bool
	}{
		{"*", "*", true},
		{"*", "arn:aws:s3:::b/k", true},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::b/a/b/c", true},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::bb/a", false},
		{"arn:aws:s3:::b/*", "*", false},
		{"arn:aws:s3:::B/*", "arn:aws:s3:::b/x", false}, // case-sensitive
		{"arn:aws:dynamodb:*:111122223333:table/orders", "arn:aws:dynamodb:eu-west-1:111122223333:table/orders", true},
		// A wildcard in the region segment does not cross colons.
		{"arn:aws:sqs:us-*:1:q", "arn:aws:sqs:us-east-1:1:q", true},
		{"arn:aws:logs:*:*:log-group:app:*", "arn:aws:logs:us-east-1:1:log-group:app:log-stream:s", true},
		{"arn:aws:iam::*:role/app-*", "arn:aws:iam::111122223333:role/app-backend", true},
		{"arn:aws:iam::*:role/app-*", "arn:aws:iam::111122223333:user/app-backend", false},
		{"arn:aws:s3:::b", "not-an-arn", false},
	}
	for _, c := range cases {
		if got := Match(c.p, c.r); got != c.want {
			t.Errorf("Match(%q,%q)=%v want %v", c.p, c.r, got, c.want)
		}
	}
}

func TestSubsumes(t *testing.T) {
	cases := []struct {
		g, s string
		want bool
	}{
		{"*", "arn:aws:s3:::b/*", true},
		{"arn:aws:s3:::*", "arn:aws:s3:::b/x/*", true},
		{"arn:aws:s3:::b/x/*", "arn:aws:s3:::b/*", false},
		{"arn:aws:s3:::b/*", "*", false},
		{"arn:aws:sqs:*:*:*", "arn:aws:sqs:us-east-1:1:orders", true},
		{"arn:aws:sqs:us-east-1:1:orders-*", "arn:aws:sqs:us-east-1:1:orders-dlq", true},
		{"arn:aws:sqs:us-east-1:1:orders-*", "arn:aws:sqs:us-east-1:1:*", false},
		{"bad", "bad", true},
	}
	for _, c := range cases {
		if got := Subsumes(c.g, c.s); got != c.want {
			t.Errorf("Subsumes(%q,%q)=%v want %v", c.g, c.s, got, c.want)
		}
	}
	if !IsPattern("arn:aws:s3:::b/*") || IsPattern("arn:aws:s3:::b/k") {
		t.Fatal("IsPattern")
	}
}
