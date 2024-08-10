package engine

import (
	"strings"
	"testing"

	"github.com/lutherleo/leastpriv/internal/policy"
)

func mustDoc(t testing.TB, js string) *policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(js))
	if err != nil {
		t.Fatalf("parse %s: %v", js, err)
	}
	return d
}

func set(t testing.TB, boundary string, identity ...string) *Set {
	t.Helper()
	s := &Set{}
	for i, js := range identity {
		p, err := Compile("p"+string(rune('0'+i)), mustDoc(t, js))
		if err != nil {
			t.Fatal(err)
		}
		s.Identity = append(s.Identity, p)
	}
	if boundary != "" {
		p, err := Compile("boundary", mustDoc(t, boundary))
		if err != nil {
			t.Fatal(err)
		}
		s.Boundary = p
	}
	return s
}

func stmt(body string) string {
	return `{"Version":"2012-10-17","Statement":[` + body + `]}`
}

type evalCase struct {
	name     string
	doc      string // AWS documentation section the case mirrors
	identity []string
	boundary string
	action   string
	resource string
	ctx      map[string][]string
	want     Decision
}

// TestEvaluationLogic mirrors the IAM User Guide sections "Policy evaluation
// logic", "Determining whether a request is allowed or denied within an
// account", "IAM JSON policy elements: NotAction / NotResource" and
// "Condition operators". Each case names the section it reproduces.
func TestEvaluationLogic(t *testing.T) {
	const (
		bucketObj = "arn:aws:s3:::reports/2026/q3.csv"
		table     = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
	)
	allowGet := stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}`)
	cases := []evalCase{
		{name: "default implicit deny", doc: "Policy evaluation logic: by default all requests are implicitly denied",
			identity: nil, action: "s3:GetObject", resource: bucketObj, want: ImplicitDeny},
		{name: "matching allow", doc: "Identity-based policies: an Allow permits the request",
			identity: []string{allowGet}, action: "s3:GetObject", resource: bucketObj, want: Allow},
		{name: "action not listed", doc: "Implicit deny when no statement matches the action",
			identity: []string{allowGet}, action: "s3:PutObject", resource: bucketObj, want: ImplicitDeny},
		{name: "resource not matched", doc: "Implicit deny when no statement matches the resource",
			identity: []string{allowGet}, action: "s3:GetObject", resource: "arn:aws:s3:::private/x", want: ImplicitDeny},
		{name: "explicit deny overrides allow in same policy", doc: "An explicit deny in any policy overrides any allow",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/2026/*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: ExplicitDeny},
		{name: "explicit deny overrides allow across policies", doc: "Explicit deny across multiple identity policies",
			identity: []string{allowGet, stmt(`{"Effect":"Deny","Action":"*","Resource":"*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: ExplicitDeny},
		{name: "allows union across policies", doc: "Permissions from multiple identity policies are combined",
			identity: []string{allowGet, stmt(`{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"` + table + `"}`)},
			action:   "dynamodb:GetItem", resource: table, want: Allow},
		{name: "action match is case-insensitive", doc: "Action element: action names are case-insensitive",
			identity: []string{stmt(`{"Effect":"Allow","Action":"S3:getobject","Resource":"*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: Allow},
		{name: "resource match is case-sensitive", doc: "Resource element: ARNs are case-sensitive",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::Reports/*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: ImplicitDeny},
		{name: "action wildcard", doc: "Action element: wildcards * and ?",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}`)},
			action:   "s3:GetObjectTagging", resource: bucketObj, want: Allow},
		{name: "action single char wildcard", doc: "Action element: ? matches one character",
			identity: []string{stmt(`{"Effect":"Allow","Action":"sqs:?eceiveMessage","Resource":"*"}`)},
			action:   "sqs:ReceiveMessage", resource: "arn:aws:sqs:us-east-1:111122223333:jobs", want: Allow},
		{name: "full wildcard action", doc: "Action \"*\" matches every action",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*"}`)},
			action:   "iam:CreateUser", resource: "arn:aws:iam::111122223333:user/x", want: Allow},
		{name: "resource-less action needs Resource *", doc: "Actions without resource-level permissions require \"Resource\": \"*\"",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"arn:aws:s3:::*"}`)},
			action:   "s3:ListAllMyBuckets", resource: "*", want: ImplicitDeny},
		{name: "NotAction allow grants everything else", doc: "NotAction with Allow: allows all actions except those listed",
			identity: []string{stmt(`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: Allow},
		{name: "NotAction allow excludes listed", doc: "NotAction with Allow does not allow the listed actions",
			identity: []string{stmt(`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`)},
			action:   "iam:CreateUser", resource: "arn:aws:iam::111122223333:user/x", want: ImplicitDeny},
		{name: "NotAction deny denies everything else", doc: "NotAction with Deny: denies all actions except those listed",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","NotAction":["iam:Get*","iam:List*"],"Resource":"*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: ExplicitDeny},
		{name: "NotAction deny leaves listed actions allowed", doc: "NotAction with Deny: listed actions are not denied by that statement",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","NotAction":["iam:Get*","iam:List*"],"Resource":"*"}`)},
			action:   "iam:GetRole", resource: "arn:aws:iam::111122223333:role/x", want: Allow},
		{name: "NotResource allow", doc: "NotResource with Allow: everything except listed resources",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::secret/*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: Allow},
		{name: "NotResource allow excludes listed", doc: "NotResource with Allow does not apply to the listed resources",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::secret/*"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::secret/k", want: ImplicitDeny},
		{name: "NotResource deny", doc: "NotResource with Deny: deny everything except listed resources",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*"},{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::reports","arn:aws:s3:::reports/*"]}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::other/k", want: ExplicitDeny},
		{name: "boundary intersection allows", doc: "Permissions boundaries: effective permissions are the intersection",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)},
			boundary: stmt(`{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}`),
			action:   "s3:GetObject", resource: bucketObj, want: Allow},
		{name: "boundary blocks identity allow", doc: "Permissions boundaries: identity allow outside the boundary is implicitly denied",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)},
			boundary: stmt(`{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}`),
			action:   "s3:PutObject", resource: bucketObj, want: ImplicitDeny},
		{name: "boundary alone grants nothing", doc: "Permissions boundaries do not grant permissions on their own",
			identity: nil,
			boundary: stmt(`{"Effect":"Allow","Action":"*","Resource":"*"}`),
			action:   "s3:GetObject", resource: bucketObj, want: ImplicitDeny},
		{name: "boundary explicit deny", doc: "An explicit deny in a permissions boundary overrides identity allows",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)},
			boundary: stmt(`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}`),
			action:   "s3:GetObject", resource: bucketObj, want: ExplicitDeny},
		{name: "condition StringEquals satisfied", doc: "Condition operators: StringEquals",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:requestedregion": {"us-east-1"}}, want: Allow},
		{name: "condition StringEquals fails", doc: "Condition operators: StringEquals",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:requestedregion": {"eu-west-1"}}, want: ImplicitDeny},
		{name: "condition values are ORed", doc: "Creating a condition with multiple keys or values: values for one key are ORed",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":["us-east-1","eu-west-1"]}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:requestedregion": {"eu-west-1"}}, want: Allow},
		{name: "condition keys are ANDed", doc: "Creating a condition with multiple keys or values: keys are ANDed",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"},"Bool":{"aws:SecureTransport":"true"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:requestedregion": {"us-east-1"}, "aws:securetransport": {"false"}}, want: ImplicitDeny},
		{name: "condition key names are case-insensitive", doc: "Condition element: key names are not case-sensitive",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"AWS:REQUESTEDREGION":"us-east-1"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:requestedregion": {"us-east-1"}}, want: Allow},
		{name: "missing key fails positive operator", doc: "Condition operators: a missing key does not match",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"data"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, want: ImplicitDeny},
		{name: "missing key satisfies negated operator", doc: "Negated matching condition operators return true when the key is missing",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"contractors"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, want: Allow},
		{name: "IfExists with missing key", doc: "...IfExists condition operators: true when the key is missing",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEqualsIfExists":{"aws:PrincipalTag/team":"data"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, want: Allow},
		{name: "IfExists with present key", doc: "...IfExists condition operators: evaluated normally when present",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEqualsIfExists":{"aws:PrincipalTag/team":"data"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:principaltag/team": {"web"}}, want: ImplicitDeny},
		{name: "Null true with missing key", doc: "Condition operator to check existence of condition keys (Null)",
			identity: []string{stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Null":{"aws:MultiFactorAuthAge":"true"}}},{"Effect":"Allow","Action":"*","Resource":"*"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: ExplicitDeny},
		{name: "Null true with present key", doc: "Condition operator to check existence of condition keys (Null)",
			identity: []string{stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Null":{"aws:MultiFactorAuthAge":"true"}}},{"Effect":"Allow","Action":"*","Resource":"*"}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:multifactorauthage": {"30"}}, want: Allow},
		{name: "Bool MFA deny pattern", doc: "Bool condition operators (aws:MultiFactorAuthPresent)",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}`)},
			action:   "iam:CreateUser", resource: "arn:aws:iam::111122223333:user/x", ctx: map[string][]string{"aws:multifactorauthpresent": {"false"}}, want: ExplicitDeny},
		{name: "Bool is case-insensitive", doc: "Bool condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"TRUE"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:securetransport": {"true"}}, want: Allow},
		{name: "StringLike wildcard", doc: "String condition operators: StringLike",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"StringLike":{"s3:prefix":["home/","home/team-*"]}}}`)},
			action:   "s3:ListBucket", resource: "arn:aws:s3:::reports", ctx: map[string][]string{"s3:prefix": {"home/team-a"}}, want: Allow},
		{name: "StringEqualsIgnoreCase", doc: "String condition operators: StringEqualsIgnoreCase",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEqualsIgnoreCase":{"aws:PrincipalTag/env":"PROD"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:principaltag/env": {"prod"}}, want: Allow},
		{name: "StringNotLike excludes", doc: "String condition operators: StringNotLike",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringNotLike":{"aws:UserAgent":"*Boto*"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:useragent": {"Boto3/1.35"}}, want: ImplicitDeny},
		{name: "StringNotEquals multiple values is NOR", doc: "Negated operators with multiple values: not equal to any",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:requestedregion": {"us-west-2"}}, want: ImplicitDeny},
		{name: "NumericLessThan", doc: "Numeric condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:multifactorauthage": {"120"}}, want: Allow},
		{name: "NumericGreaterThanEquals fails", doc: "Numeric condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericGreaterThanEquals":{"s3:max-keys":10}}}`)},
			action:   "s3:ListBucket", resource: "arn:aws:s3:::reports", ctx: map[string][]string{"s3:max-keys": {"5"}}, want: ImplicitDeny},
		{name: "non-numeric request value never matches", doc: "Numeric condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"s3:max-keys":"10"}}}`)},
			action:   "s3:ListBucket", resource: "arn:aws:s3:::reports", ctx: map[string][]string{"s3:max-keys": {"ten"}}, want: ImplicitDeny},
		{name: "DateLessThan", doc: "Date condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2026-12-31T23:59:59Z"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:currenttime": {"2026-10-24T10:00:00Z"}}, want: Allow},
		{name: "DateGreaterThan epoch", doc: "Date condition operators accept epoch seconds",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"DateGreaterThan":{"aws:EpochTime":"1798761600"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:epochtime": {"1792780800"}}, want: ImplicitDeny},
		{name: "IpAddress CIDR", doc: "IP address condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":["203.0.113.0/24","2001:db8::/32"]}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:sourceip": {"203.0.113.77"}}, want: Allow},
		{name: "IpAddress IPv6", doc: "IP address condition operators (IPv6)",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":["2001:db8::/32"]}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:sourceip": {"2001:db8::1"}}, want: Allow},
		{name: "NotIpAddress deny", doc: "IP address condition operators: deny outside corporate range",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"198.51.100.0/24"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:sourceip": {"203.0.113.9"}}, want: ExplicitDeny},
		{name: "ArnLike", doc: "Amazon Resource Name (ARN) condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:111122223333:alerts-*"}}}`)},
			action:   "sqs:SendMessage", resource: "arn:aws:sqs:us-east-1:111122223333:q", ctx: map[string][]string{"aws:sourcearn": {"arn:aws:sns:us-east-1:111122223333:alerts-prod"}}, want: Allow},
		{name: "ArnNotEquals", doc: "Amazon Resource Name (ARN) condition operators",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"ArnNotEquals":{"aws:PrincipalArn":"arn:aws:iam::111122223333:role/blocked"}}}`)},
			action:   "s3:GetObject", resource: bucketObj, ctx: map[string][]string{"aws:principalarn": {"arn:aws:iam::111122223333:role/blocked"}}, want: ImplicitDeny},
		{name: "ForAllValues all match", doc: "Multivalued context keys: ForAllValues",
			identity: []string{stmt(`{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*","Condition":{"ForAllValues:StringEquals":{"dynamodb:Attributes":["id","status"]}}}`)},
			action:   "dynamodb:GetItem", resource: table, ctx: map[string][]string{"dynamodb:attributes": {"id", "status"}}, want: Allow},
		{name: "ForAllValues one outside", doc: "Multivalued context keys: ForAllValues",
			identity: []string{stmt(`{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*","Condition":{"ForAllValues:StringEquals":{"dynamodb:Attributes":["id","status"]}}}`)},
			action:   "dynamodb:GetItem", resource: table, ctx: map[string][]string{"dynamodb:attributes": {"id", "ssn"}}, want: ImplicitDeny},
		{name: "ForAllValues missing key is true", doc: "Multivalued context keys: ForAllValues returns true for a missing key",
			identity: []string{stmt(`{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*","Condition":{"ForAllValues:StringEquals":{"dynamodb:Attributes":["id"]}}}`)},
			action:   "dynamodb:GetItem", resource: table, want: Allow},
		{name: "ForAnyValue match", doc: "Multivalued context keys: ForAnyValue",
			identity: []string{stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["owner"]}}},{"Effect":"Allow","Action":"*","Resource":"*"}`)},
			action:   "ec2:CreateTags", resource: "arn:aws:ec2:us-east-1:111122223333:instance/i-1", ctx: map[string][]string{"aws:tagkeys": {"env", "owner"}}, want: ExplicitDeny},
		{name: "ForAnyValue missing key is false", doc: "Multivalued context keys: ForAnyValue returns false for a missing key",
			identity: []string{stmt(`{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["owner"]}}},{"Effect":"Allow","Action":"*","Resource":"*"}`)},
			action:   "ec2:CreateTags", resource: "arn:aws:ec2:us-east-1:111122223333:instance/i-1", want: Allow},
		{name: "ForAllValues negated", doc: "Multivalued context keys: ForAllValues with a negated operator",
			identity: []string{stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"ForAllValues:StringNotLike":{"aws:TagKeys":["aws:*"]}}}`)},
			action:   "ec2:CreateTags", resource: "arn:aws:ec2:us-east-1:111122223333:instance/i-1", ctx: map[string][]string{"aws:tagkeys": {"env", "aws:cloudformation"}}, want: ImplicitDeny},
		{name: "policy variable in resource", doc: "IAM policy elements: Variables and tags (aws:username)",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username}/*"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::home/alice/notes.txt", ctx: map[string][]string{"aws:username": {"alice"}}, want: Allow},
		{name: "policy variable mismatch", doc: "IAM policy elements: Variables and tags",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username}/*"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::home/bob/notes.txt", ctx: map[string][]string{"aws:username": {"alice"}}, want: ImplicitDeny},
		{name: "policy variable missing key", doc: "Variables: a missing key makes the element not match",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username}/*"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::home/alice/x", want: ImplicitDeny},
		{name: "policy variable default value", doc: "Variables: specifying default values",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username, 'shared'}/*"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::home/shared/x", want: Allow},
		{name: "policy variable value is literal", doc: "Variables: substituted values never act as wildcards",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username}/*"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::home/anyone/x", ctx: map[string][]string{"aws:username": {"*"}}, want: ImplicitDeny},
		{name: "special variable ${*}", doc: "Variables: special characters ${*}",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::lit/${*}"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::lit/*", want: Allow},
		{name: "special variable ${*} is not a wildcard", doc: "Variables: special characters ${*}",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::lit/${*}"}`)},
			action:   "s3:GetObject", resource: "arn:aws:s3:::lit/abc", want: ImplicitDeny},
		{name: "variables are literal in 2008 version", doc: "Version element: 2008-10-17 does not support policy variables",
			identity: []string{`{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username}/*"}]}`},
			action:   "s3:GetObject", resource: "arn:aws:s3:::home/alice/x", ctx: map[string][]string{"aws:username": {"alice"}}, want: ImplicitDeny},
		{name: "variable in condition value", doc: "Variables in Condition element",
			identity: []string{stmt(`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"StringLike":{"s3:prefix":"home/${aws:username}/*"}}}`)},
			action:   "s3:ListBucket", resource: "arn:aws:s3:::reports", ctx: map[string][]string{"aws:username": {"alice"}, "s3:prefix": {"home/alice/docs"}}, want: Allow},
		{name: "deny wins even when allow is more specific", doc: "There is no specificity ordering: deny always wins",
			identity: []string{stmt(`{"Effect":"Deny","Action":"s3:*","Resource":"*"},{"Effect":"Allow","Action":"s3:GetObject","Resource":"` + bucketObj + `"}`)},
			action:   "s3:GetObject", resource: bucketObj, want: ExplicitDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := set(t, c.boundary, c.identity...)
			req := NewRequest(c.action, c.resource)
			for k, v := range c.ctx {
				req.Set(k, v...)
			}
			got := s.Evaluate(req)
			if got.Decision != c.want {
				t.Fatalf("[%s] decision=%s want %s (%s)", c.doc, got.Decision, c.want, got.Reason)
			}
			if got.Uncertain {
				t.Fatalf("authoritative context must not produce uncertain results")
			}
		})
	}
}

func TestUnknownContext(t *testing.T) {
	s := set(t, "", stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}`))
	req := NewRequest("s3:GetObject", "arn:aws:s3:::b/k")
	req.Unknown = AllUnknown
	res := s.Evaluate(req)
	if res.Decision != Allow || !res.Uncertain || len(res.UnknownKeys) != 1 || res.UnknownKeys[0] != "aws:resourcetag/env" {
		t.Fatalf("unexpected %+v", res)
	}
	// An unknown deny condition leaves the allow uncertain.
	s2 := set(t, "", stmt(`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"aws:ViaAWSService":"true"}}}`))
	res = s2.Evaluate(req)
	if res.Decision != Allow || !res.Uncertain {
		t.Fatalf("want uncertain allow, got %+v", res)
	}
	// Unknown variables still let fixed text rule a resource out.
	s3 := set(t, "", stmt(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::home/${aws:username}/*"}`))
	if s3.Evaluate(Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::other/x", Unknown: AllUnknown}).Allowed() {
		t.Fatal("fixed prefix mismatch must not be allowed")
	}
	r := s3.Evaluate(Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::home/u/x", Unknown: AllUnknown})
	if !r.Allowed() || !r.Uncertain {
		t.Fatalf("want uncertain allow, got %+v", r)
	}
	if got := s3.Identity[0].ReferencedKeys(); len(got) != 1 || got[0] != "aws:username" {
		t.Fatalf("ReferencedKeys=%v", got)
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []string{
		stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEqualsFoo":{"k":"v"}}}`),
		stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"k":"abc"}}}`),
		stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"DateEquals":{"k":"yesterday"}}}`),
		stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"IpAddress":{"k":"300.1.1.1"}}}`),
		stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"k":"maybe"}}}`),
		stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NullIfExists":{"k":"true"}}}`),
		stmt(`{"Effect":"Permit","Action":"*","Resource":"*"}`),
		stmt(`{"Effect":"Allow","Resource":"*"}`),
		stmt(`{"Effect":"Allow","Action":"*"}`),
		stmt(`{"Effect":"Allow","Action":"*","NotAction":"s3:*","Resource":"*"}`),
	}
	for _, js := range bad {
		if _, err := Compile("bad", mustDoc(t, js)); err == nil {
			t.Errorf("expected compile error for %s", js)
		}
	}
	if !KnownOperator("ForAnyValue:StringLikeIfExists") || KnownOperator("BinaryEquals") {
		t.Fatal("KnownOperator")
	}
}

func TestResultDetails(t *testing.T) {
	s := set(t, "", stmt(`{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"},{"Sid":"D","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}`))
	res := s.Evaluate(NewRequest("s3:DeleteBucket", "arn:aws:s3:::b"))
	if res.Decision != ExplicitDeny || len(res.Matched) != 2 {
		t.Fatalf("%+v", res)
	}
	SortRefs(res.Matched)
	if res.Matched[0].Sid != "A" || res.Matched[1].Sid != "D" {
		t.Fatalf("refs %+v", res.Matched)
	}
	if !strings.Contains(res.Reason, "explicit Deny") || res.Decision.String() != "explicitDeny" {
		t.Fatal(res.Reason)
	}
	b, _ := Allow.MarshalText()
	if string(b) != "allowed" || ImplicitDeny.String() != "implicitDeny" {
		t.Fatal("decision text")
	}
	if s.Identity[0].MatchStatement(0, NewRequest("s3:GetObject", "*")) != Yes {
		t.Fatal("MatchStatement")
	}
	if Maybe.String() != "maybe" || Yes.String() != "yes" || No.String() != "no" {
		t.Fatal("tri strings")
	}
	issues := Validate(mustDoc(t, stmt(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"BinaryEquals":{"k":"QUJD"}}}`)))
	found := false
	for _, i := range issues {
		if i.Code == "bad-condition-operator" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected operator issue, got %v", issues)
	}
}

func BenchmarkEvaluate(b *testing.B) {
	s := set(b, "", stmt(`{"Effect":"Allow","Action":["s3:Get*","s3:List*","dynamodb:Query","dynamodb:GetItem"],"Resource":["arn:aws:s3:::acme-*/*","arn:aws:dynamodb:*:*:table/orders*"]},`+
		`{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}},`+
		`{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}`))
	req := NewRequest("s3:GetObject", "arn:aws:s3:::acme-app-data/uploads/2026/10/24/x.json")
	req.Set("aws:RequestedRegion", "us-east-1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Evaluate(req)
	}
}
