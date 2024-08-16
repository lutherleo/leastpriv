package mapper

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/lutherleo/leastpriv/internal/catalog"
	"github.com/lutherleo/leastpriv/internal/cloudtrail"
)

func rec(t *testing.T, source, name, params, resources string) *cloudtrail.Record {
	t.Helper()
	if params == "" {
		params = "{}"
	}
	if resources == "" {
		resources = "[]"
	}
	js := `{"eventSource":"` + source + `","eventName":"` + name + `","awsRegion":"us-east-1","recipientAccountId":"111122223333",
		"requestParameters":` + params + `,"resources":` + resources + `}`
	var r cloudtrail.Record
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func render(calls []Call) []string {
	var out []string
	for _, c := range calls {
		s := c.Action + " " + c.Resource + " " + string(c.Confidence)
		if c.NoAuth {
			s += " noauth"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestMap(t *testing.T) {
	m := New(catalog.Default())
	const acct = "111122223333"
	cases := []struct {
		name                     string
		source, event, params, r string
		want                     []string
	}{
		{"s3 object via resources", "s3.amazonaws.com", "GetObject", `{"bucketName":"b","key":"k"}`,
			`[{"type":"AWS::S3::Object","ARN":"arn:aws:s3:::b/k"},{"type":"AWS::S3::Bucket","ARN":"arn:aws:s3:::b"}]`,
			[]string{"s3:GetObject arn:aws:s3:::b/k exact"}},
		{"s3 object via params", "s3.amazonaws.com", "HeadObject", `{"bucketName":"b","key":"a/b c.txt"}`, "",
			[]string{"s3:GetObject arn:aws:s3:::b/a/b c.txt exact"}},
		{"s3 list", "s3.amazonaws.com", "ListObjectsV2", `{"bucketName":"b","prefix":"x/"}`, "",
			[]string{"s3:ListBucket arn:aws:s3:::b exact"}},
		{"s3 copy needs both", "s3.amazonaws.com", "CopyObject", `{"bucketName":"dst","key":"new","x-amz-copy-source":"src/old%20name.txt?versionId=3"}`, "",
			[]string{"s3:GetObject arn:aws:s3:::src/old name.txt exact", "s3:PutObject arn:aws:s3:::dst/new exact"}},
		{"s3 delete objects fans out", "s3.amazonaws.com", "DeleteObjects", `{"bucketName":"b","delete":{"Object":[{"Key":"x"},{"Key":"y"}]}}`, "",
			[]string{"s3:DeleteObject arn:aws:s3:::b/x exact", "s3:DeleteObject arn:aws:s3:::b/y exact"}},
		{"s3 object unresolved key", "s3.amazonaws.com", "DeleteObjects", `{"bucketName":"b"}`, "",
			[]string{"s3:DeleteObject arn:aws:s3:::b/* partial"}},
		{"resource-less", "s3.amazonaws.com", "ListBuckets", "", "",
			[]string{"s3:ListAllMyBuckets * exact"}},
		{"dynamodb query index", "dynamodb.amazonaws.com", "Query", `{"tableName":"orders","indexName":"by-day"}`,
			`[{"type":"AWS::DynamoDB::Table","ARN":"arn:aws:dynamodb:us-east-1:` + acct + `:table/orders"}]`,
			[]string{"dynamodb:Query arn:aws:dynamodb:us-east-1:" + acct + ":table/orders/index/by-day exact"}},
		{"dynamodb query table", "dynamodb.amazonaws.com", "Query", `{"tableName":"orders"}`, "",
			[]string{"dynamodb:Query arn:aws:dynamodb:us-east-1:" + acct + ":table/orders exact"}},
		{"dynamodb batch keys", "dynamodb.amazonaws.com", "BatchGetItem", `{"requestItems":{"b":{},"a":{}}}`, "",
			[]string{"dynamodb:BatchGetItem arn:aws:dynamodb:us-east-1:" + acct + ":table/a exact", "dynamodb:BatchGetItem arn:aws:dynamodb:us-east-1:" + acct + ":table/b exact"}},
		{"dynamodb stream unresolved", "dynamodb.amazonaws.com", "GetRecords", `{"shardIterator":"x"}`, "",
			[]string{"dynamodb:GetRecords arn:aws:dynamodb:us-east-1:" + acct + ":table/*/stream/* partial"}},
		{"sqs queue url", "sqs.amazonaws.com", "DeleteMessageBatch", `{"queueUrl":"https://sqs.us-east-1.amazonaws.com/` + acct + `/jobs/"}`, "",
			[]string{"sqs:DeleteMessage arn:aws:sqs:us-east-1:" + acct + ":jobs exact"}},
		{"sns topic arn", "sns.amazonaws.com", "Publish", `{"topicArn":"arn:aws:sns:us-east-1:` + acct + `:alerts"}`, "",
			[]string{"sns:Publish arn:aws:sns:us-east-1:" + acct + ":alerts exact"}},
		{"kms via resources despite alias", "kms.amazonaws.com", "GenerateDataKey", `{"keyId":"alias/app"}`,
			`[{"type":"AWS::KMS::Key","ARN":"arn:aws:kms:us-east-1:` + acct + `:key/k-1"}]`,
			[]string{"kms:GenerateDataKey arn:aws:kms:us-east-1:" + acct + ":key/k-1 exact"}},
		{"kms key id", "kms.amazonaws.com", "DescribeKey", `{"keyId":"key/k-2"}`, "",
			[]string{"kms:DescribeKey arn:aws:kms:us-east-1:" + acct + ":key/k-2 exact"}},
		{"kms alias only", "kms.amazonaws.com", "DescribeKey", `{"keyId":"alias/app"}`, "",
			[]string{"kms:DescribeKey arn:aws:kms:us-east-1:" + acct + ":key/* partial"}},
		{"kms reencrypt", "kms.amazonaws.com", "ReEncrypt", "",
			`[{"type":"AWS::KMS::Key","ARN":"arn:aws:kms:us-east-1:` + acct + `:key/k-3"}]`,
			[]string{"kms:ReEncryptFrom arn:aws:kms:us-east-1:" + acct + ":key/k-3 exact", "kms:ReEncryptTo arn:aws:kms:us-east-1:" + acct + ":key/k-3 exact"}},
		{"kms create alias", "kms.amazonaws.com", "CreateAlias", `{"aliasName":"alias/new"}`, "",
			[]string{"kms:CreateAlias arn:aws:kms:us-east-1:" + acct + ":alias/new exact"}},
		{"secret by arn", "secretsmanager.amazonaws.com", "GetSecretValue", `{"secretId":"arn:aws:secretsmanager:us-east-1:` + acct + `:secret:db-AbCdEf"}`, "",
			[]string{"secretsmanager:GetSecretValue arn:aws:secretsmanager:us-east-1:" + acct + ":secret:db-AbCdEf exact"}},
		{"secret by name", "secretsmanager.amazonaws.com", "GetSecretValue", `{"secretId":"prod/db"}`, "",
			[]string{"secretsmanager:GetSecretValue arn:aws:secretsmanager:us-east-1:" + acct + ":secret:prod/db-?????? exact"}},
		{"lambda versioned event", "lambda.amazonaws.com", "UpdateFunctionCode20150331v2", `{"functionName":"api:live"}`, "",
			[]string{"lambda:UpdateFunctionCode arn:aws:lambda:us-east-1:" + acct + ":function:api exact"}},
		{"lambda arn name", "lambda.amazonaws.com", "Invoke", `{"functionName":"arn:aws:lambda:us-east-1:` + acct + `:function:worker:3"}`, "",
			[]string{"lambda:InvokeFunction arn:aws:lambda:us-east-1:" + acct + ":function:worker exact"}},
		{"lambda partial arn", "lambda.amazonaws.com", "GetFunction20150331v2", `{"functionName":"` + acct + `:function:cron"}`, "",
			[]string{"lambda:GetFunction arn:aws:lambda:us-east-1:" + acct + ":function:cron exact"}},
		{"lambda short arn", "lambda.amazonaws.com", "GetFunction20150331v2", `{"functionName":"arn:aws:lambda"}`, "",
			[]string{"lambda:GetFunction arn:aws:lambda:us-east-1:" + acct + ":function:* partial"}},
		{"ssm names fan out", "ssm.amazonaws.com", "GetParameters", `{"names":["/a/b","/c"]}`, "",
			[]string{"ssm:GetParameters arn:aws:ssm:us-east-1:" + acct + ":parameter/a/b exact", "ssm:GetParameters arn:aws:ssm:us-east-1:" + acct + ":parameter/c exact"}},
		{"ec2 instances", "ec2.amazonaws.com", "StopInstances", `{"instancesSet":{"items":[{"instanceId":"i-1"},{"instanceId":"i-2"}]}}`, "",
			[]string{"ec2:StopInstances arn:aws:ec2:us-east-1:" + acct + ":instance/i-1 exact", "ec2:StopInstances arn:aws:ec2:us-east-1:" + acct + ":instance/i-2 exact"}},
		{"ec2 tags all mode", "ec2.amazonaws.com", "CreateTags", `{"resourcesSet":{"items":[{"resourceId":"i-1"},{"resourceId":"vol-9"},{"resourceId":"sg-1"}]}}`, "",
			[]string{"ec2:CreateTags arn:aws:ec2:us-east-1:" + acct + ":instance/i-1 exact", "ec2:CreateTags arn:aws:ec2:us-east-1:" + acct + ":volume/vol-9 exact"}},
		{"ec2 attach all mode", "ec2.amazonaws.com", "AttachVolume", `{"volumeId":"vol-1","instanceId":"i-7","device":"/dev/sdf"}`, "",
			[]string{"ec2:AttachVolume arn:aws:ec2:us-east-1:" + acct + ":instance/i-7 exact", "ec2:AttachVolume arn:aws:ec2:us-east-1:" + acct + ":volume/vol-1 exact"}},
		{"ec2 attach unresolved", "ec2.amazonaws.com", "AttachVolume", `{}`, "",
			[]string{"ec2:AttachVolume arn:aws:ec2:us-east-1:" + acct + ":volume/* partial"}},
		{"sts assume role", "sts.amazonaws.com", "AssumeRole", `{"roleArn":"arn:aws:iam::` + acct + `:role/x","roleSessionName":"s"}`, "",
			[]string{"sts:AssumeRole arn:aws:iam::" + acct + ":role/x exact"}},
		{"no auth", "sts.amazonaws.com", "GetCallerIdentity", "", "",
			[]string{"sts:GetCallerIdentity * exact noauth"}},
		{"iam role", "iam.amazonaws.com", "AttachRolePolicy", `{"roleName":"deploy","policyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}`, "",
			[]string{"iam:AttachRolePolicy arn:aws:iam::" + acct + ":role/deploy exact"}},
		{"logs group", "logs.amazonaws.com", "CreateLogStream", `{"logGroupName":"/aws/lambda/fn","logStreamName":"s"}`, "",
			[]string{"logs:CreateLogStream arn:aws:logs:us-east-1:" + acct + ":log-group:/aws/lambda/fn exact"}},
		{"uncatalogued event", "s3.amazonaws.com", "GetBucketWebsite", "", "",
			[]string{"s3:GetBucketWebsite * uncatalogued"}},
		{"uncatalogued lambda event strips suffix", "lambda.amazonaws.com", "GetAlias20150331", "", "",
			[]string{"lambda:GetAlias * uncatalogued"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls, err := m.Map(rec(t, c.source, c.event, c.params, c.r))
			if err != nil {
				t.Fatal(err)
			}
			got := render(calls)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
	if _, err := m.Map(rec(t, "rds.amazonaws.com", "DescribeDBInstances", "", "")); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("want ErrUnknownService, got %v", err)
	}
}

func TestTransforms(t *testing.T) {
	cases := map[string][2]string{
		"lastPathSegment":        {"https://x/y/z", "z"},
		"copySourceBucket":       {"/b/k", "b"},
		"copySourceKey":          {"b", ""},
		"stripLeadingSlash":      {"/a/b", "a/b"},
		"secretPattern":          {"arn:aws:x", ""},
		"kmsKeyId":               {"arn:aws:kms:us-east-1:1:key/x", ""},
		"kmsAlias":               {"k-1", ""},
		"requirePrefix:i-":       {"vol-1", ""},
		"unknown":                {"x", ""},
		"lambdaName":             {"plain", "plain"},
		"lastPathSegment:ignore": {"noslash", "noslash"},
	}
	for tr, io := range cases {
		if got := applyTransform(tr, io[0]); got != io[1] {
			t.Errorf("%s(%q)=%q want %q", tr, io[0], got, io[1])
		}
	}
	if lookupPath(nil, "a") != nil || lookupPath(map[string]any{"a": 1.0}, "") != nil {
		t.Fatal("lookupPath empty")
	}
	if got := lookupPath(map[string]any{"a": map[string]any{"b": true}}, "a.b"); len(got) != 1 || got[0] != "true" {
		t.Fatalf("bool scalar %v", got)
	}
	if got := lookupPath(map[string]any{"a": "x"}, "a.b"); got != nil {
		t.Fatalf("path through scalar %v", got)
	}
}
