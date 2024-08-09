package synth

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// event is the CloudTrail record shape the simulator writes. It carries the
// fields a real record has (including ones leastpriv ignores) so fixtures
// look like delivered CloudTrail logs.
type event struct {
	EventVersion       string         `json:"eventVersion"`
	UserIdentity       map[string]any `json:"userIdentity"`
	EventTime          string         `json:"eventTime"`
	EventSource        string         `json:"eventSource"`
	EventName          string         `json:"eventName"`
	AWSRegion          string         `json:"awsRegion"`
	SourceIPAddress    string         `json:"sourceIPAddress"`
	UserAgent          string         `json:"userAgent"`
	ErrorCode          string         `json:"errorCode,omitempty"`
	ErrorMessage       string         `json:"errorMessage,omitempty"`
	RequestParameters  map[string]any `json:"requestParameters"`
	ResponseElements   any            `json:"responseElements"`
	RequestID          string         `json:"requestID"`
	EventID            string         `json:"eventID"`
	ReadOnly           bool           `json:"readOnly"`
	Resources          []resource     `json:"resources,omitempty"`
	EventType          string         `json:"eventType"`
	ManagementEvent    bool           `json:"managementEvent"`
	RecipientAccountID string         `json:"recipientAccountId"`
	EventCategory      string         `json:"eventCategory"`
	TLSDetails         map[string]any `json:"tlsDetails,omitempty"`
}

type resource struct {
	AccountID string `json:"accountId,omitempty"`
	Type      string `json:"type"`
	ARN       string `json:"ARN"`
}

// call is one API call to render as a record.
type call struct {
	source    string
	name      string
	region    string
	params    map[string]any
	resources []resource
	readOnly  bool
	data      bool
	errorCode string
}

// actor is a simulated caller.
type actor struct {
	key        string // short name used in truth and logs
	arn        string // IAM principal ARN
	kind       string // "role" or "user"
	name       string
	principal  string // AROA/AIDA id
	session    string
	sourceIP   func(r *rand.Rand) string
	userAgent  string
	mfa        bool
	consoleUse bool
}

func (a *actor) identity(account string, t time.Time) map[string]any {
	created := t.Add(-37 * time.Minute).Format(time.RFC3339)
	if a.kind == "service" {
		return map[string]any{"type": "AWSService", "invokedBy": a.userAgent}
	}
	if a.kind == "user" {
		id := map[string]any{
			"type": "IAMUser", "principalId": a.principal, "arn": a.arn,
			"accountId": account, "accessKeyId": "ASIA" + strings.Repeat("X", 12) + "USER", "userName": a.name,
		}
		if a.consoleUse {
			id["sessionContext"] = map[string]any{
				"sessionIssuer": map[string]any{},
				"attributes":    map[string]any{"creationDate": created, "mfaAuthenticated": fmt.Sprint(a.mfa)},
			}
		}
		return id
	}
	return map[string]any{
		"type":        "AssumedRole",
		"principalId": a.principal + ":" + a.session,
		"arn":         fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", account, a.name, a.session),
		"accountId":   account,
		"accessKeyId": "ASIA" + strings.Repeat("X", 12) + "ROLE",
		"sessionContext": map[string]any{
			"sessionIssuer": map[string]any{
				"type": "Role", "principalId": a.principal, "arn": a.arn, "accountId": account, "userName": a.name,
			},
			"attributes": map[string]any{"creationDate": created, "mfaAuthenticated": fmt.Sprint(a.mfa)},
		},
	}
}

func uuid(r *rand.Rand) string {
	return fmt.Sprintf("%08x-%04x-4%03x-%04x-%012x", r.Uint32(), r.Uint32()&0xffff, r.Uint32()&0xfff, (r.Uint32()&0x3fff)|0x8000, r.Uint64()&0xffffffffffff)
}

func render(r *rand.Rand, account string, a *actor, c call, t time.Time) event {
	e := event{
		EventVersion:       "1.09",
		UserIdentity:       a.identity(account, t),
		EventTime:          t.UTC().Format(time.RFC3339),
		EventSource:        c.source,
		EventName:          c.name,
		AWSRegion:          c.region,
		SourceIPAddress:    a.sourceIP(r),
		UserAgent:          a.userAgent,
		RequestParameters:  c.params,
		RequestID:          strings.ToUpper(strings.ReplaceAll(uuid(r), "-", ""))[:20],
		EventID:            uuid(r),
		ReadOnly:           c.readOnly,
		Resources:          c.resources,
		EventType:          "AwsApiCall",
		ManagementEvent:    !c.data,
		RecipientAccountID: account,
		EventCategory:      "Management",
		TLSDetails: map[string]any{
			"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256",
			"clientProvidedHostHeader": strings.TrimSuffix(c.source, ".amazonaws.com") + "." + c.region + ".amazonaws.com",
		},
	}
	if c.data {
		e.EventCategory = "Data"
	}
	if c.errorCode != "" {
		e.ErrorCode = c.errorCode
		e.ErrorMessage = "User: " + a.arn + " is not authorized to perform this operation"
	}
	return e
}

// Builders for the API calls the scenario uses. Each mirrors the
// requestParameters / resources CloudTrail records for that API.

func s3Object(name, bucket, key string, readOnly bool) call {
	return call{
		source: "s3.amazonaws.com", name: name, region: "us-east-1", readOnly: readOnly, data: true,
		params: map[string]any{"bucketName": bucket, "key": key, "Host": bucket + ".s3.us-east-1.amazonaws.com"},
		resources: []resource{
			{Type: "AWS::S3::Object", ARN: "arn:aws:s3:::" + bucket + "/" + key},
			{Type: "AWS::S3::Bucket", ARN: "arn:aws:s3:::" + bucket, AccountID: Account},
		},
	}
}

func s3List(bucket, prefix string) call {
	return call{
		source: "s3.amazonaws.com", name: "ListObjects", region: "us-east-1", readOnly: true, data: true,
		params:    map[string]any{"bucketName": bucket, "prefix": prefix, "delimiter": "/", "Host": bucket + ".s3.us-east-1.amazonaws.com"},
		resources: []resource{{Type: "AWS::S3::Bucket", ARN: "arn:aws:s3:::" + bucket, AccountID: Account}},
	}
}

func s3Bucket(name, bucket string) call {
	return call{
		source: "s3.amazonaws.com", name: name, region: "us-east-1",
		params:    map[string]any{"bucketName": bucket, "Host": bucket + ".s3.us-east-1.amazonaws.com"},
		resources: []resource{{Type: "AWS::S3::Bucket", ARN: "arn:aws:s3:::" + bucket, AccountID: Account}},
	}
}

func ddb(name, table, index string, readOnly bool) call {
	region := homeRegion
	p := map[string]any{"tableName": table}
	if index != "" {
		p["indexName"] = index
	}
	if name == "GetItem" || name == "PutItem" || name == "UpdateItem" || name == "DeleteItem" {
		p["key"] = map[string]any{"pk": "HIDDEN_DUE_TO_SECURITY_REASONS"}
	}
	return call{
		source: "dynamodb.amazonaws.com", name: name, region: region, readOnly: readOnly, data: true, params: p,
		resources: []resource{{Type: "AWS::DynamoDB::Table", ARN: fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", region, Account, table), AccountID: Account}},
	}
}

func sqsCall(name, region, queue string, readOnly bool) call {
	return call{
		source: "sqs.amazonaws.com", name: name, region: region, readOnly: readOnly, data: true,
		params: map[string]any{"queueUrl": fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", region, Account, queue)},
	}
}

func kmsCall(name, keyID, keyRef string) call {
	p := map[string]any{"encryptionAlgorithm": "SYMMETRIC_DEFAULT", "encryptionContext": map[string]any{"app": "acme"}}
	if keyRef != "" {
		p["keyId"] = keyRef
	}
	if name == "GenerateDataKey" {
		p["keySpec"] = "AES_256"
		delete(p, "encryptionAlgorithm")
	}
	return call{
		source: "kms.amazonaws.com", name: name, region: "us-east-1", readOnly: name == "Decrypt", params: p,
		resources: []resource{{Type: "AWS::KMS::Key", ARN: fmt.Sprintf("arn:aws:kms:us-east-1:%s:key/%s", Account, keyID), AccountID: Account}},
	}
}

func secretCall(secretARN string) call {
	return call{source: "secretsmanager.amazonaws.com", name: "GetSecretValue", region: "us-east-1", readOnly: true,
		params: map[string]any{"secretId": secretARN}}
}

func logsCall(name, group, stream string) call {
	p := map[string]any{"logGroupName": group}
	if stream != "" {
		p["logStreamName"] = stream
	}
	return call{source: "logs.amazonaws.com", name: name, region: "us-east-1", params: p}
}

func lambdaCall(event, region, fn string, readOnly bool) call {
	return call{source: "lambda.amazonaws.com", name: event, region: region, readOnly: readOnly,
		params: map[string]any{"functionName": fn}}
}

func ec2Instances(name string, ids ...string) call {
	items := make([]any, len(ids))
	for i, id := range ids {
		items[i] = map[string]any{"instanceId": id}
	}
	return call{source: "ec2.amazonaws.com", name: name, region: "us-east-1",
		params: map[string]any{"instancesSet": map[string]any{"items": items}}}
}

func ec2Describe() call {
	return call{source: "ec2.amazonaws.com", name: "DescribeInstances", region: "us-east-1", readOnly: true,
		params: map[string]any{"instancesSet": map[string]any{}, "filterSet": map[string]any{"items": []any{map[string]any{"name": "tag:schedule"}}}}}
}

func ec2Tags(ids ...string) call {
	items := make([]any, len(ids))
	for i, id := range ids {
		items[i] = map[string]any{"resourceId": id}
	}
	return call{source: "ec2.amazonaws.com", name: "CreateTags", region: "us-east-1",
		params: map[string]any{"resourcesSet": map[string]any{"items": items}, "tagSet": map[string]any{"items": []any{map[string]any{"key": "last-scheduled", "value": "true"}}}}}
}

func ssmGet(name string) call {
	return call{source: "ssm.amazonaws.com", name: "GetParameter", region: "us-east-1", readOnly: true,
		params: map[string]any{"name": name, "withDecryption": true}}
}

func snsPublish(topic string) call {
	return call{source: "sns.amazonaws.com", name: "Publish", region: "us-east-1", data: true,
		params: map[string]any{"topicArn": fmt.Sprintf("arn:aws:sns:us-east-1:%s:%s", Account, topic)}}
}

func plain(source, name string, readOnly bool) call {
	return call{source: source, name: name, region: homeRegion, readOnly: readOnly, params: map[string]any{}}
}

func denied(c call) call {
	c.errorCode = "AccessDenied"
	return c
}
