package synth

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/url"
	"time"
)

const (
	appBucket      = "acme-app-data"
	artifactBucket = "acme-artifacts"
	reportBucket   = "acme-reports"
	dataKeyID      = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab"
	otherKeyID     = "9f8e7d6c-5b4a-4c3d-9e2f-ba9876543210"
)

var (
	roleApp     = "arn:aws:iam::" + Account + ":role/app/app-backend"
	roleCI      = "arn:aws:iam::" + Account + ":role/ci-deployer"
	roleOps     = "arn:aws:iam::" + Account + ":role/ops-automation"
	roleLegacy  = "arn:aws:iam::" + Account + ":role/legacy-reporting"
	userAnalyst = "arn:aws:iam::" + Account + ":user/analyst-01"
	dbSecret    = "arn:aws:secretsmanager:us-east-1:" + Account + ":secret:acme/app/db-Xk3P9q"
)

func ipIn(prefix string) func(r *rand.Rand) string {
	return func(r *rand.Rand) string { return fmt.Sprintf("%s.%d", prefix, 1+r.IntN(250)) }
}

// scenario defines the actors, their workloads (tasks), background noise and
// the ground truth. Rates are mean calls per active day.
func scenario() ([]task, []task, []PrincipalTruth) {
	app := &actor{key: "app", arn: roleApp, kind: "role", name: "app-backend", principal: "AROAEXAMPLEAPPBACKEND", session: "i-0f1e2d3c4b5a69788", sourceIP: ipIn("10.20.3"), userAgent: "aws-sdk-go-v2/1.32.6 os/linux lang/go#1.23.4 api/s3"}
	ci := &actor{key: "ci", arn: roleCI, kind: "role", name: "ci-deployer", principal: "AROAEXAMPLECIDEPLOYER", session: "gha-run-881", sourceIP: ipIn("198.51.100"), userAgent: "aws-cli/2.22.10 Python/3.12.6 Linux/6.5.0 exe/x86_64.ubuntu.24"}
	analyst := &actor{key: "analyst", arn: userAnalyst, kind: "user", name: "analyst-01", principal: "AIDAEXAMPLEANALYST01", sourceIP: ipIn("203.0.113"), userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", mfa: true, consoleUse: true}
	ops := &actor{key: "ops", arn: roleOps, kind: "role", name: "ops-automation", principal: "AROAEXAMPLEOPSAUTOMAT", session: "scheduler", sourceIP: ipIn("10.30.1"), userAgent: "Boto3/1.35.80 md/Botocore#1.35.80 ua/2.0 os/linux Python/3.12.7 exec-env/AWS_Lambda_python3.12"}
	svcIdentity := &actor{key: "svc", kind: "service"}

	instances := []string{"i-0a1b2c3d4e5f60001", "i-0a1b2c3d4e5f60002", "i-0a1b2c3d4e5f60003"}
	uploadKey := func(r *rand.Rand, date time.Time) string {
		return fmt.Sprintf("uploads/%s/%08x.json", date.Format("2006/01/02"), r.Uint32())
	}
	exportKey := func(r *rand.Rand, _ time.Time) string {
		return fmt.Sprintf("exports/tenant-%02d/report-%04d.csv", 1+r.IntN(4), r.IntN(10000))
	}
	reportKey := func(r *rand.Rand, date time.Time) string {
		return fmt.Sprintf("reports/%s/%s.csv", date.Format("2006-01"), []string{"sales", "returns", "inventory", "margin"}[r.IntN(4)])
	}
	region := func(r *rand.Rand) string {
		if r.IntN(10) == 0 {
			return "us-west-2"
		}
		return "us-east-1"
	}
	fn := func(r *rand.Rand) string { return []string{"deploy-api", "deploy-worker", "deploy-cron"}[r.IntN(3)] }

	n := func(action, res, freq string) Need {
		return Need{Action: action, Resource: res, Frequency: freq, Observable: true}
	}
	tasks := []task{
		// app-backend: an order-processing service.
		{actor: app, need: n("s3:GetObject", "arn:aws:s3:::acme-app-data/uploads/*", "frequent"), rate: 14, hour: -1,
			build: func(r *rand.Rand, _ int, d time.Time) call {
				return s3Object("GetObject", appBucket, uploadKey(r, d.AddDate(0, 0, -r.IntN(3))), true)
			}},
		{actor: app, need: n("s3:PutObject", "arn:aws:s3:::acme-app-data/uploads/*", "frequent"), rate: 8, hour: -1,
			build: func(r *rand.Rand, _ int, d time.Time) call {
				return s3Object("PutObject", appBucket, uploadKey(r, d), false)
			}},
		{actor: app, need: n("s3:PutObject", "arn:aws:s3:::acme-app-data/exports/*", "daily"), rate: 2, hour: 2,
			build: func(r *rand.Rand, _ int, d time.Time) call {
				return s3Object("PutObject", appBucket, exportKey(r, d), false)
			}},
		{actor: app, need: n("s3:ListBucket", "arn:aws:s3:::acme-app-data", "daily"), rate: 3, hour: -1,
			build: func(_ *rand.Rand, _ int, d time.Time) call {
				return s3List(appBucket, "uploads/"+d.Format("2006/01/02")+"/")
			}},
		{actor: app, need: n("s3:DeleteObject", "arn:aws:s3:::acme-app-data/exports/*", "monthly"), everyDays: 30, phase: 27, hour: 3,
			build: func(r *rand.Rand, _ int, d time.Time) call {
				return s3Object("DeleteObject", appBucket, exportKey(r, d), false)
			}},
		{actor: app, need: n("dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:111122223333:table/orders", "frequent"), rate: 10, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return ddb("GetItem", "orders", "", true) }},
		{actor: app, need: n("dynamodb:PutItem", "arn:aws:dynamodb:us-east-1:111122223333:table/orders", "frequent"), rate: 6, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return ddb("PutItem", "orders", "", false) }},
		{actor: app, need: n("dynamodb:UpdateItem", "arn:aws:dynamodb:us-east-1:111122223333:table/orders", "frequent"), rate: 5, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return ddb("UpdateItem", "orders", "", false) }},
		{actor: app, need: n("dynamodb:Query", "arn:aws:dynamodb:us-east-1:111122223333:table/orders/index/by-customer", "frequent"), rate: 4, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return ddb("Query", "orders", "by-customer", true) }},
		{actor: app, need: n("sqs:SendMessage", "arn:aws:sqs:us-east-1:111122223333:order-events", "frequent"), rate: 6, hour: -1,
			build: func(*rand.Rand, int, time.Time) call {
				return sqsCall("SendMessage", "us-east-1", "order-events", false)
			}},
		{actor: app, need: n("sqs:ReceiveMessage", "arn:aws:sqs:us-east-1:111122223333:order-jobs", "frequent"), rate: 6, hour: -1,
			build: func(*rand.Rand, int, time.Time) call {
				return sqsCall("ReceiveMessage", "us-east-1", "order-jobs", true)
			}},
		{actor: app, need: n("sqs:DeleteMessage", "arn:aws:sqs:us-east-1:111122223333:order-jobs", "frequent"), rate: 5, hour: -1,
			build: func(*rand.Rand, int, time.Time) call {
				return sqsCall("DeleteMessageBatch", "us-east-1", "order-jobs", false)
			}},
		{actor: app, need: n("kms:Decrypt", "arn:aws:kms:us-east-1:111122223333:key/"+dataKeyID, "frequent"), rate: 4, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return kmsCall("Decrypt", dataKeyID, "") }},
		{actor: app, need: n("kms:GenerateDataKey", "arn:aws:kms:us-east-1:111122223333:key/"+dataKeyID, "daily"), rate: 2, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return kmsCall("GenerateDataKey", dataKeyID, "alias/app-data") }},
		{actor: app, need: n("secretsmanager:GetSecretValue", dbSecret, "daily"), rate: 1, hour: 6,
			build: func(*rand.Rand, int, time.Time) call { return secretCall(dbSecret) }},
		{actor: app, need: n("secretsmanager:DescribeSecret", dbSecret, "quarterly"), everyDays: 90, phase: 70, hour: 6,
			build: func(*rand.Rand, int, time.Time) call {
				c := secretCall(dbSecret)
				c.name = "DescribeSecret"
				return c
			}},
		{actor: app, need: n("logs:CreateLogStream", "arn:aws:logs:us-east-1:111122223333:log-group:/acme/app-backend", "weekly"), everyDays: 7, phase: 3, hour: 0,
			build: func(_ *rand.Rand, day int, _ time.Time) call {
				return logsCall("CreateLogStream", "/acme/app-backend", fmt.Sprintf("app-backend/main/%03d", day))
			}},
		{actor: app, need: Need{Action: "logs:PutLogEvents", Resource: "arn:aws:logs:us-east-1:111122223333:log-group:/acme/app-backend:log-stream:*", Frequency: "never-logged"}},

		// ci-deployer: CI pipeline deploying three Lambda functions.
		{actor: ci, need: n("lambda:UpdateFunctionCode", "arn:aws:lambda:*:111122223333:function:deploy-*", "daily"), rate: 2, weekdays: true, hour: 15,
			build: func(r *rand.Rand, _ int, _ time.Time) call {
				return lambdaCall("UpdateFunctionCode20150331v2", "us-east-1", fn(r), false)
			}},
		{actor: ci, need: n("lambda:PublishVersion", "arn:aws:lambda:*:111122223333:function:deploy-*", "daily"), rate: 2, weekdays: true, hour: 15,
			build: func(r *rand.Rand, _ int, _ time.Time) call {
				return lambdaCall("PublishVersion20150331", "us-east-1", fn(r), false)
			}},
		{actor: ci, need: n("lambda:UpdateFunctionConfiguration", "arn:aws:lambda:*:111122223333:function:deploy-*", "weekly"), everyDays: 7, phase: 1, hour: 15,
			build: func(r *rand.Rand, _ int, _ time.Time) call {
				return lambdaCall("UpdateFunctionConfiguration20150331v2", "us-east-1", fn(r), false)
			}},
		{actor: ci, need: n("lambda:GetFunction", "arn:aws:lambda:*:111122223333:function:deploy-*", "daily"), rate: 3, weekdays: true, hour: 15,
			build: func(r *rand.Rand, _ int, _ time.Time) call {
				return lambdaCall("GetFunction20150331v2", region(r), fn(r), true)
			}},
		{actor: ci, need: n("lambda:CreateFunction", "arn:aws:lambda:*:111122223333:function:deploy-*", "monthly"), everyDays: 30, phase: 12, hour: 15,
			build: func(*rand.Rand, int, time.Time) call {
				return lambdaCall("CreateFunction20150331", "us-east-1", "deploy-reports", false)
			}},
		{actor: ci, need: n("lambda:DeleteFunction", "arn:aws:lambda:*:111122223333:function:deploy-*", "quarterly"), everyDays: 90, phase: 75, hour: 16,
			build: func(*rand.Rand, int, time.Time) call {
				return lambdaCall("DeleteFunction20150331", "us-east-1", "deploy-reports", false)
			}},
		{actor: ci, need: n("s3:PutObject", "arn:aws:s3:::acme-artifacts/builds/*", "daily"), rate: 2, weekdays: true, hour: 14,
			build: func(r *rand.Rand, _ int, _ time.Time) call {
				return s3Object("PutObject", artifactBucket, fmt.Sprintf("builds/%06d/bundle.zip", r.IntN(1000000)), false)
			}},
		{actor: ci, need: n("s3:GetObject", "arn:aws:s3:::acme-artifacts/builds/*", "daily"), rate: 2, weekdays: true, hour: 14,
			build: func(r *rand.Rand, _ int, _ time.Time) call {
				return s3Object("GetObject", artifactBucket, fmt.Sprintf("builds/%06d/manifest.json", r.IntN(1000000)), true)
			}},
		{actor: ci, need: n("sts:GetCallerIdentity", "*", "daily"), rate: 1, weekdays: true, hour: 14,
			build: func(*rand.Rand, int, time.Time) call {
				return plain("sts.amazonaws.com", "GetCallerIdentity", true)
			}},
		{actor: ci, need: Need{Action: "iam:PassRole", Resource: "arn:aws:iam::111122223333:role/lambda-exec-deploy", Frequency: "never-logged"}},

		// analyst-01: console user reading reports with MFA.
		{actor: analyst, need: n("s3:GetObject", "arn:aws:s3:::acme-reports/reports/*", "frequent"), rate: 6, weekdays: true, hour: -1,
			build: func(r *rand.Rand, _ int, d time.Time) call {
				return s3Object("GetObject", reportBucket, reportKey(r, d), true)
			}},
		{actor: analyst, need: n("s3:ListBucket", "arn:aws:s3:::acme-reports", "daily"), rate: 3, weekdays: true, hour: -1,
			build: func(_ *rand.Rand, _ int, d time.Time) call {
				return s3List(reportBucket, "reports/"+d.Format("2006-01")+"/")
			}},
		{actor: analyst, need: n("s3:ListAllMyBuckets", "*", "daily"), rate: 1, weekdays: true, hour: 9,
			build: func(*rand.Rand, int, time.Time) call {
				return plain("s3.amazonaws.com", "ListBuckets", true)
			}},
		{actor: analyst, need: n("dynamodb:Scan", "arn:aws:dynamodb:us-east-1:111122223333:table/metrics", "daily"), rate: 2, weekdays: true, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return ddb("Scan", "metrics", "", true) }},
		{actor: analyst, need: n("dynamodb:DescribeTable", "arn:aws:dynamodb:us-east-1:111122223333:table/metrics", "weekly"), everyDays: 7, phase: 2, hour: 10,
			build: func(*rand.Rand, int, time.Time) call { return ddb("DescribeTable", "metrics", "", true) }},
		{actor: analyst, need: n("ssm:GetParameter", "arn:aws:ssm:us-east-1:111122223333:parameter/analytics/warehouse-url", "weekly"), everyDays: 7, phase: 4, hour: 9,
			build: func(*rand.Rand, int, time.Time) call { return ssmGet("/analytics/warehouse-url") }},

		// ops-automation: instance scheduler with a permissions boundary.
		{actor: ops, need: n("ec2:DescribeInstances", "*", "daily"), rate: 4, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return ec2Describe() }},
		{actor: ops, need: n("ec2:DescribeVolumes", "*", "daily"), rate: 1, weekdays: true, hour: 19,
			build: func(*rand.Rand, int, time.Time) call {
				return plain("ec2.amazonaws.com", "DescribeVolumes", true)
			}},
		{actor: ops, need: n("ec2:DescribeSnapshots", "*", "daily"), rate: 1, weekdays: true, hour: 19,
			build: func(*rand.Rand, int, time.Time) call {
				return plain("ec2.amazonaws.com", "DescribeSnapshots", true)
			}},
		{actor: ops, need: n("ec2:StopInstances", "arn:aws:ec2:us-east-1:111122223333:instance/*", "daily"), rate: 1, weekdays: true, hour: 20,
			build: func(*rand.Rand, int, time.Time) call { return ec2Instances("StopInstances", instances...) }},
		{actor: ops, need: n("ec2:StartInstances", "arn:aws:ec2:us-east-1:111122223333:instance/*", "daily"), rate: 1, weekdays: true, hour: 7,
			build: func(*rand.Rand, int, time.Time) call { return ec2Instances("StartInstances", instances...) }},
		{actor: ops, need: n("ec2:CreateTags", "arn:aws:ec2:us-east-1:111122223333:instance/*", "daily"), rate: 1, weekdays: true, hour: 20,
			build: func(*rand.Rand, int, time.Time) call { return ec2Tags(instances...) }},
		{actor: ops, need: n("ssm:GetParameter", "arn:aws:ssm:us-east-1:111122223333:parameter/ops/*", "daily"), rate: 3, hour: -1,
			build: func(r *rand.Rand, _ int, _ time.Time) call {
				return ssmGet([]string{"/ops/schedule/weekday", "/ops/schedule/weekend", "/ops/schedule/holidays"}[r.IntN(3)])
			}},
		{actor: ops, need: n("sns:Publish", "arn:aws:sns:us-east-1:111122223333:ops-alerts", "weekly"), everyDays: 5, phase: 2, hour: -1,
			build: func(*rand.Rand, int, time.Time) call { return snsPublish("ops-alerts") }},
	}

	noise := []task{
		{actor: app, need: Need{Frequency: "denied-explicit-deny"}, everyDays: 30, phase: 11,
			build: func(*rand.Rand, int, time.Time) call { return denied(s3Bucket("DeleteBucket", appBucket)) }},
		{actor: app, need: Need{Frequency: "denied-not-granted"}, everyDays: 20, phase: 5,
			build: func(*rand.Rand, int, time.Time) call {
				return denied(plain("iam.amazonaws.com", "ListRoles", true))
			}},
		{actor: analyst, need: Need{Frequency: "denied-not-granted"}, everyDays: 15, phase: 8,
			build: func(*rand.Rand, int, time.Time) call {
				return denied(s3Object("PutObject", reportBucket, "reports/scratch/notes.csv", false))
			}},
		{actor: ci, need: Need{Frequency: "uncatalogued-service"}, everyDays: 2, phase: 0,
			build: func(*rand.Rand, int, time.Time) call {
				return plain("cloudformation.amazonaws.com", "DescribeStacks", true)
			}},
		{actor: svcIdentity, need: Need{Frequency: "aws-service-principal"}, everyDays: 3, phase: 1,
			build: func(*rand.Rand, int, time.Time) call {
				return plain("sts.amazonaws.com", "AssumeRole", false)
			}},
	}
	svcIdentity.sourceIP = func(*rand.Rand) string { return "lambda.amazonaws.com" }
	svcIdentity.userAgent = "lambda.amazonaws.com"

	truths := buildTruth(tasks, map[string]string{
		roleApp:     "Order-processing service (ECS task role): S3 uploads/exports, DynamoDB orders, SQS, KMS, one secret.",
		roleCI:      "CI pipeline deploying three Lambda functions and build artifacts; original policy is admin-in-two-regions.",
		userAnalyst: "Console analyst (MFA) reading reports and metrics via a group policy.",
		roleOps:     "Instance scheduler with a permissions boundary that blocks IAM.",
		roleLegacy:  "Decommissioned reporting job: policies still attached, no activity.",
	})
	addDecoys(truths)
	return tasks, noise, truths
}

func buildTruth(tasks []task, desc map[string]string) []PrincipalTruth {
	byARN := map[string]*PrincipalTruth{}
	var order []string
	add := func(arn string) *PrincipalTruth {
		if pt, ok := byARN[arn]; ok {
			return pt
		}
		pt := &PrincipalTruth{ARN: arn, Description: desc[arn]}
		byARN[arn] = pt
		order = append(order, arn)
		return pt
	}
	for _, t := range tasks {
		add(t.actor.arn).Needs = append(add(t.actor.arn).Needs, t.need)
	}
	add(roleLegacy)
	out := make([]PrincipalTruth, 0, len(order))
	for _, a := range order {
		out = append(out, *byARN[a])
	}
	return out
}

func addDecoys(ts []PrincipalTruth) {
	decoys := map[string][]Decoy{
		roleApp: {
			{"s3:GetObject", "arn:aws:s3:::acme-payroll/2026/salaries.csv", "another team's bucket"},
			{"s3:GetObject", "arn:aws:s3:::acme-app-data/admin/break-glass.txt", "same bucket, prefix the service never reads"},
			{"s3:DeleteObject", "arn:aws:s3:::acme-app-data/uploads/2026/07/01/a.json", "service never deletes uploads"},
			{"dynamodb:DeleteTable", "arn:aws:dynamodb:us-east-1:111122223333:table/orders", "destructive table operation"},
			{"dynamodb:Scan", "arn:aws:dynamodb:us-east-1:111122223333:table/customers-pii", "PII table"},
			{"sqs:PurgeQueue", "arn:aws:sqs:us-east-1:111122223333:order-jobs", "destructive queue operation"},
			{"kms:Decrypt", "arn:aws:kms:us-east-1:111122223333:key/" + otherKeyID, "another key"},
			{"secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/root-AbCdEf", "unrelated secret"},
		},
		roleCI: {
			{"lambda:UpdateFunctionCode", "arn:aws:lambda:us-east-1:111122223333:function:payments-prod", "function the pipeline does not own"},
			{"iam:CreateUser", "arn:aws:iam::111122223333:user/backdoor", "identity creation"},
			{"iam:AttachRolePolicy", "arn:aws:iam::111122223333:role/ci-deployer", "self privilege escalation"},
			{"s3:GetObject", "arn:aws:s3:::acme-payroll/2026/salaries.csv", "sensitive bucket"},
			{"ec2:TerminateInstances", "arn:aws:ec2:us-east-1:111122223333:instance/i-0a1b2c3d4e5f60001", "unrelated infrastructure"},
			{"secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/root-AbCdEf", "unrelated secret"},
		},
		userAnalyst: {
			{"s3:GetObject", "arn:aws:s3:::acme-payroll/2026/salaries.csv", "sensitive bucket"},
			{"s3:GetObject", "arn:aws:s3:::acme-app-data/uploads/2026/07/01/a.json", "application data"},
			{"dynamodb:Scan", "arn:aws:dynamodb:us-east-1:111122223333:table/customers-pii", "PII table"},
			{"ssm:GetParameter", "arn:aws:ssm:us-east-1:111122223333:parameter/ops/slack/webhook", "another team's parameter"},
		},
		roleOps: {
			{"ec2:TerminateInstances", "arn:aws:ec2:us-east-1:111122223333:instance/i-0a1b2c3d4e5f60001", "scheduler never terminates"},
			{"ec2:AuthorizeSecurityGroupIngress", "arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0", "network exposure"},
			{"ssm:PutParameter", "arn:aws:ssm:us-east-1:111122223333:parameter/ops/schedule/weekday", "write to config"},
			{"sns:Publish", "arn:aws:sns:us-east-1:111122223333:customer-notifications", "customer-facing topic"},
		},
		roleLegacy: {
			{"s3:GetObject", "arn:aws:s3:::acme-legacy/exports/2025/q4.csv", "decommissioned workload"},
			{"dynamodb:Scan", "arn:aws:dynamodb:us-east-1:111122223333:table/legacy-reports", "decommissioned workload"},
		},
	}
	for i := range ts {
		ts[i].Decoys = decoys[ts[i].ARN]
	}
}

func stmt(sid, effect string, actions, resources []string, cond map[string]any) map[string]any {
	s := map[string]any{"Sid": sid, "Effect": effect, "Action": actions, "Resource": resources}
	if cond != nil {
		s["Condition"] = cond
	}
	return s
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // static literal data; cannot fail
	}
	return string(b)
}

func doc(stmts ...map[string]any) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": stmts}
}

// inventory returns the IAM inventory in get-account-authorization-details
// format. One inline policy is URL-encoded, as the raw IAM API returns it.
func inventory() map[string]any {
	any1 := []string{"*"}
	appPolicy := doc(
		stmt("S3Data", "Allow", []string{"s3:*"}, any1, nil),
		stmt("Orders", "Allow", []string{"dynamodb:*"}, []string{"arn:aws:dynamodb:us-east-1:" + Account + ":table/*"}, nil),
		stmt("Queues", "Allow", []string{"sqs:*"}, any1, nil),
		stmt("Crypto", "Allow", []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"}, any1, nil),
		stmt("Secrets", "Allow", []string{"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets"}, any1, nil),
		stmt("Logs", "Allow", []string{"logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"}, []string{"arn:aws:logs:*:*:*"}, nil),
		stmt("ProtectBuckets", "Deny", []string{"s3:DeleteBucket", "s3:PutBucketPolicy"}, any1, nil),
	)
	ciPolicy := doc(
		stmt("AdminInDeployRegions", "Allow", []string{"*"}, any1, map[string]any{
			"StringEquals": map[string]any{"aws:RequestedRegion": []string{"us-east-1", "us-west-2"}},
		}),
		stmt("PassExecRoles", "Allow", []string{"iam:PassRole"}, []string{"arn:aws:iam::" + Account + ":role/lambda-exec-*"}, nil),
	)
	analystGroup := doc(
		stmt("ReadReports", "Allow", []string{"s3:Get*", "s3:List*"}, any1, map[string]any{
			"Bool": map[string]any{"aws:MultiFactorAuthPresent": "true"},
		}),
		stmt("ReadMetrics", "Allow", []string{"dynamodb:Describe*", "dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem"}, []string{"arn:aws:dynamodb:*:" + Account + ":table/*"}, nil),
	)
	analystInline := doc(
		stmt("AnalyticsParams", "Allow", []string{"ssm:GetParameter", "ssm:GetParameters"}, []string{"arn:aws:ssm:us-east-1:" + Account + ":parameter/analytics/*"}, nil),
	)
	opsPolicy := doc(
		stmt("Compute", "Allow", []string{"ec2:*"}, any1, nil),
		stmt("Params", "Allow", []string{"ssm:GetParameter*", "ssm:PutParameter"}, []string{"arn:aws:ssm:us-east-1:" + Account + ":parameter/ops/*"}, nil),
		stmt("Alerts", "Allow", []string{"sns:Publish"}, any1, nil),
		stmt("LegacyIamAccess", "Allow", []string{"iam:*"}, any1, nil),
	)
	opsBoundary := doc(
		stmt("BoundaryAllow", "Allow", []string{"ec2:*", "ssm:*", "sns:*", "logs:*"}, any1, nil),
		stmt("NoTerminate", "Deny", []string{"ec2:TerminateInstances"}, any1, nil),
	)
	legacyPolicy := doc(
		stmt("LegacyRead", "Allow", []string{"s3:GetObject", "s3:ListBucket"}, []string{"arn:aws:s3:::acme-legacy", "arn:aws:s3:::acme-legacy/*"}, nil),
		stmt("LegacyTable", "Allow", []string{"dynamodb:Scan", "dynamodb:Query"}, []string{"arn:aws:dynamodb:us-east-1:" + Account + ":table/legacy-reports"}, nil),
	)
	managed := func(name string, d map[string]any) map[string]any {
		return map[string]any{
			"PolicyName": name, "Arn": "arn:aws:iam::" + Account + ":policy/" + name,
			"DefaultVersionId": "v1", "AttachmentCount": 1, "IsAttachable": true,
			"PolicyVersionList": []any{map[string]any{"Document": d, "VersionId": "v1", "IsDefaultVersion": true}},
		}
	}
	attach := func(names ...string) []any {
		out := make([]any, len(names))
		for i, n := range names {
			out[i] = map[string]any{"PolicyName": n, "PolicyArn": "arn:aws:iam::" + Account + ":policy/" + n}
		}
		return out
	}
	encodedLegacy := mustJSON(legacyPolicy)
	return map[string]any{
		"UserDetailList": []any{map[string]any{
			"Path": "/", "UserName": "analyst-01", "UserId": "AIDAEXAMPLEANALYST01", "Arn": userAnalyst,
			"GroupList":               []string{"analysts"},
			"UserPolicyList":          []any{map[string]any{"PolicyName": "AnalyticsParams", "PolicyDocument": analystInline}},
			"AttachedManagedPolicies": []any{},
		}},
		"GroupDetailList": []any{map[string]any{
			"Path": "/", "GroupName": "analysts", "GroupId": "AGPAEXAMPLEANALYSTS", "Arn": "arn:aws:iam::" + Account + ":group/analysts",
			"GroupPolicyList": []any{}, "AttachedManagedPolicies": attach("ReadOnlyAnalyst"),
		}},
		"RoleDetailList": []any{
			map[string]any{"Path": "/app/", "RoleName": "app-backend", "RoleId": "AROAEXAMPLEAPPBACKEND", "Arn": roleApp,
				"RolePolicyList": []any{map[string]any{"PolicyName": "AppBackendAccess", "PolicyDocument": appPolicy}}, "AttachedManagedPolicies": []any{}},
			map[string]any{"Path": "/", "RoleName": "ci-deployer", "RoleId": "AROAEXAMPLECIDEPLOYER", "Arn": roleCI,
				"RolePolicyList": []any{}, "AttachedManagedPolicies": attach("CiDeployerAccess")},
			map[string]any{"Path": "/", "RoleName": "ops-automation", "RoleId": "AROAEXAMPLEOPSAUTOMAT", "Arn": roleOps,
				"RolePolicyList": []any{map[string]any{"PolicyName": "OpsAccess", "PolicyDocument": opsPolicy}}, "AttachedManagedPolicies": []any{},
				"PermissionsBoundary": map[string]any{"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::" + Account + ":policy/OpsBoundary"}},
			map[string]any{"Path": "/", "RoleName": "legacy-reporting", "RoleId": "AROAEXAMPLELEGACYREPO", "Arn": roleLegacy,
				"RolePolicyList": []any{map[string]any{"PolicyName": "LegacyReporting", "PolicyDocument": url.QueryEscape(encodedLegacy)}}, "AttachedManagedPolicies": []any{}},
		},
		"Policies": []any{managed("CiDeployerAccess", ciPolicy), managed("ReadOnlyAnalyst", analystGroup), managed("OpsBoundary", opsBoundary)},
	}
}
