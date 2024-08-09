#!/usr/bin/env python3
"""Emit internal/catalog/data/catalog.json from the compact table below.

The catalog is a hand-curated subset of the AWS Service Authorization
Reference (action names, access levels, resource types, ARN formats) and of
the CloudTrail event names those actions produce. Keeping the source as a
compact table makes review easier than editing the JSON by hand.

Run: python3 scripts/gen_catalog.py > internal/catalog/data/catalog.json
"""
import json

L, R, W, P, T = "List", "Read", "Write", "Permissions management", "Tagging"

def a(name, access, resources=(), events=None, **flags):
    d = {"name": name, "access": access, "resources": list(resources)}
    if events is not None:
        d["events"] = list(events)
    d.update(flags)
    return d

services = []

services.append({
    "prefix": "s3", "name": "Amazon S3", "eventSource": "s3.amazonaws.com",
    "resourceTypes": [
        {"name": "bucket", "arn": "arn:${Partition}:s3:::${BucketName}", "cloudTrailType": "AWS::S3::Bucket",
         "params": {"BucketName": ["bucketName"]}},
        {"name": "object", "arn": "arn:${Partition}:s3:::${BucketName}/${ObjectName}", "cloudTrailType": "AWS::S3::Object",
         "params": {"BucketName": ["bucketName"], "ObjectName": ["key", "delete.Object[].Key"]}},
    ],
    "actions": [
        a("ListAllMyBuckets", L, events=["ListBuckets"]),
        a("ListBucket", L, ["bucket"], events=["ListObjects", "ListObjectsV2", "HeadBucket"]),
        a("ListBucketVersions", L, ["bucket"], events=["ListObjectVersions"]),
        a("ListBucketMultipartUploads", L, ["bucket"], events=["ListMultipartUploads"]),
        a("GetBucketLocation", R, ["bucket"]),
        a("GetBucketPolicy", R, ["bucket"]),
        a("PutBucketPolicy", P, ["bucket"]),
        a("DeleteBucketPolicy", P, ["bucket"]),
        a("GetBucketAcl", R, ["bucket"]),
        a("PutBucketAcl", P, ["bucket"]),
        a("GetBucketTagging", R, ["bucket"]),
        a("PutBucketTagging", T, ["bucket"]),
        a("GetBucketVersioning", R, ["bucket"]),
        a("PutBucketVersioning", W, ["bucket"]),
        a("GetEncryptionConfiguration", R, ["bucket"], events=["GetBucketEncryption"]),
        a("PutEncryptionConfiguration", W, ["bucket"], events=["PutBucketEncryption"]),
        a("GetLifecycleConfiguration", R, ["bucket"], events=["GetBucketLifecycle"]),
        a("PutLifecycleConfiguration", W, ["bucket"], events=["PutBucketLifecycle"]),
        a("GetBucketPublicAccessBlock", R, ["bucket"], events=["GetPublicAccessBlock"]),
        a("PutBucketPublicAccessBlock", P, ["bucket"], events=["PutPublicAccessBlock"]),
        a("CreateBucket", W, ["bucket"]),
        a("DeleteBucket", W, ["bucket"]),
        a("GetObject", R, ["object"], events=["GetObject", "HeadObject"], dataEvent=True),
        a("GetObjectVersion", R, ["object"], events=[], dataEvent=True),
        a("PutObject", W, ["object"], events=["PutObject", "CopyObject", "CreateMultipartUpload", "UploadPart", "CompleteMultipartUpload"], dataEvent=True),
        a("DeleteObject", W, ["object"], events=["DeleteObject", "DeleteObjects"], dataEvent=True),
        a("AbortMultipartUpload", W, ["object"], dataEvent=True),
        a("ListMultipartUploadParts", L, ["object"], events=["ListParts"], dataEvent=True),
        a("GetObjectAcl", R, ["object"], dataEvent=True),
        a("PutObjectAcl", P, ["object"], dataEvent=True),
        a("GetObjectTagging", R, ["object"], dataEvent=True),
        a("PutObjectTagging", T, ["object"], dataEvent=True),
    ],
    "extraEvents": [
        {"event": "CopyObject", "action": "GetObject",
         "params": {"BucketName": ["x-amz-copy-source|copySourceBucket"], "ObjectName": ["x-amz-copy-source|copySourceKey"]}},
    ],
})

services.append({
    "prefix": "dynamodb", "name": "Amazon DynamoDB", "eventSource": "dynamodb.amazonaws.com",
    "resourceTypes": [
        {"name": "index", "arn": "arn:${Partition}:dynamodb:${Region}:${Account}:table/${TableName}/index/${IndexName}",
         "params": {"TableName": ["tableName"], "IndexName": ["indexName"]}},
        {"name": "stream", "arn": "arn:${Partition}:dynamodb:${Region}:${Account}:table/${TableName}/stream/${StreamLabel}",
         "arnParams": ["streamArn"], "params": {}},
        {"name": "table", "arn": "arn:${Partition}:dynamodb:${Region}:${Account}:table/${TableName}", "cloudTrailType": "AWS::DynamoDB::Table",
         "params": {"TableName": ["tableName", "requestItems.{}", "transactItems[].get.tableName"]}},
    ],
    "actions": [
        a("ListTables", L),
        a("ListStreams", R),
        a("DescribeTable", R, ["table"]),
        a("DescribeTimeToLive", R, ["table"]),
        a("ListTagsOfResource", R, ["table"]),
        a("GetItem", R, ["table"], dataEvent=True),
        a("BatchGetItem", R, ["table"], dataEvent=True),
        a("ConditionCheckItem", R, ["table"], dataEvent=True),
        a("Query", R, ["index", "table"], dataEvent=True),
        a("Scan", R, ["index", "table"], dataEvent=True),
        a("PutItem", W, ["table"], dataEvent=True),
        a("UpdateItem", W, ["table"], dataEvent=True),
        a("DeleteItem", W, ["table"], dataEvent=True),
        a("BatchWriteItem", W, ["table"], dataEvent=True),
        a("CreateTable", W, ["table"]),
        a("DeleteTable", W, ["table"]),
        a("UpdateTable", W, ["table"]),
        a("UpdateTimeToLive", W, ["table"]),
        a("DescribeStream", R, ["stream"], dataEvent=True),
        a("GetRecords", R, ["stream"], dataEvent=True),
        a("GetShardIterator", R, ["stream"], dataEvent=True),
        a("TagResource", T, ["table"]),
        a("UntagResource", T, ["table"]),
    ],
})

services.append({
    "prefix": "lambda", "name": "AWS Lambda", "eventSource": "lambda.amazonaws.com", "stripEventSuffix": True,
    "resourceTypes": [
        {"name": "function", "arn": "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}", "cloudTrailType": "AWS::Lambda::Function",
         "params": {"FunctionName": ["functionName|lambdaName"]}},
    ],
    "actions": [
        a("ListFunctions", L),
        a("GetFunction", R, ["function"]),
        a("GetFunctionConfiguration", R, ["function"]),
        a("GetPolicy", R, ["function"]),
        a("ListTags", R, ["function"]),
        a("ListVersionsByFunction", L, ["function"]),
        a("InvokeFunction", W, ["function"], events=["Invoke"], dataEvent=True),
        a("CreateFunction", W, ["function"]),
        a("DeleteFunction", W, ["function"]),
        a("UpdateFunctionCode", W, ["function"]),
        a("UpdateFunctionConfiguration", W, ["function"]),
        a("PublishVersion", W, ["function"]),
        a("AddPermission", P, ["function"]),
        a("RemovePermission", P, ["function"]),
        a("TagResource", T, ["function"]),
    ],
})

services.append({
    "prefix": "sqs", "name": "Amazon SQS", "eventSource": "sqs.amazonaws.com",
    "resourceTypes": [
        {"name": "queue", "arn": "arn:${Partition}:sqs:${Region}:${Account}:${QueueName}", "cloudTrailType": "AWS::SQS::Queue",
         "params": {"QueueName": ["queueUrl|lastPathSegment", "queueName"]}},
    ],
    "actions": [
        a("ListQueues", L),
        a("GetQueueUrl", R, ["queue"]),
        a("GetQueueAttributes", R, ["queue"]),
        a("ListQueueTags", R, ["queue"]),
        a("SendMessage", W, ["queue"], events=["SendMessage", "SendMessageBatch"], dataEvent=True),
        a("ReceiveMessage", R, ["queue"], dataEvent=True),
        a("DeleteMessage", W, ["queue"], events=["DeleteMessage", "DeleteMessageBatch"], dataEvent=True),
        a("ChangeMessageVisibility", W, ["queue"], events=["ChangeMessageVisibility", "ChangeMessageVisibilityBatch"], dataEvent=True),
        a("SetQueueAttributes", W, ["queue"]),
        a("CreateQueue", W, ["queue"]),
        a("DeleteQueue", W, ["queue"]),
        a("PurgeQueue", W, ["queue"]),
        a("AddPermission", P, ["queue"]),
        a("RemovePermission", P, ["queue"]),
        a("TagQueue", T, ["queue"]),
    ],
})

services.append({
    "prefix": "sns", "name": "Amazon SNS", "eventSource": "sns.amazonaws.com",
    "resourceTypes": [
        {"name": "topic", "arn": "arn:${Partition}:sns:${Region}:${Account}:${TopicName}", "cloudTrailType": "AWS::SNS::Topic",
         "arnParams": ["topicArn"], "params": {"TopicName": ["name"]}},
    ],
    "actions": [
        a("ListTopics", L),
        a("ListSubscriptions", L),
        a("ListSubscriptionsByTopic", L, ["topic"]),
        a("GetTopicAttributes", R, ["topic"]),
        a("Publish", W, ["topic"], dataEvent=True),
        a("Subscribe", W, ["topic"]),
        a("CreateTopic", W, ["topic"]),
        a("DeleteTopic", W, ["topic"]),
        a("SetTopicAttributes", W, ["topic"]),
        a("AddPermission", P, ["topic"]),
        a("RemovePermission", P, ["topic"]),
        a("TagResource", T, ["topic"]),
    ],
})

services.append({
    "prefix": "kms", "name": "AWS KMS", "eventSource": "kms.amazonaws.com",
    "resourceTypes": [
        {"name": "key", "arn": "arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}", "cloudTrailType": "AWS::KMS::Key",
         "arnParams": ["keyId"], "params": {"KeyId": ["keyId|kmsKeyId"]}},
        {"name": "alias", "arn": "arn:${Partition}:kms:${Region}:${Account}:alias/${Alias}",
         "params": {"Alias": ["aliasName|kmsAlias"]}},
    ],
    "actions": [
        a("ListKeys", L),
        a("ListAliases", L),
        a("CreateKey", W),
        a("DescribeKey", R, ["key"]),
        a("GetKeyPolicy", R, ["key"]),
        a("GetPublicKey", R, ["key"]),
        a("GetKeyRotationStatus", R, ["key"]),
        a("Decrypt", W, ["key"]),
        a("Encrypt", W, ["key"]),
        a("GenerateDataKey", W, ["key"]),
        a("GenerateDataKeyWithoutPlaintext", W, ["key"]),
        a("ReEncryptFrom", W, ["key"], events=["ReEncrypt"]),
        a("ReEncryptTo", W, ["key"], events=["ReEncrypt"]),
        a("Sign", W, ["key"]),
        a("Verify", W, ["key"]),
        a("ScheduleKeyDeletion", W, ["key"]),
        a("EnableKeyRotation", W, ["key"]),
        a("CreateAlias", W, ["alias"]),
        a("PutKeyPolicy", P, ["key"]),
        a("CreateGrant", P, ["key"]),
        a("RetireGrant", P, ["key"]),
    ],
})

services.append({
    "prefix": "secretsmanager", "name": "AWS Secrets Manager", "eventSource": "secretsmanager.amazonaws.com",
    "resourceTypes": [
        {"name": "Secret", "arn": "arn:${Partition}:secretsmanager:${Region}:${Account}:secret:${SecretId}", "cloudTrailType": "AWS::SecretsManager::Secret",
         "arnParams": ["secretId"], "params": {"SecretId": ["secretId|secretPattern", "name|secretPattern"]}},
    ],
    "actions": [
        a("ListSecrets", L),
        a("GetSecretValue", R, ["Secret"]),
        a("DescribeSecret", R, ["Secret"]),
        a("GetResourcePolicy", R, ["Secret"]),
        a("CreateSecret", W, ["Secret"]),
        a("PutSecretValue", W, ["Secret"]),
        a("UpdateSecret", W, ["Secret"]),
        a("RotateSecret", W, ["Secret"]),
        a("DeleteSecret", W, ["Secret"]),
        a("PutResourcePolicy", P, ["Secret"]),
        a("TagResource", T, ["Secret"]),
    ],
})

services.append({
    "prefix": "ssm", "name": "AWS Systems Manager (Parameter Store)", "eventSource": "ssm.amazonaws.com",
    "resourceTypes": [
        {"name": "parameter", "arn": "arn:${Partition}:ssm:${Region}:${Account}:parameter/${ParameterNameWithoutLeadingSlash}",
         "params": {"ParameterNameWithoutLeadingSlash": ["name|stripLeadingSlash", "names[]|stripLeadingSlash", "path|stripLeadingSlash"]}},
    ],
    "actions": [
        a("DescribeParameters", L),
        a("GetParameter", R, ["parameter"]),
        a("GetParameters", R, ["parameter"]),
        a("GetParametersByPath", R, ["parameter"]),
        a("GetParameterHistory", R, ["parameter"]),
        a("PutParameter", W, ["parameter"]),
        a("DeleteParameter", W, ["parameter"]),
        a("AddTagsToResource", T, ["parameter"]),
    ],
})

services.append({
    "prefix": "logs", "name": "Amazon CloudWatch Logs", "eventSource": "logs.amazonaws.com",
    "resourceTypes": [
        {"name": "log-stream", "arn": "arn:${Partition}:logs:${Region}:${Account}:log-group:${LogGroupName}:log-stream:${LogStreamName}",
         "params": {"LogGroupName": ["logGroupName"], "LogStreamName": ["logStreamName"]}},
        {"name": "log-group", "arn": "arn:${Partition}:logs:${Region}:${Account}:log-group:${LogGroupName}",
         "params": {"LogGroupName": ["logGroupName"]}},
    ],
    "actions": [
        a("DescribeLogGroups", L),
        a("DescribeLogStreams", L, ["log-group"]),
        a("CreateLogGroup", W, ["log-group"]),
        a("CreateLogStream", W, ["log-group"]),
        a("DeleteLogGroup", W, ["log-group"]),
        a("PutRetentionPolicy", W, ["log-group"]),
        a("PutLogEvents", W, ["log-stream"], notLogged=True),
        a("GetLogEvents", R, ["log-stream"]),
        a("FilterLogEvents", R, ["log-group"]),
        a("StartQuery", R, ["log-group"]),
        a("GetQueryResults", R),
        a("TagResource", T, ["log-group"]),
    ],
})

services.append({
    "prefix": "iam", "name": "AWS Identity and Access Management", "eventSource": "iam.amazonaws.com",
    "resourceTypes": [
        {"name": "role", "arn": "arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}", "cloudTrailType": "AWS::IAM::Role",
         "params": {"RoleNameWithPath": ["roleName"]}},
        {"name": "user", "arn": "arn:${Partition}:iam::${Account}:user/${UserNameWithPath}", "cloudTrailType": "AWS::IAM::User",
         "params": {"UserNameWithPath": ["userName"]}},
        {"name": "group", "arn": "arn:${Partition}:iam::${Account}:group/${GroupNameWithPath}",
         "params": {"GroupNameWithPath": ["groupName"]}},
        {"name": "policy", "arn": "arn:${Partition}:iam::${Account}:policy/${PolicyNameWithPath}",
         "arnParams": ["policyArn"], "params": {"PolicyNameWithPath": ["policyName"]}},
    ],
    "actions": [
        a("ListUsers", L), a("ListRoles", L), a("ListPolicies", L), a("GetAccountSummary", L),
        a("GenerateCredentialReport", R), a("GetCredentialReport", R),
        a("GetUser", R, ["user"]), a("GetRole", R, ["role"]),
        a("GetPolicy", R, ["policy"]), a("GetPolicyVersion", R, ["policy"]),
        a("ListAttachedRolePolicies", L, ["role"]), a("ListRolePolicies", L, ["role"]),
        a("ListAccessKeys", L, ["user"]), a("ListMFADevices", L, ["user"]),
        a("CreateUser", W, ["user"]), a("DeleteUser", W, ["user"]),
        a("CreateRole", W, ["role"]), a("DeleteRole", W, ["role"]),
        a("CreateAccessKey", W, ["user"]), a("DeleteAccessKey", W, ["user"]),
        a("AddUserToGroup", W, ["group"]),
        a("PassRole", W, ["role"], notLogged=True),
        a("AttachRolePolicy", P, ["role"]), a("DetachRolePolicy", P, ["role"]),
        a("PutRolePolicy", P, ["role"]), a("DeleteRolePolicy", P, ["role"]),
        a("AttachUserPolicy", P, ["user"]), a("PutUserPolicy", P, ["user"]),
        a("CreatePolicy", P, ["policy"]), a("CreatePolicyVersion", P, ["policy"]),
        a("UpdateAssumeRolePolicy", P, ["role"]),
        a("TagRole", T, ["role"]),
    ],
})

services.append({
    "prefix": "sts", "name": "AWS Security Token Service", "eventSource": "sts.amazonaws.com",
    "resourceTypes": [
        {"name": "role", "arn": "arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}",
         "arnParams": ["roleArn"], "params": {}},
    ],
    "actions": [
        a("AssumeRole", W, ["role"]),
        a("TagSession", T, ["role"], events=[]),
        a("GetCallerIdentity", R, noAuth=True),
        a("GetSessionToken", R),
        a("GetAccessKeyInfo", R),
        a("DecodeAuthorizationMessage", W),
    ],
})

services.append({
    "prefix": "ec2", "name": "Amazon EC2", "eventSource": "ec2.amazonaws.com",
    "resourceTypes": [
        {"name": "instance", "arn": "arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}", "cloudTrailType": "AWS::EC2::Instance",
         "params": {"InstanceId": ["instancesSet.items[].instanceId", "instanceId|requirePrefix:i-", "resourcesSet.items[].resourceId|requirePrefix:i-"]}},
        {"name": "volume", "arn": "arn:${Partition}:ec2:${Region}:${Account}:volume/${VolumeId}",
         "params": {"VolumeId": ["volumeId", "resourcesSet.items[].resourceId|requirePrefix:vol-"]}},
        {"name": "security-group", "arn": "arn:${Partition}:ec2:${Region}:${Account}:security-group/${SecurityGroupId}",
         "params": {"SecurityGroupId": ["groupId"]}},
    ],
    "actions": [
        a("DescribeInstances", L), a("DescribeVolumes", L), a("DescribeSecurityGroups", L),
        a("DescribeImages", L), a("DescribeSubnets", L), a("DescribeVpcs", L), a("DescribeRegions", L),
        a("DescribeSnapshots", L),
        a("StartInstances", W, ["instance"]), a("StopInstances", W, ["instance"]),
        a("RebootInstances", W, ["instance"]), a("TerminateInstances", W, ["instance"]),
        a("RunInstances", W),
        a("AttachVolume", W, ["volume", "instance"], resourceMode="all"),
        a("DetachVolume", W, ["volume", "instance"], resourceMode="all"),
        a("CreateSnapshot", W, ["volume"]),
        a("CreateSecurityGroup", W),
        a("AuthorizeSecurityGroupIngress", W, ["security-group"]),
        a("RevokeSecurityGroupIngress", W, ["security-group"]),
        a("CreateTags", T, ["instance", "volume"], resourceMode="all"),
        a("DeleteTags", T, ["instance", "volume"], resourceMode="all"),
    ],
})

doc = {
    "schemaVersion": 1,
    "description": "Hand-curated subset of the AWS Service Authorization Reference and CloudTrail event names. Not exhaustive; see DATA.md.",
    "services": services,
}
print(json.dumps(doc, indent=1))
